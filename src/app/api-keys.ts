/**
 * API keys (lld/identity.md §4, §6): created and rolled from a stepped-up session, shown once,
 * stored as SHA-256. Revocation purges the authz caches (Valkey and LRU at once; other replicas by
 * the purge broadcast or within 30 s) and emits `evt.identity.api_key.revoked`. Stage 2: restricted
 * keys (`rk_…`) hold only catalogue scopes (write implies read, expanded at the gateway); a key's
 * name, IP allow-list and (restricted) scopes change with `updateApiKey`, purged the same way.
 */
import { KEY_SCOPES } from "@nearpay/spec";
import { withTx } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import {
  checkScopes,
  displayPrefix,
  generateKey,
  type KeyType,
  keyHash,
  last4,
  type ScopeCheck,
} from "../domain/api-key/key.js";
import { type Actor, audit, dbNow, emitEvent, type Identity, type Tx } from "./context.js";
import { apiKeyView, type KeyRow } from "./views.js";

const eventObject = (k: KeyRow) => apiKeyView(k);

export async function emitKey(
  tx: Tx,
  k: KeyRow,
  subject: "evt.identity.api_key.created" | "evt.identity.api_key.revoked",
) {
  await emitEvent(tx, {
    subject,
    aggregate: { type: "api_key", id: fromUuid("key", k.id), version: subject.endsWith("created") ? 1 : 2 },
    accountUuid: k.account_id,
    livemode: k.livemode,
    object: eventObject(k),
  });
}

export async function listKeys(
  id: Identity,
  accountId: string,
  livemode: boolean,
  q: { limit: number; starting_after?: string | undefined; ending_before?: string | undefined },
) {
  let query = id.db
    .selectFrom("api_keys")
    .selectAll()
    .where("account_id", "=", toUuid(accountId, "acct"))
    .where("livemode", "=", livemode)
    .where("revoked_at", "is", null)
    .orderBy("created_at", "desc")
    .orderBy("id", "desc")
    .limit(q.limit + 1);
  if (q.starting_after) query = query.where("id", "<", toUuid(q.starting_after, "key"));
  if (q.ending_before) query = query.where("id", ">", toUuid(q.ending_before, "key"));
  const rows = await query.execute();
  return {
    object: "list" as const,
    data: rows.slice(0, q.limit).map((k) => apiKeyView(k)),
    has_more: rows.length > q.limit,
    url: "/v1/api_keys",
  };
}

export async function insertKey(
  tx: Tx,
  k: {
    accountUuid: string;
    livemode: boolean;
    type: KeyType;
    name: string;
    scopes: string[];
    ipAllowlist: string[];
    expiresAt: Date | null;
    createdBy: string;
  },
) {
  const secret = generateKey(k.type, k.livemode);
  const row = await tx
    .insertInto("api_keys")
    .values({
      id: uuidv7(),
      account_id: k.accountUuid,
      livemode: k.livemode,
      type: k.type,
      key_hash: keyHash(secret),
      display_prefix: displayPrefix(k.type, k.livemode),
      last4: last4(secret),
      scopes: k.scopes,
      name: k.name,
      ip_allowlist: k.ipAllowlist,
      created_by: k.createdBy,
      expires_at: k.expiresAt,
    })
    .returningAll()
    .executeTakeFirstOrThrow();
  await emitKey(tx, row, "evt.identity.api_key.created");
  return { row, secret };
}

export async function createKey(
  id: Identity,
  accountId: string,
  b: {
    type: KeyType;
    livemode: boolean;
    name: string;
    scopes?: string[] | undefined;
    ip_allowlist?: string[] | undefined;
    expires_at?: number | undefined;
  },
  actor: Actor & { userUuid: string },
) {
  if (b.expires_at !== undefined && b.expires_at * 1000 <= id.now())
    throw ApiError.invalid("expires_at must be in the future", "expires_at");
  const scopes = scopesOrThrow(checkScopes(b.type, b.scopes, KEY_SCOPES));
  return withTx(id.db, async (tx) => {
    const { row, secret } = await insertKey(tx, {
      accountUuid: toUuid(accountId, "acct"),
      livemode: b.livemode,
      type: b.type,
      name: b.name,
      scopes,
      ipAllowlist: b.ip_allowlist ?? [],
      expiresAt: b.expires_at === undefined ? null : new Date(b.expires_at * 1000),
      createdBy: actor.userUuid,
    });
    await audit(id, tx, {
      accountUuid: row.account_id,
      actor,
      action: "api_key.created",
      target: { type: "api_key", id: fromUuid("key", row.id) },
      details: { type: row.type, livemode: row.livemode, ...(row.type === "restricted" ? { scopes: row.scopes } : {}) },
    });
    return apiKeyView(row, secret);
  });
}

function scopesOrThrow(c: ScopeCheck): string[] {
  if (c.ok) return c.scopes;
  if (c.error === "scope_unknown")
    throw new ApiError("scope_unknown", { params: { scope: c.scope ?? "" }, param: "scopes" });
  throw ApiError.invalid(c.reason, "scopes");
}

/**
 * `PATCH /v1/api_keys/{id}` (spec 0.2.0): rename, replace a restricted key's scopes, or replace the
 * IP allow-list. Scopes on a secret/publishable key, or any change to a revoked, expired or rolled
 * key, is `409 state_conflict`. The cached record is purged at once (other replicas by broadcast,
 * at most 30 s), so the change applies within 30 s.
 */
export async function updateKey(
  id: Identity,
  accountId: string,
  livemode: boolean,
  keyId: string,
  b: { name?: string | undefined; scopes?: string[] | undefined; ip_allowlist?: string[] | undefined },
  actor: Actor,
) {
  const r = await withTx(id.db, async (tx) => {
    const k = await lockKey(tx, accountId, keyId, livemode);
    const now = await dbNow(tx);
    if (k.revoked_at || (k.expires_at && k.expires_at <= now) || k.rolled_to)
      throw new ApiError("state_conflict", {
        params: { object: "api_key", state: k.revoked_at ? "revoked" : k.rolled_to ? "rolled" : "expired" },
      });
    if (b.scopes !== undefined && k.type !== "restricted")
      throw new ApiError("state_conflict", { params: { object: "api_key", state: `a ${k.type} key without scopes` } });
    const scopes = b.scopes === undefined ? k.scopes : scopesOrThrow(checkScopes("restricted", b.scopes, KEY_SCOPES));
    const next = { name: b.name ?? k.name, scopes, ip_allowlist: b.ip_allowlist ?? k.ip_allowlist };
    const changed =
      next.name !== k.name ||
      JSON.stringify(next.scopes) !== JSON.stringify(k.scopes) ||
      JSON.stringify(next.ip_allowlist) !== JSON.stringify(k.ip_allowlist);
    if (!changed) return { row: k, hash: k.key_hash };
    const row = await tx
      .updateTable("api_keys")
      .set(next)
      .where("id", "=", k.id)
      .returningAll()
      .executeTakeFirstOrThrow();
    await audit(id, tx, {
      accountUuid: k.account_id,
      actor,
      action: "api_key.updated",
      target: { type: "api_key", id: keyId },
      details: {
        fields: Object.keys(b).filter((f) => (b as Record<string, unknown>)[f] !== undefined),
        ...(b.scopes !== undefined ? { scopes: row.scopes } : {}),
      },
    });
    return { row, hash: k.key_hash };
  });
  await id.cache.purgeKey(r.hash.toString("hex"));
  return apiKeyView(r.row);
}

async function lockKey(tx: Tx, accountId: string, keyId: string, livemode?: boolean) {
  let q = tx
    .selectFrom("api_keys")
    .selectAll()
    .where("id", "=", toUuid(keyId, "key"))
    .where("account_id", "=", toUuid(accountId, "acct"));
  if (livemode !== undefined) q = q.where("livemode", "=", livemode);
  const k = await q.forUpdate().executeTakeFirst();
  if (!k) throw ApiError.missing("api_key", keyId, "id");
  return k;
}

export async function rollKey(
  id: Identity,
  accountId: string,
  keyId: string,
  expireOldInSeconds: number,
  actor: Actor & { userUuid: string },
) {
  const r = await withTx(id.db, async (tx) => {
    const old = await lockKey(tx, accountId, keyId);
    const now = await dbNow(tx);
    if (old.revoked_at || (old.expires_at && old.expires_at <= now) || old.rolled_to)
      throw new ApiError("state_conflict", {
        params: { object: "api_key", state: old.revoked_at ? "revoked" : "already rolled" },
      });
    const { row, secret } = await insertKey(tx, {
      accountUuid: old.account_id,
      livemode: old.livemode,
      type: old.type,
      name: old.name,
      scopes: old.scopes,
      ipAllowlist: old.ip_allowlist,
      expiresAt: old.expires_at,
      createdBy: actor.userUuid,
    });
    const graceEnd = new Date(now.getTime() + expireOldInSeconds * 1000);
    const updated = await tx
      .updateTable("api_keys")
      .set(
        expireOldInSeconds === 0
          ? { revoked_at: now, rolled_to: row.id }
          : {
              rolled_to: row.id,
              expires_at: old.expires_at && old.expires_at < graceEnd ? old.expires_at : graceEnd,
            },
      )
      .where("id", "=", old.id)
      .returningAll()
      .executeTakeFirstOrThrow();
    if (expireOldInSeconds === 0) await emitKey(tx, updated, "evt.identity.api_key.revoked");
    await audit(id, tx, {
      accountUuid: old.account_id,
      actor,
      action: "api_key.rolled",
      target: { type: "api_key", id: keyId },
      details: { new_key: fromUuid("key", row.id), expire_old_in_seconds: expireOldInSeconds },
    });
    return { view: apiKeyView(row, secret), oldHash: old.key_hash };
  });
  // the old key's cached record carries its previous expiry: drop it
  await id.cache.purgeKey(r.oldHash.toString("hex"));
  return r.view;
}

export async function revokeKey(id: Identity, accountId: string, keyId: string, actor: Actor) {
  const hash = await withTx(id.db, async (tx) => {
    const k = await lockKey(tx, accountId, keyId);
    if (k.revoked_at) return k.key_hash; // idempotent
    const updated = await tx
      .updateTable("api_keys")
      .set({ revoked_at: await dbNow(tx) })
      .where("id", "=", k.id)
      .returningAll()
      .executeTakeFirstOrThrow();
    await emitKey(tx, updated, "evt.identity.api_key.revoked");
    await audit(id, tx, {
      accountUuid: k.account_id,
      actor,
      action: "api_key.revoked",
      target: { type: "api_key", id: keyId },
    });
    return k.key_hash;
  });
  await id.cache.purgeKey(hash.toString("hex"));
}

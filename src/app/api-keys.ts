/**
 * API keys (lld/identity.md §4, §6): created and rolled from a stepped-up session, shown once,
 * stored as SHA-256. Revocation purges the authz caches (Valkey and LRU at once; other replicas by
 * the purge broadcast or within 30 s) and emits `evt.identity.api_key.revoked`.
 */
import { withTx } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import { displayPrefix, generateKey, type KeyType, keyHash, last4 } from "../domain/api-key/key.js";
import { type Actor, audit, dbNow, emitEvent, type Identity, type Tx } from "./context.js";
import { apiKeyView, type KeyRow } from "./views.js";

const eventObject = (k: KeyRow) => apiKeyView(k);

async function emitKey(tx: Tx, k: KeyRow, subject: "evt.identity.api_key.created" | "evt.identity.api_key.revoked") {
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

async function insertKey(
  tx: Tx,
  k: {
    accountUuid: string;
    livemode: boolean;
    type: KeyType;
    name: string;
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
      scopes: [],
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
    type: "secret" | "publishable";
    livemode: boolean;
    name: string;
    ip_allowlist?: string[] | undefined;
    expires_at?: number | undefined;
  },
  actor: Actor & { userUuid: string },
) {
  if (b.expires_at !== undefined && b.expires_at * 1000 <= id.now())
    throw ApiError.invalid("expires_at must be in the future", "expires_at");
  return withTx(id.db, async (tx) => {
    const { row, secret } = await insertKey(tx, {
      accountUuid: toUuid(accountId, "acct"),
      livemode: b.livemode,
      type: b.type,
      name: b.name,
      ipAllowlist: b.ip_allowlist ?? [],
      expiresAt: b.expires_at === undefined ? null : new Date(b.expires_at * 1000),
      createdBy: actor.userUuid,
    });
    await audit(id, tx, {
      accountUuid: row.account_id,
      actor,
      action: "api_key.created",
      target: { type: "api_key", id: fromUuid("key", row.id) },
      details: { type: row.type, livemode: row.livemode },
    });
    return apiKeyView(row, secret);
  });
}

async function lockKey(tx: Tx, accountId: string, keyId: string) {
  const k = await tx
    .selectFrom("api_keys")
    .selectAll()
    .where("id", "=", toUuid(keyId, "key"))
    .where("account_id", "=", toUuid(accountId, "acct"))
    .forUpdate()
    .executeTakeFirst();
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

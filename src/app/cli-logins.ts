/**
 * CLI login use cases (lld/identity.md §6.2, spec 0.3.0 `src/public/cli.ts`): `nearpay login` as a
 * device authorization whose result is an ordinary restricted **test** key (gateway, authz, listing
 * and revocation need nothing new).
 *
 * - The device code is stored as SHA-256 only; the client IP envelope-encrypted.
 * - Approval mints the key, audits `api_key.created` (`via: cli_login`, login IP encrypted on the
 *   audit row) and keeps the secret envelope-encrypted until the first poll that sees `approved`,
 *   which returns it and erases it in the same transaction (`redeemed`).
 * - Every time check uses the database clock (replicas agree; the job and the routes see one time).
 * - An approved key nobody collected within 15 min is revoked by the expiry job: a secret never
 *   delivered must not stay usable or stored.
 */
import {
  CLI_KEY_SCOPES,
  CLI_KEY_TTL_SECONDS,
  CLI_LOGIN_POLL_INTERVAL_SECONDS,
  CLI_LOGIN_TTL_SECONDS,
  KEY_SCOPES,
} from "@nearpay/spec";
import { type Selectable, sql, withTx } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import { checkScopes } from "../domain/api-key/key.js";
import {
  CREATE_LIMIT,
  cleanCountry,
  cleanText,
  cliKeyName,
  decide,
  deviceCodeHash,
  effectiveStatus,
  generateDeviceCode,
  generateUserCode,
  pollOutcome,
  pollPace,
  REDEEM_WINDOW_MS,
  visibleTo,
} from "../domain/cli-login/cli-login.js";
import type { CliLoginsTable } from "../infra/db/schema.js";
import { emitKey, insertKey } from "./api-keys.js";
import { type Actor, audit, dbNow, type Identity, type Tx } from "./context.js";
import { apiKeyView } from "./views.js";

type LoginRow = Selectable<CliLoginsTable>;

const unix = (d: Date) => Math.floor(d.getTime() / 1000);
const KEY_ROLES = new Set(["owner", "admin", "developer"]);

export interface CliRequestMeta {
  readonly ip: string | null;
  readonly country: string | undefined;
  readonly userAgent: string | undefined;
}

const ipAad = (loginId: string) => `cli_login:${loginId}:ip`;
const secretAad = (loginId: string) => `cli_login:${loginId}:key`;

function loginIp(id: Identity, l: LoginRow): string | null {
  if (!l.ip_enc) return null;
  try {
    return id.cipher.decrypt(l.ip_enc, ipAad(l.id)).toString("utf8");
  } catch {
    return null;
  }
}

export function cliLoginRequestView(id: Identity, l: LoginRow, now: number) {
  const status = effectiveStatus(l, now);
  return {
    object: "cli_login_request" as const,
    user_code: l.user_code,
    device_name: l.device_name,
    status,
    created: unix(l.created_at),
    expires_at: unix(l.expires_at),
    requested_from: { ip: loginIp(id, l), country: l.country, user_agent: l.user_agent },
    account: l.key_id && l.account_id ? fromUuid("acct", l.account_id) : null,
    key: l.key_id ? fromUuid("key", l.key_id) : null,
  };
}

function rateLimited(retryAfter: number): ApiError {
  return new ApiError("rate_limited", {
    params: { retry_after: String(retryAfter) },
    headers: { "Retry-After": String(retryAfter) },
  });
}

const isPendingCodeClash = (e: unknown) =>
  (e as { code?: string; constraint?: string }).code === "23505" &&
  (e as { constraint?: string }).constraint === "cli_logins_user_code_pending";

/** `POST /v1/cli/logins` (anonymous): 10 per 10 min per client IP. */
export async function createCliLogin(
  id: Identity,
  body: { device_name: string; client_version?: string | undefined },
  meta: CliRequestMeta,
) {
  const limit = await id.cache.take(`cli_login:create:${meta.ip ?? "unknown"}`, CREATE_LIMIT, id.now());
  if (!limit.allowed) {
    id.metrics.rateLimited("anonymous");
    throw rateLimited(limit.retryAfter);
  }
  const deviceName = cleanText(body.device_name, 64);
  if (!deviceName) throw ApiError.invalid("device_name must contain visible characters", "device_name");
  const deviceCode = generateDeviceCode();
  const loginId = uuidv7();
  // a user code is unique among pending logins; on the rare clash draw again
  for (let attempt = 0; ; attempt++) {
    const userCode = generateUserCode();
    try {
      const row = await id.db
        .insertInto("cli_logins")
        .values({
          id: loginId,
          device_code_sha256: deviceCodeHash(deviceCode),
          user_code: userCode,
          device_name: deviceName,
          client_version: cleanText(body.client_version, 32),
          ip_enc: meta.ip ? id.cipher.encrypt(meta.ip, ipAad(loginId)) : null,
          country: cleanCountry(meta.country),
          user_agent: cleanText(meta.userAgent, 256),
          expires_at: sql<Date>`now() + make_interval(secs => ${CLI_LOGIN_TTL_SECONDS})`,
        })
        .returning(["user_code", "expires_at"])
        .executeTakeFirstOrThrow();
      const url = `${id.dashboardOrigin.replace(/\/$/, "")}/cli/authorize`;
      return {
        object: "cli_login" as const,
        device_code: deviceCode,
        user_code: row.user_code,
        verification_url: url,
        verification_url_complete: `${url}?code=${encodeURIComponent(row.user_code)}`,
        expires_at: unix(row.expires_at),
        interval: CLI_LOGIN_POLL_INTERVAL_SECONDS,
      };
    } catch (e) {
      if (!isPendingCodeClash(e) || attempt >= 4) throw e;
    }
  }
}

/** `POST /v1/cli/logins/poll` (anonymous). The device code is the credential. */
export async function pollCliLogin(id: Identity, deviceCode: string) {
  const r = await withTx(id.db, async (tx) => {
    const l = await tx
      .selectFrom("cli_logins")
      .selectAll()
      .where("device_code_sha256", "=", deviceCodeHash(deviceCode))
      .forUpdate()
      .executeTakeFirst();
    // the code is a secret: never echoed back
    if (!l)
      throw new ApiError("resource_missing", { params: { object: "cli_login", id: "npdc_…" }, param: "device_code" });
    const now = await dbNow(tx);
    const pace = pollPace(l.last_polled_at, now.getTime(), CLI_LOGIN_POLL_INTERVAL_SECONDS);
    if (!pace.ok) return { slowDown: pace.retryAfter } as const;
    const outcome = pollOutcome(l, now.getTime());
    if (!outcome.redeem) {
      await tx.updateTable("cli_logins").set({ last_polled_at: now }).where("id", "=", l.id).execute();
      return {
        result: {
          object: "cli_login_poll" as const,
          status: outcome.status,
          interval: CLI_LOGIN_POLL_INTERVAL_SECONDS,
        },
      };
    }
    if (!l.key_id || !l.key_secret_enc || !l.account_id) throw new Error(`cli login ${l.id} approved without a key`);
    const secret = id.cipher.decrypt(l.key_secret_enc, secretAad(l.id)).toString("utf8");
    const key = await tx.selectFrom("api_keys").selectAll().where("id", "=", l.key_id).executeTakeFirstOrThrow();
    const account = await tx
      .selectFrom("accounts")
      .select(["id", "display_name"])
      .where("id", "=", l.account_id)
      .executeTakeFirstOrThrow();
    await tx
      .updateTable("cli_logins")
      .set({ status: "redeemed", key_secret_enc: null, last_polled_at: now, updated_at: now })
      .where("id", "=", l.id)
      .execute();
    return {
      result: {
        object: "cli_login_poll" as const,
        status: "approved" as const,
        interval: CLI_LOGIN_POLL_INTERVAL_SECONDS,
        key: apiKeyView(key, secret),
        account: { id: fromUuid("acct", account.id), display_name: account.display_name },
      },
    };
  });
  if ("slowDown" in r) {
    id.metrics.rateLimited("anonymous");
    throw rateLimited(r.slowDown as number);
  }
  return r.result;
}

/** The login a user code names for this account: the pending one, else the newest it may see. */
async function findForAccount(db: Identity["db"] | Tx, code: string, accountUuid: string, now: number) {
  const rows = await db
    .selectFrom("cli_logins")
    .selectAll()
    .where("user_code", "=", code)
    .orderBy("created_at", "desc")
    .limit(20)
    .execute();
  const visible = rows.filter((l) => visibleTo(l, accountUuid, now));
  return visible.find((l) => effectiveStatus(l, now) === "pending") ?? visible[0] ?? null;
}

const missing = (code: string) => ApiError.missing("cli_login", code, "code");

/** `GET /v1/cli/logins/{code}` (session owner/admin/developer). */
export async function getCliLogin(id: Identity, accountId: string, code: string) {
  const now = (await dbNow(id.db)).getTime();
  const l = await findForAccount(id.db, code, toUuid(accountId, "acct"), now);
  if (!l) throw missing(code);
  return cliLoginRequestView(id, l, now);
}

/** The session user's role on the account, re-read in the transaction (the token's role may be 10 s old). */
async function keyRoleOrThrow(tx: Tx, accountUuid: string, userUuid: string) {
  const m = await tx
    .selectFrom("memberships")
    .select("role")
    .where("account_id", "=", accountUuid)
    .where("user_id", "=", userUuid)
    .executeTakeFirst();
  if (!m || !KEY_ROLES.has(m.role))
    throw new ApiError("permission_denied", { params: { action: "approve CLI logins" } });
}

async function lockDecidable(tx: Tx, code: string, accountUuid: string, now: number) {
  const pending = await tx
    .selectFrom("cli_logins")
    .selectAll()
    .where("user_code", "=", code)
    .where("status", "=", "pending")
    .forUpdate()
    .executeTakeFirst();
  if (pending) return pending;
  const other = await findForAccount(tx, code, accountUuid, now);
  if (!other) throw missing(code);
  return other;
}

const conflict = (state: string) => new ApiError("state_conflict", { params: { object: "cli_login", state } });

/**
 * `POST /v1/cli/logins/{code}/approve` (session owner/admin/developer, step-up): mints a restricted
 * test key for the session's account whatever `NearPay-Mode` says.
 */
export async function approveCliLogin(
  id: Identity,
  accountId: string,
  code: string,
  actor: Actor & { userUuid: string },
) {
  const accountUuid = toUuid(accountId, "acct");
  return withTx(id.db, async (tx) => {
    const now = await dbNow(tx);
    const l = await lockDecidable(tx, code, accountUuid, now.getTime());
    const d = decide(l, "approve", now.getTime());
    if (!d.ok) throw conflict(d.state);
    await keyRoleOrThrow(tx, accountUuid, actor.userUuid);
    const scopes = checkScopes("restricted", CLI_KEY_SCOPES, KEY_SCOPES);
    // CLI_KEY_SCOPES ⊆ KEY_SCOPES is pinned by the spec's own tests; refuse to mint anything else
    if (!scopes.ok) throw new Error(`CLI_KEY_SCOPES outside the scope catalogue: ${scopes.scope ?? scopes.reason}`);
    const { row: key, secret } = await insertKey(tx, {
      accountUuid,
      livemode: false,
      type: "restricted",
      name: cliKeyName(l.device_name),
      scopes: scopes.scopes,
      ipAllowlist: [],
      expiresAt: new Date(now.getTime() + CLI_KEY_TTL_SECONDS * 1000),
      createdBy: actor.userUuid,
    });
    await audit(id, tx, {
      accountUuid,
      actor,
      action: "api_key.created",
      target: { type: "api_key", id: fromUuid("key", key.id) },
      details: {
        type: key.type,
        livemode: false,
        scopes: key.scopes,
        via: "cli_login",
        login_country: l.country,
        client_version: l.client_version,
      },
      originIp: loginIp(id, l),
    });
    const updated = await tx
      .updateTable("cli_logins")
      .set({
        status: "approved",
        account_id: accountUuid,
        key_id: key.id,
        key_secret_enc: id.cipher.encrypt(secret, secretAad(l.id)),
        approved_by: actor.userUuid,
        decided_at: now,
        updated_at: now,
      })
      .where("id", "=", l.id)
      .returningAll()
      .executeTakeFirstOrThrow();
    return cliLoginRequestView(id, updated, now.getTime());
  });
}

/** `POST /v1/cli/logins/{code}/deny` (session owner/admin/developer). */
export async function denyCliLogin(id: Identity, accountId: string, code: string, actor: Actor & { userUuid: string }) {
  const accountUuid = toUuid(accountId, "acct");
  return withTx(id.db, async (tx) => {
    const now = await dbNow(tx);
    const l = await lockDecidable(tx, code, accountUuid, now.getTime());
    const d = decide(l, "deny", now.getTime());
    if (!d.ok) throw conflict(d.state);
    await keyRoleOrThrow(tx, accountUuid, actor.userUuid);
    const updated = await tx
      .updateTable("cli_logins")
      .set({ status: "denied", account_id: accountUuid, approved_by: actor.userUuid, decided_at: now, updated_at: now })
      .where("id", "=", l.id)
      .returningAll()
      .executeTakeFirstOrThrow();
    await audit(id, tx, {
      accountUuid,
      actor,
      action: "cli_login.denied",
      target: { type: "cli_login", id: l.user_code },
      details: { login_country: l.country, client_version: l.client_version },
      originIp: loginIp(id, l),
    });
    return cliLoginRequestView(id, updated, now.getTime());
  });
}

export const CLI_EXPIRE_JOB = "cli_logins.expire";

/**
 * Job `cli_logins.expire` (every minute): overdue pending logins → `expired`; approvals whose key was
 * not collected within the redeem window → `expired`, key revoked (event + audit), secret erased.
 */
export async function expireCliLogins(id: Identity): Promise<{ expired: number; uncollected: number }> {
  const expired = Number(
    (
      await sql`update cli_logins set status = 'expired', updated_at = now()
        where status = 'pending' and expires_at <= now()`.execute(id.db)
    ).numAffectedRows ?? 0n,
  );
  const purged: Buffer[] = [];
  const uncollected = await withTx(id.db, async (tx) => {
    const rows = await tx
      .selectFrom("cli_logins")
      .selectAll()
      .where("status", "=", "approved")
      .where("decided_at", "<=", sql<Date>`now() - make_interval(secs => ${REDEEM_WINDOW_MS / 1000})`)
      .forUpdate()
      .skipLocked()
      .limit(100)
      .execute();
    for (const l of rows) {
      if (l.key_id) {
        const k = await tx
          .updateTable("api_keys")
          .set({ revoked_at: sql<Date>`now()` })
          .where("id", "=", l.key_id)
          .where("revoked_at", "is", null)
          .returningAll()
          .executeTakeFirst();
        if (k) {
          await emitKey(tx, k, "evt.identity.api_key.revoked");
          await audit(id, tx, {
            accountUuid: k.account_id,
            actor: { type: "system", id: "system" },
            action: "api_key.revoked",
            target: { type: "api_key", id: fromUuid("key", k.id) },
            details: { via: "cli_login", reason: "not_collected" },
          });
          purged.push(k.key_hash);
        }
      }
      await tx
        .updateTable("cli_logins")
        .set({ status: "expired", key_secret_enc: null, updated_at: sql<Date>`now()` })
        .where("id", "=", l.id)
        .execute();
    }
    return rows.length;
  });
  for (const h of purged) await id.cache.purgeKey(h.toString("hex"));
  return { expired, uncollected };
}

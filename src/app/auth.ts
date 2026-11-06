/**
 * Sign-up and passkey sessions (lld/identity.md §6, §12, FR-ACC-02). No passwords: an emailed magic
 * link verifies the address once, a passkey is registered, and every later sign-in and step-up is a
 * WebAuthn assertion (user verification required). Credentials are discoverable, so sign-in never
 * reveals whether an email is registered.
 *
 * Console (ops) sessions (`__Host-np_ops`) are accepted by authz already; issuing them arrives with
 * the console UI and its contract in Stage 2 (Stage 1 ops work runs through the ops CLIs).
 */
import { randomBytes } from "node:crypto";
import { API_VERSION } from "@nearpay/spec";
import { withTx } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError, respond } from "@nearpay-internal/service";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { DEFAULT_SETTINGS } from "../domain/account/account.js";
import { isConsoleHost } from "../domain/authz/authz.js";
import {
  ABSOLUTE_MS,
  clearCookie,
  matchesHash,
  newSecret,
  OPS_COOKIE,
  readCookie,
  SESSION_COOKIE,
  STEP_UP_MS,
  setCookie,
  sha256,
} from "../domain/session/session.js";
import { audit, dbNow, emitEvent, type Identity, type Tx } from "./context.js";
import { accountView } from "./views.js";

export const MAGIC_LINK_MS = 15 * 60_000;
export const REGISTRATION_MS = 5 * 60_000;
export const CEREMONY_MS = 5 * 60_000;
/** Magic links per email per hour (beyond: silently not sent; the gateway limits per IP). */
export const MAGIC_LINKS_PER_HOUR = 5;
export const DEFAULT_FEE_SCHEDULE = "01900000-0000-7000-8000-000000000001";

const failed = (reason: string) => new ApiError("webauthn_failed", { params: { reason } });

export interface RequestMeta {
  readonly host: string | undefined;
  readonly ip: string | null;
  readonly userAgent: string | undefined;
  readonly cookie: string | undefined;
}

// ---------------------------------------------------------------------------------------------
// Magic links
// ---------------------------------------------------------------------------------------------

export async function signup(
  id: Identity,
  b: { email: string; turnstile_token: string },
  meta: RequestMeta,
): Promise<void> {
  if (!(await id.turnstile(b.turnstile_token, meta.ip))) throw new ApiError("turnstile_failed");
  const email = b.email.trim().toLowerCase();
  const existing = await id.db.selectFrom("users").select("id").where("email", "=", email).executeTakeFirst();
  // same answer either way: sign-up never reveals whether an address has an account
  if (existing) {
    id.log.info("sign-up for an existing user; no link sent");
    return;
  }
  const recent = await id.db
    .selectFrom("magic_links")
    .select((eb) => eb.fn.countAll<string>().as("n"))
    .where("email", "=", email)
    .where("created_at", ">", new Date(id.now() - 3_600_000))
    .executeTakeFirstOrThrow();
  if (Number(recent.n) >= MAGIC_LINKS_PER_HOUR) {
    id.log.warn("magic-link limit reached for an address; no link sent");
    return;
  }
  const token = newSecret(32);
  const hash = sha256(token);
  await id.db
    .insertInto("magic_links")
    .values({ token_hash: hash, email, purpose: "signup", expires_at: new Date(id.now() + MAGIC_LINK_MS) })
    .execute();
  try {
    await id.peers.sendMagicLink({
      to: email,
      // fragment: the token never reaches a server log (the dashboard reads it client-side)
      link_url: `${id.dashboardOrigin.replace(/\/$/, "")}/auth/verify#token=${token}`,
      purpose: "signup",
      expires_in_minutes: MAGIC_LINK_MS / 60_000,
      dedupe_key: `magic:${hash.toString("hex")}`,
    });
  } catch (e) {
    id.log.error({ err: e }, "magic link could not be queued");
    throw new ApiError("api_error", { message: "Email delivery is unavailable right now; try again shortly." });
  }
}

export async function verifyMagicLink(id: Identity, token: string) {
  return withTx(id.db, async (tx) => {
    const link = await tx
      .selectFrom("magic_links")
      .selectAll()
      .where("token_hash", "=", sha256(token))
      .forUpdate()
      .executeTakeFirst();
    if (!link) throw new ApiError("link_expired");
    if (link.used_at) throw new ApiError("link_used");
    const now = await dbNow(tx);
    if (link.expires_at <= now) throw new ApiError("link_expired");
    await tx.updateTable("magic_links").set({ used_at: now }).where("token_hash", "=", link.token_hash).execute();
    const registration = newSecret(32);
    const expires = new Date(now.getTime() + REGISTRATION_MS);
    await tx
      .insertInto("registration_tokens")
      .values({
        token_hash: sha256(registration),
        email: link.email,
        user_handle: randomBytes(32),
        expires_at: expires,
      })
      .execute();
    return {
      object: "registration" as const,
      registration_token: registration,
      email: link.email,
      expires_at: Math.floor(expires.getTime() / 1000),
    };
  });
}

// ---------------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------------

interface NewSession {
  readonly token: string;
  readonly csrf: string;
  readonly expiresAt: Date;
}

async function createSession(
  id: Identity,
  tx: Tx,
  s: { kind: "dashboard" | "ops"; userId: string; accountId: string | null; meta: RequestMeta; steppedUp?: boolean },
): Promise<NewSession> {
  const token = newSecret(32);
  const csrf = newSecret(32);
  const now = await dbNow(tx);
  const sid = uuidv7();
  const expiresAt = new Date(now.getTime() + ABSOLUTE_MS);
  await tx
    .insertInto("sessions")
    .values({
      id: sid,
      kind: s.kind,
      user_id: s.userId,
      account_id: s.accountId,
      token_hash: sha256(token),
      csrf_hash: sha256(csrf),
      csrf_enc: id.cipher.encrypt(csrf, `session:${sid}:csrf`),
      // signing in with a passkey is itself a fresh user-verified assertion
      step_up_at: s.steppedUp ? now : null,
      expires_at: expiresAt,
      last_seen_at: now,
      ip_enc: s.meta.ip ? id.cipher.encrypt(s.meta.ip, `session:${sid}:ip`) : null,
      user_agent: s.meta.userAgent?.slice(0, 300) ?? null,
    })
    .execute();
  return { token, csrf, expiresAt };
}

async function sessionBody(tx: Tx, userId: string, accountId: string, s: NewSession) {
  const row = await tx
    .selectFrom("memberships")
    .innerJoin("users", "users.id", "memberships.user_id")
    .innerJoin("accounts", "accounts.id", "memberships.account_id")
    .select(["users.email", "accounts.display_name", "memberships.role"])
    .where("memberships.user_id", "=", userId)
    .where("memberships.account_id", "=", accountId)
    .executeTakeFirstOrThrow();
  return {
    object: "dashboard_session" as const,
    user: { id: fromUuid("usr", userId), email: row.email },
    account: { id: fromUuid("acct", accountId), display_name: row.display_name },
    role: row.role,
    csrf_token: s.csrf,
    expires_at: Math.floor(s.expiresAt.getTime() / 1000),
  };
}

const cookieFor = (kind: "dashboard" | "ops", s: NewSession) =>
  setCookie(kind === "ops" ? OPS_COOKIE : SESSION_COOKIE, s.token, Math.floor(ABSOLUTE_MS / 1000));

/** The caller's own session row (the request token says who; the cookie says which session). */
export async function currentSession(id: Identity, meta: RequestMeta, userUuid: string) {
  const token = readCookie(meta.cookie, isConsoleHost(meta.host) ? OPS_COOKIE : SESSION_COOKIE);
  if (!token) throw new ApiError("authentication_required");
  const s = await id.db.selectFrom("sessions").selectAll().where("token_hash", "=", sha256(token)).executeTakeFirst();
  if (!s || s.user_id !== userUuid || s.revoked_at) throw new ApiError("authentication_required");
  return s;
}

// ---------------------------------------------------------------------------------------------
// WebAuthn ceremonies
// ---------------------------------------------------------------------------------------------

function challengeOf(clientDataJSON: string): string {
  try {
    const c = JSON.parse(Buffer.from(clientDataJSON, "base64url").toString("utf8")) as { challenge?: unknown };
    if (typeof c.challenge === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(c.challenge)) return c.challenge;
  } catch {}
  throw failed("malformed client data");
}

async function takeChallenge(tx: Tx, challenge: string, purpose: "registration" | "authentication" | "step_up") {
  const row = await tx
    .selectFrom("webauthn_challenges")
    .selectAll()
    .where("challenge", "=", challenge)
    .where("purpose", "=", purpose)
    .forUpdate()
    .executeTakeFirst();
  const now = await dbNow(tx);
  if (!row || row.used_at || row.expires_at <= now) throw failed("unknown, used or expired challenge");
  await tx.updateTable("webauthn_challenges").set({ used_at: now }).where("challenge", "=", challenge).execute();
  return row;
}

async function storeChallenge(
  id: Identity,
  challenge: string,
  c: {
    purpose: "registration" | "authentication" | "step_up";
    registrationHash?: Buffer;
    userId?: string;
    sessionId?: string;
    host?: string;
  },
) {
  await id.db
    .insertInto("webauthn_challenges")
    .values({
      challenge,
      purpose: c.purpose,
      registration_token_hash: c.registrationHash ?? null,
      user_id: c.userId ?? null,
      session_id: c.sessionId ?? null,
      host: c.host ?? null,
      expires_at: new Date(id.now() + CEREMONY_MS),
    })
    .execute();
}

async function userPasskeys(id: Identity, userUuid: string) {
  return id.db.selectFrom("passkeys").select(["credential_id", "transports"]).where("user_id", "=", userUuid).execute();
}

async function liveRegistration(id: Identity, token: string | undefined) {
  if (!token) throw new ApiError("link_expired");
  const r = await id.db
    .selectFrom("registration_tokens")
    .selectAll()
    .where("token_hash", "=", sha256(token))
    .executeTakeFirst();
  if (!r || r.used_at || r.expires_at.getTime() <= id.now()) throw new ApiError("link_expired");
  return r;
}

export async function registrationOptions(
  id: Identity,
  b: { registration_token?: string | undefined },
  principal: { ptype: string; sub: string } | null,
) {
  let userName: string;
  let userHandle: Uint8Array;
  let link: { registrationHash?: Buffer; userId?: string };
  let exclude: { credential_id: Buffer; transports: string[] }[] = [];
  if (principal?.ptype === "session" && !b.registration_token) {
    const userUuid = toUuid(principal.sub, "usr");
    const u = await id.db.selectFrom("users").select(["email"]).where("id", "=", userUuid).executeTakeFirstOrThrow();
    userName = u.email;
    userHandle = Buffer.from(userUuid.replaceAll("-", ""), "hex");
    exclude = await userPasskeys(id, userUuid);
    link = { userId: userUuid };
  } else {
    const r = await liveRegistration(id, b.registration_token);
    userName = r.email;
    userHandle = r.user_handle;
    link = { registrationHash: r.token_hash };
  }
  const options = await generateRegistrationOptions({
    rpName: id.webauthn.rpName,
    rpID: id.webauthn.rpId,
    userName,
    userDisplayName: userName,
    userID: new Uint8Array(userHandle),
    timeout: CEREMONY_MS,
    attestationType: "none",
    excludeCredentials: exclude.map((p) => ({ id: p.credential_id.toString("base64url"), transports: p.transports })),
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    supportedAlgorithmIDs: [-8, -7, -257],
  });
  await storeChallenge(id, options.challenge, { purpose: "registration", ...link });
  return options;
}

export interface RegistrationBody {
  registration_token?: string | undefined;
  credential: Parameters<typeof verifyRegistrationResponse>[0]["response"];
  passkey_name?: string | undefined;
  display_name?: string | undefined;
}

export async function registrationVerify(
  id: Identity,
  b: RegistrationBody,
  principal: { ptype: string; sub: string } | null,
  meta: RequestMeta,
) {
  const challenge = challengeOf(b.credential.response.clientDataJSON);
  let verified: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verified = await verifyRegistrationResponse({
      response: b.credential,
      expectedChallenge: challenge,
      expectedOrigin: [...id.webauthn.origins],
      expectedRPID: id.webauthn.rpId,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-8, -7, -257],
    });
  } catch (e) {
    id.metrics.loginFailure();
    throw failed((e as Error).message.slice(0, 200));
  }
  if (!verified.verified) throw failed("the attestation did not verify");
  const info = verified.registrationInfo;

  const out = await withTx(id.db, async (tx) => {
    const c = await takeChallenge(tx, challenge, "registration");
    const now = await dbNow(tx);
    const credentialId = Buffer.from(info.credential.id, "base64url");
    const taken = await tx
      .selectFrom("passkeys")
      .select("id")
      .where("credential_id", "=", credentialId)
      .executeTakeFirst();
    if (taken) throw failed("this passkey is already registered");
    const passkey = (userId: string) => ({
      id: uuidv7(),
      user_id: userId,
      credential_id: credentialId,
      public_key: Buffer.from(info.credential.publicKey),
      sign_count: info.credential.counter,
      transports: info.credential.transports ?? b.credential.response.transports ?? [],
      aaguid: /^[0-9a-f-]{36}$/.test(info.aaguid) ? info.aaguid : null,
      backed_up: info.credentialBackedUp,
      name: b.passkey_name ?? "Passkey",
    });

    if (c.user_id) {
      // an additional passkey for the signed-in user
      if (principal?.ptype !== "session" || toUuid(principal.sub, "usr") !== c.user_id)
        throw failed("session mismatch");
      const s = await currentSessionTx(tx, meta, c.user_id);
      await tx.insertInto("passkeys").values(passkey(c.user_id)).execute();
      // the same CSRF token (re-issued from its encrypted copy): no rotation, no stale caches
      const csrf = id.cipher.decrypt(s.csrf_enc, `session:${s.id}:csrf`).toString("utf8");
      await audit(id, tx, {
        accountUuid: s.account_id,
        actor: { type: "user", id: fromUuid("usr", c.user_id), ip: meta.ip },
        action: "passkey.added",
      });
      return {
        body: await sessionBody(tx, c.user_id, s.account_id as string, { token: "", csrf, expiresAt: s.expires_at }),
        cookie: null,
      };
    }

    // a new user: the verified email, an account (owner), the passkey and a session
    if (!b.registration_token || !c.registration_token_hash?.equals(sha256(b.registration_token)))
      throw new ApiError("link_expired");
    const reg = await tx
      .selectFrom("registration_tokens")
      .selectAll()
      .where("token_hash", "=", c.registration_token_hash)
      .forUpdate()
      .executeTakeFirstOrThrow();
    if (reg.used_at || reg.expires_at <= now) throw new ApiError("link_expired");
    await tx
      .updateTable("registration_tokens")
      .set({ used_at: now })
      .where("token_hash", "=", reg.token_hash)
      .execute();
    const already = await tx.selectFrom("users").select("id").where("email", "=", reg.email).executeTakeFirst();
    if (already) throw new ApiError("link_expired");
    const userId = uuidv7();
    const accountId = uuidv7();
    await tx
      .insertInto("users")
      .values({ id: userId, email: reg.email, email_verified_at: now, last_login_at: now })
      .execute();
    const account = await tx
      .insertInto("accounts")
      .values({
        id: accountId,
        display_name: b.display_name ?? reg.email.split("@")[0]?.slice(0, 100) ?? "My business",
        fee_schedule_id: DEFAULT_FEE_SCHEDULE,
        api_version: API_VERSION,
        settings: JSON.stringify(DEFAULT_SETTINGS),
      })
      .returningAll()
      .executeTakeFirstOrThrow();
    await tx.insertInto("memberships").values({ account_id: accountId, user_id: userId, role: "owner" }).execute();
    await tx.insertInto("passkeys").values(passkey(userId)).execute();
    const view = accountView(account);
    await emitEvent(tx, {
      subject: "evt.identity.account.created",
      aggregate: { type: "account", id: view.id, version: account.version },
      accountUuid: accountId,
      livemode: null,
      object: view,
    });
    await audit(id, tx, {
      accountUuid: accountId,
      actor: { type: "user", id: fromUuid("usr", userId), ip: meta.ip },
      action: "account.created",
      target: { type: "account", id: view.id },
    });
    const s = await createSession(id, tx, { kind: "dashboard", userId, accountId, meta, steppedUp: true });
    return { body: await sessionBody(tx, userId, accountId, s), cookie: cookieFor("dashboard", s) };
  });
  return out.cookie ? respond(200, out.body, { "set-cookie": out.cookie }) : out.body;
}

async function currentSessionTx(tx: Tx, meta: RequestMeta, userUuid: string) {
  const token = readCookie(meta.cookie, SESSION_COOKIE);
  const s = token
    ? await tx.selectFrom("sessions").selectAll().where("token_hash", "=", sha256(token)).forUpdate().executeTakeFirst()
    : undefined;
  if (!s || s.user_id !== userUuid || s.revoked_at || s.kind !== "dashboard")
    throw new ApiError("authentication_required");
  return s;
}

export async function authenticationOptions(id: Identity, meta: RequestMeta) {
  // discoverable credentials: the email hint is not used, so the answer never depends on it
  const options = await generateAuthenticationOptions({
    rpID: id.webauthn.rpId,
    userVerification: "required",
    timeout: CEREMONY_MS,
  });
  await storeChallenge(id, options.challenge, { purpose: "authentication", ...(meta.host ? { host: meta.host } : {}) });
  return options;
}

async function verifyAssertion(
  id: Identity,
  tx: Tx,
  credential: Parameters<typeof verifyAuthenticationResponse>[0]["response"],
  challenge: string,
  userUuid?: string,
) {
  const credentialId = Buffer.from(credential.rawId, "base64url");
  let q = tx.selectFrom("passkeys").selectAll().where("credential_id", "=", credentialId);
  if (userUuid) q = q.where("user_id", "=", userUuid);
  const pk = await q.forUpdate().executeTakeFirst();
  if (!pk) throw failed("unknown passkey");
  let r: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    r = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: [...id.webauthn.origins],
      expectedRPID: id.webauthn.rpId,
      credential: {
        id: pk.credential_id.toString("base64url"),
        publicKey: new Uint8Array(pk.public_key),
        counter: Number(pk.sign_count),
        transports: pk.transports,
      },
      requireUserVerification: true,
    });
  } catch (e) {
    throw failed((e as Error).message.slice(0, 200));
  }
  if (!r.verified) throw failed("the assertion did not verify");
  const now = await dbNow(tx);
  await tx
    .updateTable("passkeys")
    .set({ sign_count: r.authenticationInfo.newCounter, last_used_at: now })
    .where("id", "=", pk.id)
    .execute();
  return { userId: pk.user_id };
}

export async function authenticationVerify(
  id: Identity,
  credential: Parameters<typeof verifyAuthenticationResponse>[0]["response"],
  meta: RequestMeta,
) {
  const challenge = challengeOf(credential.response.clientDataJSON);
  try {
    const out = await withTx(id.db, async (tx) => {
      await takeChallenge(tx, challenge, "authentication");
      const { userId } = await verifyAssertion(id, tx, credential, challenge);
      const user = await tx.selectFrom("users").selectAll().where("id", "=", userId).executeTakeFirstOrThrow();
      if (user.status !== "active") throw failed("the user is disabled");
      await tx
        .updateTable("users")
        .set({ last_login_at: await dbNow(tx) })
        .where("id", "=", userId)
        .execute();
      const m = await tx
        .selectFrom("memberships")
        .select(["account_id", "role"])
        .where("user_id", "=", userId)
        .orderBy("created_at")
        .executeTakeFirst();
      if (!m) throw failed("the user has no account");
      const s = await createSession(id, tx, {
        kind: "dashboard",
        userId,
        accountId: m.account_id,
        meta,
        steppedUp: true,
      });
      await audit(id, tx, {
        accountUuid: m.account_id,
        actor: { type: "user", id: fromUuid("usr", userId), ip: meta.ip },
        action: "login",
      });
      return { body: await sessionBody(tx, userId, m.account_id, s), session: s };
    });
    return respond(200, out.body, { "set-cookie": cookieFor("dashboard", out.session) });
  } catch (e) {
    id.metrics.loginFailure();
    throw e;
  }
}

export async function stepUpOptions(id: Identity, principal: { sub: string }, meta: RequestMeta) {
  const userUuid = toUuid(principal.sub, "usr");
  const s = await currentSession(id, meta, userUuid);
  const keys = await userPasskeys(id, userUuid);
  const options = await generateAuthenticationOptions({
    rpID: id.webauthn.rpId,
    userVerification: "required",
    timeout: CEREMONY_MS,
    allowCredentials: keys.map((k) => ({ id: k.credential_id.toString("base64url"), transports: k.transports })),
  });
  await storeChallenge(id, options.challenge, { purpose: "step_up", userId: userUuid, sessionId: s.id });
  return options;
}

export async function stepUpVerify(
  id: Identity,
  principal: { sub: string },
  credential: Parameters<typeof verifyAuthenticationResponse>[0]["response"],
  meta: RequestMeta,
) {
  const userUuid = toUuid(principal.sub, "usr");
  const challenge = challengeOf(credential.response.clientDataJSON);
  try {
    return await withTx(id.db, async (tx) => {
      const c = await takeChallenge(tx, challenge, "step_up");
      const s = await currentSession(id, meta, userUuid);
      if (c.session_id !== s.id || c.user_id !== userUuid) throw failed("the challenge belongs to another session");
      await verifyAssertion(id, tx, credential, challenge, userUuid);
      const now = await dbNow(tx);
      await tx.updateTable("sessions").set({ step_up_at: now }).where("id", "=", s.id).execute();
      id.cache.purgeSession(s.token_hash.toString("hex"));
      await audit(id, tx, {
        accountUuid: s.account_id,
        actor: { type: "user", id: principal.sub, ip: meta.ip },
        action: "step_up",
      });
      return { object: "step_up" as const, step_up_until: Math.floor((now.getTime() + STEP_UP_MS) / 1000) };
    });
  } catch (e) {
    id.metrics.loginFailure();
    throw e;
  }
}

export async function logout(id: Identity, principal: { sub: string }, meta: RequestMeta) {
  const s = await currentSession(id, meta, toUuid(principal.sub, "usr"));
  await id.db
    .updateTable("sessions")
    .set({ revoked_at: new Date(id.now()) })
    .where("id", "=", s.id)
    .execute();
  id.cache.purgeSession(s.token_hash.toString("hex"));
  return respond(204, undefined, { "set-cookie": clearCookie(s.kind === "ops" ? OPS_COOKIE : SESSION_COOKIE) });
}

export { matchesHash };

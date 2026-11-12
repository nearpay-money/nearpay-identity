/**
 * Sign-up and passkey sessions (lld/identity.md §6, §12, FR-ACC-02). No passwords: an emailed magic
 * link verifies the address once, a passkey is registered, and every later sign-in and step-up is a
 * WebAuthn assertion (user verification required). Credentials are discoverable, so sign-in never
 * reveals whether an email is registered.
 *
 * Stage 2: recovery (an emailed link adds a passkey to the existing user and locks destination changes
 * on every account the user owns or administers for 48 h), invitation links for new users (join the
 * inviting account instead of creating one), and sign-in into the most recently used account. Console
 * (ops) sessions are issued by console.ts; dashboard ceremonies only ever use dashboard passkeys.
 */
import { randomBytes } from "node:crypto";
import { withTx } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError, respond } from "@nearpay-internal/service";
import { API_VERSION } from "@nearpay-money/spec";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { DEFAULT_SETTINGS } from "../domain/account/account.js";
import { isConsoleHost } from "../domain/authz/authz.js";
import { passkeyAddGate, passkeySetupUntil } from "../domain/google/google.js";
import {
  clearCookie,
  LIFETIME,
  matchesHash,
  newSecret,
  OPS_COOKIE,
  readCookie,
  SESSION_COOKIE,
  STEP_UP_MS,
  sessionState,
  setCookie,
  sha256,
} from "../domain/session/session.js";
import type { Role } from "../domain/team/team.js";
import type { CeremonyPurpose, SessionAuthMethod } from "../infra/db/schema.js";
import { audit, dbNow, emitEvent, type Identity, type Tx } from "./context.js";
import { invitationForToken, joinInvitation } from "./team.js";
import { accountView } from "./views.js";

export const MAGIC_LINK_MS = 15 * 60_000;
export const REGISTRATION_MS = 5 * 60_000;
export const CEREMONY_MS = 5 * 60_000;
/** Magic links per email per hour (beyond: silently not sent; the gateway limits per IP). */
export const MAGIC_LINKS_PER_HOUR = 5;
/** Sign-ups/recoveries per client IP per 10 minutes while Turnstile is unavailable (payments' F-12 limit). */
export const TURNSTILE_OUTAGE_LIMIT = 5;
const TURNSTILE_OUTAGE_WINDOW_S = 600;

/**
 * The sign-up/recovery challenge. `failed` refuses. `unavailable` (siteverify down) never skips the check silently:
 * the request goes on only under a stricter per-IP limit (shared through Valkey, like the gateway's), and is counted
 * and logged, so onboarding survives a Cloudflare outage without opening sign-up to bots.
 */
async function challenge(id: Identity, token: string, meta: RequestMeta, flow: "signup" | "recovery"): Promise<void> {
  const t = await id.turnstile(token, meta.ip);
  if (t === "ok") return;
  if (t === "failed") throw new ApiError("turnstile_failed");
  const limit = id.turnstileOutageLimit ?? TURNSTILE_OUTAGE_LIMIT;
  const r = await id.cache.take(
    `turnstile:outage:${meta.ip ?? "unknown"}`,
    { rate: limit / TURNSTILE_OUTAGE_WINDOW_S, burst: limit },
    id.now(),
  );
  if (!r.allowed) {
    id.metrics.turnstileOutage("limited");
    id.metrics.rateLimited("anonymous");
    throw new ApiError("rate_limited", {
      params: { retry_after: String(r.retryAfter) },
      headers: { "Retry-After": String(r.retryAfter) },
    });
  }
  id.metrics.turnstileOutage("allowed");
  id.log.warn(
    { flow },
    "ALERT turnstile_unavailable: siteverify did not answer; allowed under the per-IP outage limit",
  );
}
export const DEFAULT_FEE_SCHEDULE = "01900000-0000-7000-8000-000000000001";

const failed = (reason: string) => new ApiError("webauthn_failed", { params: { reason } });

export interface RequestMeta {
  readonly host: string | undefined;
  readonly ip: string | null;
  readonly userAgent: string | undefined;
  readonly cookie: string | undefined;
  /** `Cf-Access-Jwt-Assertion` (console, `NP_OPS_AUTH_MODE=cloudflare_access`). */
  readonly accessJwt?: string | undefined;
}

// ---------------------------------------------------------------------------------------------
// Magic links
// ---------------------------------------------------------------------------------------------

export async function signup(
  id: Identity,
  b: { email: string; turnstile_token: string },
  meta: RequestMeta,
): Promise<void> {
  await challenge(id, b.turnstile_token, meta, "signup");
  const email = b.email.trim().toLowerCase();
  const existing = await id.db.selectFrom("users").select("id").where("email", "=", email).executeTakeFirst();
  // same answer either way: sign-up never reveals whether an address has an account
  if (existing) {
    id.log.info("sign-up for an existing user; no link sent");
    return;
  }
  await sendLink(id, email, "signup");
}

/** Emails a 15-minute magic link (at most 5 per address per hour; beyond: silently not sent). */
async function sendLink(id: Identity, email: string, purpose: "signup" | "recovery"): Promise<void> {
  const recent = await id.db
    .selectFrom("magic_links")
    .select((eb) => eb.fn.countAll<string>().as("n"))
    .where("email", "=", email)
    .where("created_at", ">", new Date(id.now() - 3_600_000))
    .executeTakeFirstOrThrow();
  if (Number(recent.n) >= MAGIC_LINKS_PER_HOUR) {
    id.log.warn({ purpose }, "magic-link limit reached for an address; no link sent");
    return;
  }
  const token = newSecret(32);
  const hash = sha256(token);
  await id.db
    .insertInto("magic_links")
    .values({ token_hash: hash, email, purpose, expires_at: new Date(id.now() + MAGIC_LINK_MS) })
    .execute();
  try {
    await id.peers.sendMagicLink({
      to: email,
      // fragment: the token never reaches a server log (the dashboard reads it client-side)
      link_url: `${id.dashboardOrigin.replace(/\/$/, "")}/auth/verify#token=${token}`,
      purpose,
      expires_in_minutes: MAGIC_LINK_MS / 60_000,
      dedupe_key: `magic:${hash.toString("hex")}`,
    });
  } catch (e) {
    id.log.error({ err: e }, "magic link could not be queued");
    throw new ApiError("api_error", { message: "Email delivery is unavailable right now; try again shortly." });
  }
}

/**
 * `POST /v1/auth/recovery` (spec 0.2.0): always `202`. Only an active user's address gets a link
 * (same rate limit as sign-up); unknown addresses get nothing and the same answer (no enumeration).
 */
export async function startRecovery(
  id: Identity,
  b: { email: string; turnstile_token: string },
  meta: RequestMeta,
): Promise<void> {
  await challenge(id, b.turnstile_token, meta, "recovery");
  const email = b.email.trim().toLowerCase();
  const user = await id.db.selectFrom("users").select(["id", "status"]).where("email", "=", email).executeTakeFirst();
  if (user?.status !== "active") {
    id.log.info("recovery for an unknown or disabled address; no link sent");
    return;
  }
  await sendLink(id, email, "recovery");
}

/**
 * `POST /v1/auth/magic_links/verify`: a sign-up, recovery or invitation link → a 5-minute registration
 * token that remembers its purpose. An invitation for an address that already has a user is not
 * consumed: that user signs in and accepts it (`acceptInvitation`); registering a passkey through an
 * invitation would otherwise add one to an existing user on email proof alone, bypassing recovery's
 * lock. Operator enrolment links are refused here (console only).
 */
export async function verifyMagicLink(id: Identity, token: string) {
  return withTx(id.db, async (tx) => {
    const link = await tx
      .selectFrom("magic_links")
      .selectAll()
      .where("token_hash", "=", sha256(token))
      .forUpdate()
      .executeTakeFirst();
    if (!link || link.purpose === "ops_enrol") throw new ApiError("link_expired");
    if (link.used_at) throw new ApiError("link_used");
    const now = await dbNow(tx);
    if (link.expires_at <= now) throw new ApiError("link_expired");
    const user = await tx
      .selectFrom("users")
      .select(["id", "status"])
      .where("email", "=", link.email)
      .executeTakeFirst();
    let invitation: { account_display_name: string; role: Role } | undefined;
    let userId: string | null = null;
    if (link.purpose === "invite") {
      if (user)
        throw new ApiError("authentication_required", {
          message: "This address already has a NearPay user: sign in, then accept the invitation.",
        });
      const inv = await invitationForToken(tx, token, now.getTime()).catch(() => {
        throw new ApiError("link_expired");
      });
      const a = await tx
        .selectFrom("accounts")
        .select("display_name")
        .where("id", "=", inv.account_id)
        .executeTakeFirstOrThrow();
      invitation = { account_display_name: a.display_name, role: inv.role };
    } else if (link.purpose === "recovery") {
      if (user?.status !== "active") throw new ApiError("link_expired");
      userId = user.id;
    }
    await tx.updateTable("magic_links").set({ used_at: now }).where("token_hash", "=", link.token_hash).execute();
    const registration = newSecret(32);
    const expires = new Date(now.getTime() + REGISTRATION_MS);
    await tx
      .insertInto("registration_tokens")
      .values({
        token_hash: sha256(registration),
        email: link.email,
        user_handle: userId ? Buffer.from(userId.replaceAll("-", ""), "hex") : randomBytes(32),
        expires_at: expires,
        purpose: link.purpose,
        user_id: userId,
        invitation_id: link.invitation_id,
      })
      .execute();
    return {
      object: "registration" as const,
      registration_token: registration,
      email: link.email,
      expires_at: Math.floor(expires.getTime() / 1000),
      purpose: link.purpose as "signup" | "recovery" | "invite",
      ...(invitation ? { invitation } : {}),
    };
  });
}

// ---------------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------------

export interface NewSession {
  readonly token: string;
  readonly csrf: string;
  readonly expiresAt: Date;
  /** ADR-0026: how the session was created and when (drives `DashboardSession.sign_in`). */
  readonly authMethod?: SessionAuthMethod;
  readonly createdAt?: Date;
}

async function createSession(
  id: Identity,
  tx: Tx,
  s: {
    kind: "dashboard" | "ops";
    userId: string;
    accountId: string | null;
    meta: RequestMeta;
    steppedUp?: boolean;
    /** ADR-0026: a Google sign-in never counts as a step-up (callers pass steppedUp false). */
    authMethod?: SessionAuthMethod;
  },
): Promise<NewSession> {
  const token = newSecret(32);
  const csrf = newSecret(32);
  const now = await dbNow(tx);
  const sid = uuidv7();
  const expiresAt = new Date(now.getTime() + LIFETIME[s.kind].absoluteMs);
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
      auth_method: s.authMethod ?? "passkey",
      created_at: now,
    })
    .execute();
  return { token, csrf, expiresAt, authMethod: s.authMethod ?? "passkey", createdAt: now };
}

export async function sessionBody(db: Identity["db"] | Tx, userId: string, accountId: string, s: NewSession) {
  const row = await db
    .selectFrom("memberships")
    .innerJoin("users", "users.id", "memberships.user_id")
    .innerJoin("accounts", "accounts.id", "memberships.account_id")
    .select(["users.email", "accounts.display_name", "memberships.role"])
    .where("memberships.user_id", "=", userId)
    .where("memberships.account_id", "=", accountId)
    .executeTakeFirst();
  // a membership removed after sign-in ends the session's access (authz denies it as well)
  if (!row) throw new ApiError("authentication_required");
  return {
    object: "dashboard_session" as const,
    user: { id: fromUuid("usr", userId), email: row.email },
    account: { id: fromUuid("acct", accountId), display_name: row.display_name },
    role: row.role,
    csrf_token: s.csrf,
    expires_at: Math.floor(s.expiresAt.getTime() / 1000),
    ...(s.authMethod && s.createdAt ? { sign_in: await signInSummary(db, userId, s.authMethod, s.createdAt) } : {}),
  };
}

/** `DashboardSession.sign_in` (spec 0.5.1, ADR-0026). */
export async function signInSummary(
  db: Identity["db"] | Tx,
  userId: string,
  authMethod: SessionAuthMethod,
  createdAt: Date,
  now: number = Date.now(),
) {
  const [pk, google] = await Promise.all([
    db
      .selectFrom("passkeys")
      .select((eb) => eb.fn.countAll<string>().as("n"))
      .where("user_id", "=", userId)
      .where("kind", "=", "dashboard")
      .executeTakeFirstOrThrow(),
    db
      .selectFrom("linked_identities")
      .select("subject")
      .where("user_id", "=", userId)
      .where("provider", "=", "google")
      .executeTakeFirst(),
  ]);
  const passkeys = Number(pk.n);
  const until = passkeySetupUntil({ passkeys, authMethod, createdAt, now });
  return {
    method: authMethod,
    passkeys,
    google_linked: google !== undefined,
    passkey_setup_until: until ? Math.floor(until.getTime() / 1000) : null,
  };
}

/** Number of dashboard passkeys of a user. */
export async function dashboardPasskeyCount(db: Identity["db"] | Tx, userId: string): Promise<number> {
  const r = await db
    .selectFrom("passkeys")
    .select((eb) => eb.fn.countAll<string>().as("n"))
    .where("user_id", "=", userId)
    .where("kind", "=", "dashboard")
    .executeTakeFirstOrThrow();
  return Number(r.n);
}

/**
 * ADR-0026: adding a passkey from a session needs a fresh confirmation — a step-up (≤ 10 min) when the user
 * has a passkey, else (Google-only) a Google sign-in within the last 10 minutes.
 */
async function requirePasskeyAddAllowed(
  id: Identity,
  db: Identity["db"] | Tx,
  userId: string,
  s: { step_up_at: Date | null; auth_method: SessionAuthMethod; created_at: Date },
) {
  const gate = passkeyAddGate({
    passkeys: await dashboardPasskeyCount(db, userId),
    stepUpAt: s.step_up_at,
    authMethod: s.auth_method,
    createdAt: s.created_at,
    now: id.now(),
    stepUpMs: STEP_UP_MS,
  });
  if (gate === "step_up_required") throw new ApiError("step_up_required");
  if (gate === "reauthentication_required")
    throw new ApiError("reauthentication_required", {
      params: { reason: "continue with Google again to add your first passkey (within 10 minutes of signing in)" },
    });
}

export const cookieFor = (kind: "dashboard" | "ops", s: NewSession) =>
  setCookie(kind === "ops" ? OPS_COOKIE : SESSION_COOKIE, s.token, Math.floor(LIFETIME[kind].absoluteMs / 1000));

/** The caller's own session row (the request token says who; the cookie says which session). */
export async function currentSession(id: Identity, meta: RequestMeta, userUuid: string) {
  const token = readCookie(meta.cookie, isConsoleHost(meta.host) ? OPS_COOKIE : SESSION_COOKIE);
  if (!token) throw new ApiError("authentication_required");
  const s = await id.db.selectFrom("sessions").selectAll().where("token_hash", "=", sha256(token)).executeTakeFirst();
  if (!s || s.user_id !== userUuid || s.revoked_at) throw new ApiError("authentication_required");
  return s;
}

/**
 * `GET /v1/auth/session` (spec 0.1.5, CR-15-01): the caller's dashboard session, so a reload or a new
 * tab recovers it without client storage. The CSRF token is the session's own, re-issued from its
 * encrypted copy (`csrf_enc`), never rotated; no cookie is set (authz already slid the TTL). The cookie
 * must name a valid dashboard session of the same user and account as the request token; anything else
 * (ops session, revoked/expired/idle, missing membership) is `401 authentication_required`.
 */
export async function getDashboardSession(id: Identity, principal: { sub: string; acct: string }, meta: RequestMeta) {
  const token = readCookie(meta.cookie, SESSION_COOKIE);
  if (!token) throw new ApiError("authentication_required");
  const s = await id.db.selectFrom("sessions").selectAll().where("token_hash", "=", sha256(token)).executeTakeFirst();
  if (
    s?.kind !== "dashboard" ||
    s.account_id === null ||
    s.user_id !== toUuid(principal.sub, "usr") ||
    s.account_id !== toUuid(principal.acct, "acct") ||
    sessionState(s, id.now(), "dashboard") !== "valid"
  )
    throw new ApiError("authentication_required");
  const csrf = id.cipher.decrypt(s.csrf_enc, `session:${s.id}:csrf`).toString("utf8");
  return sessionBody(id.db, s.user_id, s.account_id, {
    token: "",
    csrf,
    expiresAt: s.expires_at,
    authMethod: s.auth_method,
    createdAt: s.created_at,
  });
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

async function takeChallenge(tx: Tx, challenge: string, purpose: CeremonyPurpose) {
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
    purpose: CeremonyPurpose;
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

async function userPasskeys(id: Identity, userUuid: string, kind: "dashboard" | "ops" = "dashboard") {
  return id.db
    .selectFrom("passkeys")
    .select(["credential_id", "transports"])
    .where("user_id", "=", userUuid)
    .where("kind", "=", kind)
    .execute();
}

async function liveRegistration(id: Identity, token: string | undefined) {
  if (!token) throw new ApiError("link_expired");
  const r = await id.db
    .selectFrom("registration_tokens")
    .selectAll()
    .where("token_hash", "=", sha256(token))
    .executeTakeFirst();
  // operator enrolment tokens register console keys only (console.ts)
  if (!r || r.used_at || r.expires_at.getTime() <= id.now() || r.purpose === "ops_enrol")
    throw new ApiError("link_expired");
  return r;
}

export async function registrationOptions(
  id: Identity,
  b: { registration_token?: string | undefined },
  principal: { ptype: string; sub: string } | null,
  meta: RequestMeta,
) {
  let userName: string;
  let userHandle: Uint8Array;
  let link: { registrationHash?: Buffer; userId?: string };
  let exclude: { credential_id: Buffer; transports: string[] }[] = [];
  if (principal?.ptype === "session" && !b.registration_token) {
    const userUuid = toUuid(principal.sub, "usr");
    const session = await currentSession(id, meta, userUuid);
    if (session.kind !== "dashboard") throw new ApiError("authentication_required");
    await requirePasskeyAddAllowed(id, id.db, userUuid, session);
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
    if (r.purpose === "recovery" && r.user_id) exclude = await userPasskeys(id, r.user_id);
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
      await requirePasskeyAddAllowed(id, tx, c.user_id, s);
      await tx.insertInto("passkeys").values(passkey(c.user_id)).execute();
      // the same CSRF token (re-issued from its encrypted copy): no rotation, no stale caches
      const csrf = id.cipher.decrypt(s.csrf_enc, `session:${s.id}:csrf`).toString("utf8");
      await audit(id, tx, {
        accountUuid: s.account_id,
        actor: { type: "user", id: fromUuid("usr", c.user_id), ip: meta.ip },
        action: "passkey.added",
        details: { session_method: s.auth_method },
      });
      return {
        body: await sessionBody(tx, c.user_id, s.account_id as string, {
          token: "",
          csrf,
          expiresAt: s.expires_at,
          authMethod: s.auth_method,
          createdAt: s.created_at,
        }),
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
    if (reg.used_at || reg.expires_at <= now || reg.purpose === "ops_enrol") throw new ApiError("link_expired");
    await tx
      .updateTable("registration_tokens")
      .set({ used_at: now })
      .where("token_hash", "=", reg.token_hash)
      .execute();
    if (reg.purpose === "recovery") return recover(id, tx, reg, passkey, meta);
    const already = await tx.selectFrom("users").select("id").where("email", "=", reg.email).executeTakeFirst();
    if (already) throw new ApiError("link_expired");
    if (reg.purpose === "invite") return joinAsNewUser(id, tx, reg, passkey, meta);
    const { userId, accountId } = await createOwnerUser(id, tx, {
      email: reg.email,
      displayName: b.display_name,
      now,
      meta,
      method: "passkey",
      beforeEvents: (uid) => tx.insertInto("passkeys").values(passkey(uid)).execute(),
    });
    const s = await createSession(id, tx, { kind: "dashboard", userId, accountId, meta, steppedUp: true });
    return { body: await sessionBody(tx, userId, accountId, s), cookie: cookieFor("dashboard", s) };
  });
  return out.cookie ? respond(200, out.body, { "set-cookie": out.cookie }) : out.body;
}

/**
 * Sign-up's new user (email verified), account and owner membership, `evt.identity.account.created` and the
 * `account.created` audit row, in the caller's transaction. Shared by passkey sign-up and Google sign-up
 * (ADR-0026: the same path, the email verified by Google instead of a magic link).
 */
export async function createOwnerUser(
  id: Identity,
  tx: Tx,
  o: {
    email: string;
    displayName?: string | undefined;
    now: Date;
    meta: RequestMeta;
    method: "passkey" | "google";
    /** Rows that must exist before the event (the passkey, the linked identity). */
    beforeEvents?: (userId: string) => Promise<unknown>;
  },
): Promise<{ userId: string; accountId: string }> {
  const userId = uuidv7();
  const accountId = uuidv7();
  await tx
    .insertInto("users")
    .values({ id: userId, email: o.email, email_verified_at: o.now, last_login_at: o.now })
    .execute();
  const account = await tx
    .insertInto("accounts")
    .values({
      id: accountId,
      display_name: o.displayName ?? o.email.split("@")[0]?.slice(0, 100) ?? "My business",
      fee_schedule_id: DEFAULT_FEE_SCHEDULE,
      api_version: API_VERSION,
      settings: JSON.stringify(DEFAULT_SETTINGS),
    })
    .returningAll()
    .executeTakeFirstOrThrow();
  await tx.insertInto("memberships").values({ account_id: accountId, user_id: userId, role: "owner" }).execute();
  await o.beforeEvents?.(userId);
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
    actor: { type: "user", id: fromUuid("usr", userId), ip: o.meta.ip },
    action: "account.created",
    target: { type: "account", id: view.id },
    ...(o.method === "google" ? { details: { method: "google" } } : {}),
  });
  return { userId, accountId };
}

type PasskeyRow = (userId: string) => {
  id: string;
  user_id: string;
  credential_id: Buffer;
  public_key: Buffer;
  sign_count: number;
  transports: string[];
  aaguid: string | null;
  backed_up: boolean;
  name: string;
};

type RegistrationRow = { token_hash: Buffer; email: string; user_id: string | null; invitation_id: string | null };

/** The account a sign-in lands on: the most recently used membership (switchSessionAccount, sign-ins). */
async function landingAccount(tx: Tx, userId: string) {
  const m = await tx
    .selectFrom("memberships")
    .innerJoin("accounts", "accounts.id", "memberships.account_id")
    .select(["memberships.account_id", "memberships.role"])
    .where("memberships.user_id", "=", userId)
    .where("accounts.status", "<>", "closed")
    .orderBy((eb) => eb.fn.coalesce("memberships.last_used_at", "memberships.created_at"), "desc")
    .executeTakeFirst();
  if (m)
    await tx
      .updateTable("memberships")
      .set({ last_used_at: await dbNow(tx) })
      .where("account_id", "=", m.account_id)
      .where("user_id", "=", userId)
      .execute();
  return m;
}

/** Invitation link of a new user: the user, a membership in the inviting account (no new account), a session. */
async function joinAsNewUser(id: Identity, tx: Tx, reg: RegistrationRow, passkey: PasskeyRow, meta: RequestMeta) {
  if (!reg.invitation_id) throw new ApiError("link_expired");
  const inv = await tx
    .selectFrom("invitations")
    .selectAll()
    .where("id", "=", reg.invitation_id)
    .forUpdate()
    .executeTakeFirst();
  const now = await dbNow(tx);
  if (inv?.status !== "pending" || inv.expires_at <= now || inv.email !== reg.email)
    throw new ApiError("invitation_invalid", { params: { reason: "it is no longer pending" } });
  const userId = uuidv7();
  await tx
    .insertInto("users")
    .values({ id: userId, email: reg.email, email_verified_at: now, last_login_at: now })
    .execute();
  await tx.insertInto("passkeys").values(passkey(userId)).execute();
  await joinInvitation(id, tx, inv, userId, meta.ip);
  const s = await createSession(id, tx, {
    kind: "dashboard",
    userId,
    accountId: inv.account_id,
    meta,
    steppedUp: true,
  });
  return { body: await sessionBody(tx, userId, inv.account_id, s), cookie: cookieFor("dashboard", s) };
}

/**
 * Recovery (§5, §12): the new passkey joins the existing user (earlier passkeys stay), every account
 * the user owns or administers gets `recovered_at = now()` (destination creation and approval locked
 * 48 h: owners and admins can both change destinations), and the session lands on the most recently
 * used account. The new session carries no step-up.
 */
async function recover(id: Identity, tx: Tx, reg: RegistrationRow, passkey: PasskeyRow, meta: RequestMeta) {
  const userId = reg.user_id;
  if (!userId) throw new ApiError("link_expired");
  const user = await tx.selectFrom("users").select(["status"]).where("id", "=", userId).forUpdate().executeTakeFirst();
  if (user?.status !== "active") throw new ApiError("link_expired");
  const now = await dbNow(tx);
  await tx.insertInto("passkeys").values(passkey(userId)).execute();
  const counted = await tx
    .updateTable("users")
    .set((eb) => ({ last_login_at: now, recovered_at: now, recovery_count: eb("recovery_count", "+", 1) }))
    .where("id", "=", userId)
    .returning("recovery_count")
    .executeTakeFirstOrThrow();
  const managed = await tx
    .selectFrom("memberships")
    .select("account_id")
    .where("user_id", "=", userId)
    .where("role", "in", ["owner", "admin"])
    .execute();
  for (const m of managed) {
    await tx
      .updateTable("accounts")
      .set({ recovered_at: now, updated_at: now })
      .where("id", "=", m.account_id)
      .execute();
    await audit(id, tx, {
      accountUuid: m.account_id,
      actor: { type: "user", id: fromUuid("usr", userId), ip: meta.ip },
      action: "user.recovered",
      target: { type: "user", id: fromUuid("usr", userId) },
      details: { destination_lock_until: new Date(now.getTime() + id.recoveryLockMs).toISOString() },
    });
  }
  // spec 0.2.1: notify mails the owners and admins of every locked account (`security.recovery`)
  await emitEvent(tx, {
    subject: "evt.identity.user.recovered",
    aggregate: { type: "user", id: fromUuid("usr", userId), version: counted.recovery_count },
    accountUuid: null,
    livemode: null,
    object: {
      user_id: fromUuid("usr", userId),
      account_ids: managed.map((x) => fromUuid("acct", x.account_id)),
      recovered_at: now.toISOString(),
      lock_until: new Date(now.getTime() + id.recoveryLockMs).toISOString(),
    },
  });
  const m = await landingAccount(tx, userId);
  if (!m) throw failed("the user has no account");
  const s = await createSession(id, tx, {
    kind: "dashboard",
    userId,
    accountId: m.account_id,
    meta,
    steppedUp: false,
    authMethod: "recovery",
  });
  id.log.warn({ user: fromUuid("usr", userId), accounts: managed.length }, "account recovery completed");
  return { body: await sessionBody(tx, userId, m.account_id, s), cookie: cookieFor("dashboard", s) };
}

export async function currentSessionTx(tx: Tx, meta: RequestMeta, userUuid: string) {
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
  rp: { rpId: string; origins: readonly string[]; kind: "dashboard" | "ops" } = {
    rpId: id.webauthn.rpId,
    origins: id.webauthn.origins,
    kind: "dashboard",
  },
) {
  const credentialId = Buffer.from(credential.rawId, "base64url");
  // dashboard ceremonies accept dashboard passkeys only; console ceremonies ops passkeys only
  let q = tx.selectFrom("passkeys").selectAll().where("credential_id", "=", credentialId).where("kind", "=", rp.kind);
  if (userUuid) q = q.where("user_id", "=", userUuid);
  const pk = await q.forUpdate().executeTakeFirst();
  if (!pk) throw failed("unknown passkey");
  // a beta platform passkey (NP_OPS_ALLOW_PLATFORM_PASSKEYS) signs in and steps up only while the flag is on
  if (pk.ops_policy === "platform_beta" && id.console.allowPlatformPasskeys !== true)
    throw failed("platform passkeys are not accepted");
  let r: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    r = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: [...rp.origins],
      expectedRPID: rp.rpId,
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
      const m = await landingAccount(tx, userId);
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
        details: { method: "passkey" },
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
  // ADR-0026: step-ups are passkey assertions only; a Google-only user adds a passkey first
  if (keys.length === 0)
    throw new ApiError("passkey_required", { params: { reason: "sensitive actions are confirmed with a passkey." } });
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

export {
  challengeOf,
  createSession,
  failed,
  landingAccount,
  matchesHash,
  storeChallenge,
  takeChallenge,
  userPasskeys,
  verifyAssertion,
};

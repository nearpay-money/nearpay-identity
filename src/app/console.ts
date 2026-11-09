/**
 * Console (ops) sign-in (lld/identity.md §6.1, spec 0.2.0 console routes, service identity).
 *
 * `operator-add` (ops CLI) emails a 24 h enrolment link → `opsEnrolmentVerify` → a 5-minute
 * registration token → hardware-passkey registration on the console host (RP id = console host,
 * attestation `direct`, AAGUID allow-list, device-bound) → console session `__Host-np_ops`
 * (30 min idle / 12 h absolute; sign-in counts as a step-up). Only `kind = 'ops'` passkeys of active
 * operators sign in or step up; every refusal is `400 webauthn_failed` (catalogue status) (no enumeration). Every
 * console sign-in action is audited with `actor_type = operator`.
 *
 * `NP_OPS_AUTH_MODE=cloudflare_access` replaces all of the above with Cloudflare Access (Google login):
 * authz mints the ops token from the verified Access assertion (app/console-access.ts); here the session
 * view is built from it, logout only audits, and every passkey ceremony is refused.
 * `NP_OPS_ALLOW_PLATFORM_PASSKEYS=true` (BETA ONLY) admits platform / synced passkeys at registration.
 */

import { withTx } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError, respond } from "@nearpay-internal/service";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { decodeAttestationObject } from "@simplewebauthn/server/helpers";
import { authenticatorProblem, type OpsPasskeyPolicy, platformPasskeyProblem } from "../domain/console/console.js";
import {
  clearCookie,
  idleExpiresAt,
  newSecret,
  OPS_COOKIE,
  readCookie,
  STEP_UP_MS,
  sessionState,
  sha256,
  stepUpUntil,
} from "../domain/session/session.js";
import {
  CEREMONY_MS,
  challengeOf,
  cookieFor,
  createSession,
  failed,
  REGISTRATION_MS,
  type RequestMeta,
  storeChallenge,
  takeChallenge,
  userPasskeys,
  verifyAssertion,
} from "./auth.js";
import { ACCESS_REAUTH_URL, accessCsrf, accessStepUpUntil, verifyAccess } from "./console-access.js";
import { accessMode, audit, dbNow, type Identity, type Tx } from "./context.js";
import { activeOperatorByEmail } from "./operators.js";

export const ENROLMENT_MS = 24 * 3_600_000;

type OpsRole = "ops" | "ops_admin";
type Credential = Parameters<typeof verifyAssertion>[2];
type RegistrationCredential = Parameters<typeof verifyRegistrationResponse>[0]["response"];

function rp(id: Identity) {
  if (!id.console.origin || !id.console.rpId) return null;
  return { rpId: id.console.rpId, origins: [id.console.origin], kind: "ops" as const };
}

const unix = (d: Date) => Math.floor(d.getTime() / 1000);

/** Passkey ceremonies do not exist in Cloudflare Access mode. */
function passkeyMode(id: Identity) {
  if (accessMode(id.console))
    throw new ApiError("authenticator_not_allowed", {
      message: "The console signs in with Cloudflare Access; operator passkeys are not used.",
    });
}
const operatorActor = (userUuid: string, ip: string | null) => ({
  type: "operator" as const,
  id: fromUuid("usr", userUuid),
  ip,
});

async function activeOperator(db: Identity["db"] | Tx, userUuid: string) {
  return db
    .selectFrom("ops_operators")
    .innerJoin("users", "users.id", "ops_operators.user_id")
    .select([
      "ops_operators.role",
      "users.email",
      "users.status",
      "ops_operators.passkey_policy",
      "ops_operators.passkey_attachment",
      "ops_operators.passkey_synced",
    ])
    .where("ops_operators.user_id", "=", userUuid)
    .where("ops_operators.revoked_at", "is", null)
    .executeTakeFirst();
}

/** `OpsSession` for a session row (CSRF re-issued from its encrypted copy). */
async function opsSessionBody(
  id: Identity,
  db: Identity["db"] | Tx,
  s: { id: string; user_id: string; csrf_enc: Buffer; step_up_at: Date | null; expires_at: Date; last_seen_at: Date },
  csrf?: string,
) {
  const op = await activeOperator(db, s.user_id);
  if (op?.status !== "active") throw new ApiError("authentication_required");
  const until = stepUpUntil(s.step_up_at, id.now());
  return {
    // extensions (open object, not in the spec): the auth mode, and how the operator's passkey was admitted
    auth_mode: "passkey" as const,
    ...(op.passkey_policy
      ? {
          passkey: {
            policy: op.passkey_policy,
            attachment: op.passkey_attachment,
            synced: op.passkey_synced,
            ...(op.passkey_policy === "platform_beta" ? { label: "platform passkey — beta" } : {}),
          },
        }
      : {}),
    object: "ops_session" as const,
    operator: { id: fromUuid("usr", s.user_id), email: op.email },
    role: op.role,
    csrf_token: csrf ?? id.cipher.decrypt(s.csrf_enc, `session:${s.id}:csrf`).toString("utf8"),
    step_up_until: until ?? null,
    idle_expires_at: unix(idleExpiresAt(s, "ops")),
    expires_at: unix(s.expires_at),
  };
}

async function newOpsSession(id: Identity, tx: Tx, userUuid: string, meta: RequestMeta) {
  const s = await createSession(id, tx, { kind: "ops", userId: userUuid, accountId: null, meta, steppedUp: true });
  const row = await tx
    .selectFrom("sessions")
    .selectAll()
    .where("token_hash", "=", sha256(s.token))
    .executeTakeFirstOrThrow();
  return { body: await opsSessionBody(id, tx, row, s.csrf), cookie: cookieFor("ops", s) };
}

// ---------------------------------------------------------------------------------------------
// Enrolment (ops CLI `operator-add` → link → registration token → hardware passkey)
// ---------------------------------------------------------------------------------------------

/**
 * Emails a 24 h enrolment link to an operator (ops CLI). The token travels only in the link fragment
 * (`<console>/auth/enrol#token=…`) and is stored as SHA-256.
 */
export async function sendEnrolment(id: Identity, user: { id: string; email: string }, role: OpsRole) {
  if (!id.console.origin) throw new Error("NP_OPS_ORIGIN is not configured: no enrolment link can be sent");
  const token = newSecret(32);
  const hash = sha256(token);
  await id.db
    .insertInto("magic_links")
    .values({
      token_hash: hash,
      email: user.email,
      purpose: "ops_enrol",
      role,
      expires_at: new Date(id.now() + ENROLMENT_MS),
    })
    .execute();
  await id.peers.sendOpsEnrolment({
    to: user.email,
    link_url: `${id.console.origin}/auth/enrol#token=${token}`,
    role,
    expires_in_minutes: ENROLMENT_MS / 60_000,
    dedupe_key: `ops-enrol:${hash.toString("hex")}`,
  });
}

/** `opsEnrolmentVerify`: unknown, used and expired links and revoked operators all answer alike. */
export async function enrolmentVerify(id: Identity, token: string) {
  passkeyMode(id);
  return withTx(id.db, async (tx) => {
    const link = await tx
      .selectFrom("magic_links")
      .selectAll()
      .where("token_hash", "=", sha256(token))
      .where("purpose", "=", "ops_enrol")
      .forUpdate()
      .executeTakeFirst();
    if (!link) throw new ApiError("link_expired");
    if (link.used_at) throw new ApiError("link_used");
    const now = await dbNow(tx);
    if (link.expires_at <= now) throw new ApiError("link_expired");
    const user = await tx.selectFrom("users").select(["id"]).where("email", "=", link.email).executeTakeFirst();
    const op = user ? await activeOperator(tx, user.id) : undefined;
    if (!user || !op || op.status !== "active") throw new ApiError("link_expired");
    await tx.updateTable("magic_links").set({ used_at: now }).where("token_hash", "=", link.token_hash).execute();
    const registration = newSecret(32);
    const expires = new Date(now.getTime() + REGISTRATION_MS);
    await tx
      .insertInto("registration_tokens")
      .values({
        token_hash: sha256(registration),
        email: link.email,
        user_handle: Buffer.from(user.id.replaceAll("-", ""), "hex"),
        expires_at: expires,
        purpose: "ops_enrol",
        user_id: user.id,
      })
      .execute();
    return {
      object: "ops_registration" as const,
      registration_token: registration,
      email: link.email,
      expires_at: unix(expires),
      // extension (beta only): the console then offers platform passkeys instead of insisting on a key
      ...(id.console.allowPlatformPasskeys ? { platform_passkeys_allowed: true } : {}),
    };
  });
}

async function liveEnrolment(db: Identity["db"] | Tx, token: string, now: number, lock = false) {
  let q = db.selectFrom("registration_tokens").selectAll().where("token_hash", "=", sha256(token));
  if (lock) q = q.forUpdate();
  const r = await q.executeTakeFirst();
  if (r?.purpose !== "ops_enrol" || !r.user_id || r.used_at || r.expires_at.getTime() <= now)
    throw new ApiError("link_expired");
  return r as typeof r & { user_id: string };
}

export async function registrationOptions(id: Identity, b: { registration_token: string }) {
  passkeyMode(id);
  const party = rp(id);
  if (!party) throw new ApiError("authenticator_not_allowed");
  const r = await liveEnrolment(id.db, b.registration_token, id.now());
  const existing = await userPasskeys(id, r.user_id, "ops");
  const options = await generateRegistrationOptions({
    rpName: "NearPay Console",
    rpID: party.rpId,
    userName: r.email,
    userDisplayName: r.email,
    userID: new Uint8Array(r.user_handle),
    timeout: CEREMONY_MS,
    attestationType: "direct",
    excludeCredentials: existing.map((p) => ({ id: p.credential_id.toString("base64url"), transports: p.transports })),
    // beta (NP_OPS_ALLOW_PLATFORM_PASSKEYS): no attachment preference, so Touch ID / phone passkeys are offered
    authenticatorSelection: id.console.allowPlatformPasskeys
      ? { residentKey: "required", userVerification: "required" }
      : { authenticatorAttachment: "cross-platform", residentKey: "required", userVerification: "required" },
    supportedAlgorithmIDs: [-8, -7, -257],
  });
  await storeChallenge(id, options.challenge, {
    purpose: "ops_registration",
    registrationHash: r.token_hash,
    userId: r.user_id,
  });
  return options;
}

export async function registrationVerify(
  id: Identity,
  b: { registration_token: string; credential: RegistrationCredential; passkey_name?: string | undefined },
  meta: RequestMeta,
) {
  passkeyMode(id);
  const party = rp(id);
  if (!party) throw new ApiError("authenticator_not_allowed");
  const challenge = challengeOf(b.credential.response.clientDataJSON);
  let verified: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verified = await verifyRegistrationResponse({
      response: b.credential,
      expectedChallenge: challenge,
      expectedOrigin: party.origins,
      expectedRPID: party.rpId,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-8, -7, -257],
    });
  } catch (e) {
    id.metrics.loginFailure();
    throw failed((e as Error).message.slice(0, 200));
  }
  if (!verified.verified) throw failed("the attestation did not verify");
  const info = verified.registrationInfo;
  const att = decodeAttestationObject(new Uint8Array(info.attestationObject));
  const synced = info.credentialDeviceType === "multiDevice" || info.credentialBackedUp;
  const problem = authenticatorProblem({
    env: id.env,
    fmt: info.fmt,
    hasX5c: Array.isArray(att.get("attStmt").get("x5c")) && (att.get("attStmt").get("x5c") as unknown[]).length > 0,
    aaguid: info.aaguid,
    synced,
    allowlist: id.console.aaguids,
    rootsConfigured: id.console.attestationRoots.length > 0,
  });
  let policy: OpsPasskeyPolicy = "hardware";
  if (problem) {
    // beta only: a platform / synced passkey (UV verified above; resident key still required)
    const rk = (b.credential.clientExtensionResults as { credProps?: { rk?: boolean } } | undefined)?.credProps?.rk;
    const beta = platformPasskeyProblem({ allowed: id.console.allowPlatformPasskeys === true, residentKey: rk });
    if (beta) {
      id.log.warn({ aaguid: info.aaguid, fmt: info.fmt, reason: problem, beta }, "operator key refused");
      throw new ApiError("authenticator_not_allowed");
    }
    policy = "platform_beta";
  }
  const attachment =
    b.credential.authenticatorAttachment === "platform" || b.credential.authenticatorAttachment === "cross-platform"
      ? b.credential.authenticatorAttachment
      : null;

  const out = await withTx(id.db, async (tx) => {
    const c = await takeChallenge(tx, challenge, "ops_registration");
    if (!c.registration_token_hash?.equals(sha256(b.registration_token))) throw new ApiError("link_expired");
    const reg = await liveEnrolment(tx, b.registration_token, id.now(), true);
    const op = await activeOperator(tx, reg.user_id);
    if (op?.status !== "active") throw new ApiError("link_expired");
    const now = await dbNow(tx);
    await tx
      .updateTable("registration_tokens")
      .set({ used_at: now })
      .where("token_hash", "=", reg.token_hash)
      .execute();
    const credentialId = Buffer.from(info.credential.id, "base64url");
    const taken = await tx
      .selectFrom("passkeys")
      .select("id")
      .where("credential_id", "=", credentialId)
      .executeTakeFirst();
    if (taken) throw failed("this key is already registered");
    await tx
      .insertInto("passkeys")
      .values({
        id: uuidv7(),
        user_id: reg.user_id,
        credential_id: credentialId,
        public_key: Buffer.from(info.credential.publicKey),
        sign_count: info.credential.counter,
        transports: info.credential.transports ?? b.credential.response.transports ?? [],
        aaguid: info.aaguid.toLowerCase(),
        backed_up: info.credentialBackedUp,
        name: b.passkey_name ?? (policy === "platform_beta" ? "Platform passkey" : "Security key"),
        kind: "ops",
        ops_policy: policy,
      })
      .execute();
    // the operator record shows how their console passkey was admitted (console session, ops CLI)
    await tx
      .updateTable("ops_operators")
      .set({
        passkey_policy: policy,
        passkey_attachment: attachment,
        passkey_synced: synced,
        passkey_registered_at: now,
      })
      .where("user_id", "=", reg.user_id)
      .execute();
    await tx
      .updateTable("users")
      .set({ email_verified_at: now, last_login_at: now })
      .where("id", "=", reg.user_id)
      .execute();
    await audit(id, tx, {
      accountUuid: null,
      actor: operatorActor(reg.user_id, meta.ip),
      action: "ops.enrolled",
      target: { type: "user", id: fromUuid("usr", reg.user_id) },
      details: { role: op.role, aaguid: info.aaguid.toLowerCase(), fmt: info.fmt, passkey_policy: policy },
    });
    if (policy === "platform_beta")
      await audit(id, tx, {
        accountUuid: null,
        actor: operatorActor(reg.user_id, meta.ip),
        action: "ops.passkey_platform_registered",
        target: { type: "user", id: fromUuid("usr", reg.user_id) },
        details: {
          beta: true,
          flag: "NP_OPS_ALLOW_PLATFORM_PASSKEYS",
          attachment,
          synced,
          fmt: info.fmt,
          aaguid: info.aaguid.toLowerCase(),
        },
      });
    return newOpsSession(id, tx, reg.user_id, meta);
  });
  return respond(200, out.body, { "set-cookie": out.cookie });
}

// ---------------------------------------------------------------------------------------------
// Sign-in, step-up, session, logout
// ---------------------------------------------------------------------------------------------

export async function authenticationOptions(id: Identity, meta: RequestMeta) {
  passkeyMode(id);
  const party = rp(id);
  // no console configured: still answer, every verification then fails (no configuration leak)
  const options = await generateAuthenticationOptions({
    rpID: party?.rpId ?? "console.invalid",
    userVerification: "required",
    timeout: CEREMONY_MS,
  });
  await storeChallenge(id, options.challenge, {
    purpose: "ops_authentication",
    ...(meta.host ? { host: meta.host } : {}),
  });
  return options;
}

export async function authenticationVerify(id: Identity, credential: Credential, meta: RequestMeta) {
  passkeyMode(id);
  const party = rp(id);
  try {
    if (!party) throw failed("the console is not configured");
    const challenge = challengeOf(credential.response.clientDataJSON);
    const out = await withTx(id.db, async (tx) => {
      await takeChallenge(tx, challenge, "ops_authentication");
      const { userId } = await verifyAssertion(id, tx, credential, challenge, undefined, party);
      const op = await activeOperator(tx, userId);
      if (op?.status !== "active") throw failed("not an active operator");
      await tx
        .updateTable("users")
        .set({ last_login_at: await dbNow(tx) })
        .where("id", "=", userId)
        .execute();
      await audit(id, tx, {
        accountUuid: null,
        actor: operatorActor(userId, meta.ip),
        action: "ops.signed_in",
        details: { role: op.role },
      });
      return newOpsSession(id, tx, userId, meta);
    });
    return respond(200, out.body, { "set-cookie": out.cookie });
  } catch (e) {
    id.metrics.loginFailure();
    // every refusal looks the same
    if (e instanceof ApiError && e.code !== "webauthn_failed") throw failed("refused");
    throw e;
  }
}

/** The caller's console session row (cookie `__Host-np_ops`, same operator as the request token, valid). */
async function currentOpsSession(id: Identity, db: Identity["db"] | Tx, meta: RequestMeta, sub: string, lock = false) {
  const token = readCookie(meta.cookie, OPS_COOKIE);
  if (!token) throw new ApiError("authentication_required");
  let q = db.selectFrom("sessions").selectAll().where("token_hash", "=", sha256(token));
  if (lock) q = q.forUpdate();
  const s = await q.executeTakeFirst();
  if (s?.kind !== "ops" || s.user_id !== toUuid(sub, "usr") || sessionState(s, id.now(), "ops") !== "valid")
    throw new ApiError("authentication_required");
  return s;
}

export async function stepUpOptions(id: Identity, principal: { sub: string }, meta: RequestMeta) {
  passkeyMode(id);
  const party = rp(id);
  const s = await currentOpsSession(id, id.db, meta, principal.sub);
  const keys = await userPasskeys(id, s.user_id, "ops");
  const options = await generateAuthenticationOptions({
    rpID: party?.rpId ?? "console.invalid",
    userVerification: "required",
    timeout: CEREMONY_MS,
    allowCredentials: keys.map((k) => ({ id: k.credential_id.toString("base64url"), transports: k.transports })),
  });
  await storeChallenge(id, options.challenge, { purpose: "ops_step_up", userId: s.user_id, sessionId: s.id });
  return options;
}

export async function stepUpVerify(
  id: Identity,
  principal: { sub: string },
  credential: Credential,
  meta: RequestMeta,
) {
  passkeyMode(id);
  const party = rp(id);
  try {
    if (!party) throw failed("the console is not configured");
    const challenge = challengeOf(credential.response.clientDataJSON);
    return await withTx(id.db, async (tx) => {
      const c = await takeChallenge(tx, challenge, "ops_step_up");
      const s = await currentOpsSession(id, tx, meta, principal.sub, true);
      if (c.session_id !== s.id || c.user_id !== s.user_id) throw failed("the challenge belongs to another session");
      await verifyAssertion(id, tx, credential, challenge, s.user_id, party);
      const now = await dbNow(tx);
      const updated = await tx
        .updateTable("sessions")
        .set({ step_up_at: now, last_seen_at: now })
        .where("id", "=", s.id)
        .returningAll()
        .executeTakeFirstOrThrow();
      id.cache.purgeSession(s.token_hash.toString("hex"));
      await audit(id, tx, {
        accountUuid: null,
        actor: operatorActor(s.user_id, meta.ip),
        action: "ops.step_up",
        details: { step_up_until: new Date(now.getTime() + STEP_UP_MS).toISOString() },
      });
      return opsSessionBody(id, tx, updated);
    });
  } catch (e) {
    id.metrics.loginFailure();
    throw e;
  }
}

/**
 * Access mode: the console session is the verified Access login (authz already checked it; it is verified
 * again here for its times). The sign-in is audited once per Access login (deterministic event id).
 */
async function accessSession(id: Identity, principal: { sub: string }, meta: RequestMeta) {
  const v = id.console.access;
  const nowS = Math.floor(id.now() / 1000);
  const who = v ? await verifyAccess(v, meta.accessJwt, nowS) : null;
  if (!v || !who) throw new ApiError("authentication_required");
  const op = await activeOperatorByEmail(id.db, who.email);
  if (!op || fromUuid("usr", op.user_id) !== principal.sub) throw new ApiError("authentication_required");
  await audit(id, id.db, {
    accountUuid: null,
    actor: operatorActor(op.user_id, meta.ip),
    action: "ops.signed_in",
    details: { role: op.role, auth_mode: "cloudflare_access", access_iat: who.iat },
    eventId: accessSignInEventId(op.user_id, who.iat),
  });
  return {
    auth_mode: "cloudflare_access" as const,
    reauth_url: ACCESS_REAUTH_URL,
    object: "ops_session" as const,
    operator: { id: principal.sub, email: op.email },
    role: op.role,
    csrf_token: accessCsrf(v, principal.sub, who.iat),
    step_up_until: accessStepUpUntil(who.iat, nowS) ?? null,
    idle_expires_at: who.exp,
    expires_at: who.exp,
  };
}

/** One audit event per Access login: a UUID (v8 layout) derived from the operator and the login time. */
export function accessSignInEventId(userUuid: string, iat: number): string {
  const h = sha256(`ops-access-signin:${userUuid}:${iat}`).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-8${h.slice(13, 16)}-${((Number.parseInt(h.slice(16, 17), 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export async function getOpsSession(id: Identity, principal: { sub: string }, meta: RequestMeta) {
  if (accessMode(id.console)) return accessSession(id, principal, meta);
  return opsSessionBody(id, id.db, await currentOpsSession(id, id.db, meta, principal.sub));
}

export async function logout(id: Identity, principal: { sub: string }, meta: RequestMeta) {
  if (accessMode(id.console)) {
    // the Access login ends at Cloudflare (`/cdn-cgi/access/logout`); identity records the sign-out
    await audit(id, id.db, {
      accountUuid: null,
      actor: { type: "operator", id: principal.sub, ip: meta.ip },
      action: "ops.signed_out",
      details: { auth_mode: "cloudflare_access" },
    });
    return respond(204, undefined, {});
  }
  const s = await currentOpsSession(id, id.db, meta, principal.sub);
  await withTx(id.db, async (tx) => {
    await tx
      .updateTable("sessions")
      .set({ revoked_at: await dbNow(tx) })
      .where("id", "=", s.id)
      .execute();
    await audit(id, tx, { accountUuid: null, actor: operatorActor(s.user_id, meta.ip), action: "ops.signed_out" });
  });
  id.cache.purgeSession(s.token_hash.toString("hex"));
  return respond(204, undefined, { "set-cookie": clearCookie(OPS_COOKIE) });
}

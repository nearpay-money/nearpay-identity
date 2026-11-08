/**
 * Console (ops) sign-in (lld/identity.md §6.1, spec 0.2.0 console routes, service identity).
 *
 * `operator-add` (ops CLI) emails a 24 h enrolment link → `opsEnrolmentVerify` → a 5-minute
 * registration token → hardware-passkey registration on the console host (RP id = console host,
 * attestation `direct`, AAGUID allow-list, device-bound) → console session `__Host-np_ops`
 * (30 min idle / 12 h absolute; sign-in counts as a step-up). Only `kind = 'ops'` passkeys of active
 * operators sign in or step up; every refusal is `400 webauthn_failed` (catalogue status) (no enumeration). Every
 * console sign-in action is audited with `actor_type = operator`.
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
import { authenticatorProblem } from "../domain/console/console.js";
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
import { audit, dbNow, type Identity, type Tx } from "./context.js";

export const ENROLMENT_MS = 24 * 3_600_000;

type OpsRole = "ops" | "ops_admin";
type Credential = Parameters<typeof verifyAssertion>[2];
type RegistrationCredential = Parameters<typeof verifyRegistrationResponse>[0]["response"];

function rp(id: Identity) {
  if (!id.console.origin || !id.console.rpId) return null;
  return { rpId: id.console.rpId, origins: [id.console.origin], kind: "ops" as const };
}

const unix = (d: Date) => Math.floor(d.getTime() / 1000);
const operatorActor = (userUuid: string, ip: string | null) => ({
  type: "operator" as const,
  id: fromUuid("usr", userUuid),
  ip,
});

async function activeOperator(db: Identity["db"] | Tx, userUuid: string) {
  return db
    .selectFrom("ops_operators")
    .innerJoin("users", "users.id", "ops_operators.user_id")
    .select(["ops_operators.role", "users.email", "users.status"])
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
    authenticatorSelection: {
      authenticatorAttachment: "cross-platform",
      residentKey: "required",
      userVerification: "required",
    },
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
  const problem = authenticatorProblem({
    env: id.env,
    fmt: info.fmt,
    hasX5c: Array.isArray(att.get("attStmt").get("x5c")) && (att.get("attStmt").get("x5c") as unknown[]).length > 0,
    aaguid: info.aaguid,
    synced: info.credentialDeviceType === "multiDevice" || info.credentialBackedUp,
    allowlist: id.console.aaguids,
    rootsConfigured: id.console.attestationRoots.length > 0,
  });
  if (problem) {
    id.log.warn({ aaguid: info.aaguid, fmt: info.fmt, reason: problem }, "operator key refused");
    throw new ApiError("authenticator_not_allowed");
  }

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
        name: b.passkey_name ?? "Security key",
        kind: "ops",
      })
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
      details: { role: op.role, aaguid: info.aaguid.toLowerCase(), fmt: info.fmt },
    });
    return newOpsSession(id, tx, reg.user_id, meta);
  });
  return respond(200, out.body, { "set-cookie": out.cookie });
}

// ---------------------------------------------------------------------------------------------
// Sign-in, step-up, session, logout
// ---------------------------------------------------------------------------------------------

export async function authenticationOptions(id: Identity, meta: RequestMeta) {
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

export async function getOpsSession(id: Identity, principal: { sub: string }, meta: RequestMeta) {
  return opsSessionBody(id, id.db, await currentOpsSession(id, id.db, meta, principal.sub));
}

export async function logout(id: Identity, principal: { sub: string }, meta: RequestMeta) {
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

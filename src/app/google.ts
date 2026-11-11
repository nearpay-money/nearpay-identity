/**
 * Continue with Google (ADR-0026, lld/identity.md §22): sign-in / sign-up, linking from Settings and
 * unlinking. OpenID Connect authorization code flow with PKCE (S256), `state` and `nonce`, run here;
 * the browser only carries the flow cookie and Google's redirect.
 *
 * - The flow is single use, 10 minutes, and accepted only from the browser holding its cookie (binding);
 *   it is consumed before the code is exchanged, so a replayed callback never runs twice.
 * - A Google login is the Google `sub` in `linked_identities`. A new verified email creates a user and an
 *   account exactly like sign-up; an email that already has a user is refused (never linked automatically).
 * - Google sessions carry no step-up: sensitive actions still need a passkey assertion.
 */
import { withTx } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError, respond } from "@nearpay-internal/service";
import { GOOGLE_FLOW_COOKIE } from "@nearpay-money/spec";
import {
  clearFlowCookie,
  decideLink,
  decideSignIn,
  errorPath,
  FLOW_MS,
  type FlowIntent,
  type FlowPurpose,
  flowCookie,
  type GoogleSignInError,
  isSafeNext,
  pkceChallenge,
  START_LIMIT,
  successPath,
} from "../domain/google/google.js";
import { newSecret, readCookie, sessionState, sha256 } from "../domain/session/session.js";
import { GoogleRejected } from "../infra/clients/google.js";
import {
  cookieFor,
  createOwnerUser,
  createSession,
  currentSessionTx,
  dashboardPasskeyCount,
  landingAccount,
  matchesHash,
  type NewSession,
  type RequestMeta,
} from "./auth.js";
import { audit, dbNow, emitEvent, type Identity, type Tx } from "./context.js";

function google(id: Identity) {
  if (!id.google) throw new ApiError("google_signin_disabled");
  return id.google;
}

/** `GET /v1/auth/methods`: whether the dashboard may offer Continue with Google. */
export const authMethods = (id: Identity) => ({
  object: "auth_methods" as const,
  passkey: true as const,
  google: id.google != null,
});

async function startFlow(
  id: Identity,
  f: {
    purpose: FlowPurpose;
    intent: FlowIntent;
    next: string | null;
    userId: string | null;
    sessionId: string | null;
  },
) {
  const g = google(id);
  const state = newSecret(32);
  const binding = newSecret(32);
  const nonce = newSecret(32);
  const verifier = newSecret(32); // 43 base64url characters (RFC 7636: 43–128)
  const flowId = uuidv7();
  const expires = new Date(id.now() + FLOW_MS);
  await id.db
    .insertInto("oauth_flows")
    .values({
      id: flowId,
      provider: "google",
      purpose: f.purpose,
      intent: f.intent,
      state_hash: sha256(state),
      binding_hash: sha256(binding),
      nonce_hash: sha256(nonce),
      code_verifier_enc: id.cipher.encrypt(verifier, `oauth_flow:${flowId}:verifier`),
      next_path: f.next,
      user_id: f.userId,
      session_id: f.sessionId,
      expires_at: expires,
    })
    .execute();
  return respond(
    200,
    {
      object: "google_authorization" as const,
      authorization_url: g.authorizationUrl({
        state,
        nonce,
        codeChallenge: pkceChallenge(verifier),
        selectAccount: f.purpose === "link",
      }),
      expires_at: Math.floor(expires.getTime() / 1000),
    },
    { "set-cookie": flowCookie(binding) },
  );
}

/** `POST /v1/auth/google/start` (anonymous; per-IP limit on top of the gateway's anonymous limit). */
export async function startSignIn(
  id: Identity,
  b: { intent?: FlowIntent | undefined; next?: string | undefined },
  meta: RequestMeta,
) {
  google(id);
  const limit = await id.cache.take(`google:start:${meta.ip ?? "unknown"}`, START_LIMIT, id.now());
  if (!limit.allowed) {
    id.metrics.rateLimited("anonymous");
    throw new ApiError("rate_limited", {
      params: { retry_after: String(limit.retryAfter) },
      headers: { "Retry-After": String(limit.retryAfter) },
    });
  }
  return startFlow(id, {
    purpose: "signin",
    intent: b.intent ?? "signin",
    next: isSafeNext(b.next) ? b.next : null,
    userId: null,
    sessionId: null,
  });
}

/** `POST /v1/auth/google/link` (session + step-up, enforced from the spec): a flow bound to this session. */
export async function startLink(id: Identity, principal: { sub: string }, meta: RequestMeta) {
  google(id);
  const userUuid = toUuid(principal.sub, "usr");
  const s = await withTx(id.db, (tx) => currentSessionTx(tx, meta, userUuid));
  const linked = await id.db
    .selectFrom("linked_identities")
    .select("subject")
    .where("user_id", "=", userUuid)
    .where("provider", "=", "google")
    .executeTakeFirst();
  if (linked) throw new ApiError("google_already_linked");
  return startFlow(id, { purpose: "link", intent: "signin", next: null, userId: userUuid, sessionId: s.id });
}

export interface Redirect {
  readonly location: string;
  readonly cookies: readonly string[];
}

/**
 * `GET /v1/auth/google/callback`: always a redirect to a dashboard page. Order: consume the flow (state,
 * cookie binding, expiry, single use) → Google's error → code exchange with the PKCE verifier → ID token
 * verification (JWKS signature, iss, aud, exp, nonce, email_verified) → sign-in / sign-up / link.
 */
export async function callback(
  id: Identity,
  q: { code?: string | undefined; state?: string | undefined; error?: string | undefined },
  meta: RequestMeta,
): Promise<Redirect> {
  const origin = new URL(id.dashboardOrigin).origin;
  const cookies = [clearFlowCookie()];
  const go = (path: string, extra: string[] = []): Redirect => ({
    location: `${origin}${path}`,
    cookies: [...cookies, ...extra],
  });
  const fail = (purpose: FlowPurpose | null, intent: FlowIntent | null, error: GoogleSignInError, why?: string) => {
    if (error !== "cancelled") id.metrics.loginFailure();
    id.log.info({ provider: "google", error, why, purpose }, "google sign-in did not complete");
    return go(errorPath(purpose, intent, error));
  };
  if (!id.google) return fail(null, null, "disabled");

  // 1. the flow, once: unknown state, a foreign browser (no or another cookie), expiry and reuse all fail
  //    the same way; any attempt consumes the flow
  const binding = readCookie(meta.cookie, GOOGLE_FLOW_COOKIE);
  const taken = q.state
    ? await withTx(id.db, async (tx) => {
        const f = await tx
          .selectFrom("oauth_flows")
          .selectAll()
          .where("state_hash", "=", sha256(q.state as string))
          .where("provider", "=", "google")
          .forUpdate()
          .executeTakeFirst();
        if (!f) return null;
        const now = await dbNow(tx);
        const ok = f.used_at === null && f.expires_at > now && matchesHash(binding, f.binding_hash);
        if (f.used_at === null)
          await tx.updateTable("oauth_flows").set({ used_at: now }).where("id", "=", f.id).execute();
        return { f, ok };
      })
    : null;
  if (!taken?.ok) return fail(taken?.f.purpose ?? null, taken?.f.intent ?? null, "state_invalid", "flow");
  const f = taken.f;
  if (q.error) {
    const e =
      q.error === "access_denied"
        ? "cancelled"
        : /unavailable|server_error/.test(q.error)
          ? "unavailable"
          : "token_invalid";
    return fail(f.purpose, f.intent, e, q.error.slice(0, 64));
  }
  if (!q.code) return fail(f.purpose, f.intent, "token_invalid", "no code");

  // 2. code → ID token → verified Google identity
  let identity: { sub: string; email: string };
  try {
    const verifier = id.cipher.decrypt(f.code_verifier_enc, `oauth_flow:${f.id}:verifier`).toString("utf8");
    const idToken = await id.google.exchangeCode(q.code, verifier);
    const check = await id.google.verifyIdToken(idToken, f.nonce_hash);
    if (!check.ok) return fail(f.purpose, f.intent, check.error, check.reason);
    identity = check.identity;
  } catch (e) {
    if (e instanceof GoogleRejected) return fail(f.purpose, f.intent, "token_invalid", e.message);
    id.log.warn({ err: e }, "google unreachable during sign-in");
    return fail(f.purpose, f.intent, "unavailable", "google");
  }

  // 3. apply
  if (f.purpose === "link") {
    const r = await linkVerified(id, f, identity, meta);
    return "error" in r ? fail("link", null, r.error, "link") : go(successPath({ purpose: "link" }));
  }
  let r: Awaited<ReturnType<typeof signInVerified>>;
  try {
    r = await signInVerified(id, identity, meta);
  } catch (e) {
    // a concurrent sign-up of the same address or Google account (unique violation): treat as taken
    if ((e as { code?: string }).code === "23505") return fail("signin", f.intent, "email_exists", "race");
    throw e;
  }
  if ("error" in r) return fail("signin", f.intent, r.error, "signin");
  return go(successPath({ purpose: "signin", created: r.created, next: f.next_path }), [
    cookieFor("dashboard", r.session),
  ]);
}

async function signInVerified(
  id: Identity,
  g: { sub: string; email: string },
  meta: RequestMeta,
): Promise<{ error: GoogleSignInError } | { session: NewSession; created: boolean }> {
  return withTx(id.db, async (tx) => {
    const now = await dbNow(tx);
    const linked = await tx
      .selectFrom("linked_identities")
      .innerJoin("users", "users.id", "linked_identities.user_id")
      .select(["users.id", "users.status"])
      .where("linked_identities.provider", "=", "google")
      .where("linked_identities.subject", "=", g.sub)
      .executeTakeFirst();
    const emailUser = linked
      ? undefined
      : await tx.selectFrom("users").select("id").where("email", "=", g.email).executeTakeFirst();
    const decision = decideSignIn({
      linkedUser: linked ? { status: linked.status } : null,
      emailUserExists: emailUser !== undefined,
    });
    if (decision === "account_disabled") return { error: "account_disabled" as const };
    if (decision === "email_exists") {
      // never linked here: the owner of that user signs in with a passkey and connects Google in Settings
      id.log.warn({ provider: "google" }, "google sign-in for an existing unlinked user refused");
      return { error: "email_exists" as const };
    }
    let userId: string;
    let accountId: string;
    let created = false;
    if (decision === "create") {
      ({ userId, accountId } = await createOwnerUser(id, tx, {
        email: g.email,
        now,
        meta,
        method: "google",
        beforeEvents: (uid) =>
          tx
            .insertInto("linked_identities")
            .values({ provider: "google", subject: g.sub, user_id: uid, email_at_link: g.email })
            .execute(),
      }));
      await audit(id, tx, {
        accountUuid: accountId,
        actor: { type: "user", id: fromUuid("usr", userId), ip: meta.ip },
        action: "user.google_linked",
        target: { type: "user", id: fromUuid("usr", userId) },
        details: { provider: "google", via: "signup" },
      });
      created = true;
    } else {
      userId = (linked as { id: string }).id;
      const m = await landingAccount(tx, userId);
      if (!m) return { error: "no_account" as const };
      accountId = m.account_id;
      await tx.updateTable("users").set({ last_login_at: now }).where("id", "=", userId).execute();
    }
    const session = await createSession(id, tx, {
      kind: "dashboard",
      userId,
      accountId,
      meta,
      steppedUp: false, // ADR-0026: a Google login is never a step-up
      authMethod: "google",
    });
    await audit(id, tx, {
      accountUuid: accountId,
      actor: { type: "user", id: fromUuid("usr", userId), ip: meta.ip },
      action: "login",
      details: { method: "google", new_user: created },
    });
    return { session, created };
  });
}

type FlowRow = { session_id: string | null; user_id: string | null };

async function linkVerified(
  id: Identity,
  f: FlowRow,
  g: { sub: string; email: string },
  meta: RequestMeta,
): Promise<{ error: GoogleSignInError } | { linked: true }> {
  return withTx(id.db, async (tx) => {
    const userId = f.user_id as string;
    const s = await tx
      .selectFrom("sessions")
      .selectAll()
      .where("id", "=", f.session_id as string)
      .forUpdate()
      .executeTakeFirst();
    if (s?.kind !== "dashboard" || s.user_id !== userId || sessionState(s, id.now(), "dashboard") !== "valid")
      return { error: "link_session_invalid" as const };
    const user = await tx.selectFrom("users").select("status").where("id", "=", userId).forUpdate().executeTakeFirst();
    if (user?.status !== "active") return { error: "account_disabled" as const };
    const bySubject = await tx
      .selectFrom("linked_identities")
      .select("user_id")
      .where("provider", "=", "google")
      .where("subject", "=", g.sub)
      .executeTakeFirst();
    const ofUser = await tx
      .selectFrom("linked_identities")
      .select("subject")
      .where("provider", "=", "google")
      .where("user_id", "=", userId)
      .executeTakeFirst();
    const d = decideLink({ userId, subjectUserId: bySubject?.user_id ?? null, userSubject: ofUser?.subject ?? null });
    if (d === "identity_in_use" || d === "already_linked") return { error: d };
    if (d === "already_linked_same") return { linked: true as const };
    await tx
      .insertInto("linked_identities")
      .values({ provider: "google", subject: g.sub, user_id: userId, email_at_link: g.email })
      .execute();
    await signInMethodChanged(id, tx, userId, "google_linked", meta, { via: "settings" });
    return { linked: true as const };
  });
}

/** Audit row in every account of the user + `evt.identity.user.google_(un)linked` (ids only). */
async function signInMethodChanged(
  id: Identity,
  tx: Tx,
  userId: string,
  change: "google_linked" | "google_unlinked",
  meta: RequestMeta,
  details: Record<string, unknown>,
) {
  const v = await tx
    .updateTable("users")
    .set((eb) => ({ sign_in_methods_version: eb("sign_in_methods_version", "+", 1) }))
    .where("id", "=", userId)
    .returning("sign_in_methods_version")
    .executeTakeFirstOrThrow();
  const accounts = await tx.selectFrom("memberships").select("account_id").where("user_id", "=", userId).execute();
  const usr = fromUuid("usr", userId);
  for (const a of accounts)
    await audit(id, tx, {
      accountUuid: a.account_id,
      actor: { type: "user", id: usr, ip: meta.ip },
      action: `user.${change}`,
      target: { type: "user", id: usr },
      details: { provider: "google", ...details },
    });
  await emitEvent(tx, {
    subject: `evt.identity.user.${change}`,
    aggregate: { type: "user_sign_in_methods", id: usr, version: v.sign_in_methods_version },
    accountUuid: null,
    livemode: null,
    object: {
      user_id: usr,
      provider: "google",
      account_ids: accounts.map((a) => fromUuid("acct", a.account_id)),
      occurred_at: (await dbNow(tx)).toISOString(),
    },
  });
}

/** `GET /v1/auth/linked_identities`. */
export async function listLinked(id: Identity, principal: { sub: string }) {
  const rows = await id.db
    .selectFrom("linked_identities")
    .select(["provider", "email_at_link", "created_at"])
    .where("user_id", "=", toUuid(principal.sub, "usr"))
    .orderBy("created_at")
    .execute();
  return {
    object: "list" as const,
    data: rows.map((r) => ({
      object: "linked_identity" as const,
      provider: r.provider,
      email: r.email_at_link,
      created: Math.floor(r.created_at.getTime() / 1000),
    })),
    has_more: false,
    url: "/v1/auth/linked_identities",
  };
}

/**
 * `DELETE /v1/auth/linked_identities/google` (session + step-up from the spec): only while the user keeps a
 * passkey. The user's other Google-created sessions end (the current one stays: it just stepped up).
 */
export async function unlink(id: Identity, principal: { sub: string }, meta: RequestMeta) {
  const userUuid = toUuid(principal.sub, "usr");
  const revoked = await withTx(id.db, async (tx) => {
    const s = await currentSessionTx(tx, meta, userUuid);
    if ((await dashboardPasskeyCount(tx, userUuid)) === 0)
      throw new ApiError("passkey_required", {
        params: { reason: "without a passkey you could not sign in after disconnecting Google." },
      });
    const gone = await tx
      .deleteFrom("linked_identities")
      .where("user_id", "=", userUuid)
      .where("provider", "=", "google")
      .returning("subject")
      .executeTakeFirst();
    if (!gone) throw new ApiError("resource_missing", { params: { object: "linked_identity", id: "google" } });
    const now = await dbNow(tx);
    const ended = await tx
      .updateTable("sessions")
      .set({ revoked_at: now })
      .where("user_id", "=", userUuid)
      .where("auth_method", "=", "google")
      .where("revoked_at", "is", null)
      .where("id", "<>", s.id)
      .returning("token_hash")
      .execute();
    await signInMethodChanged(id, tx, userUuid, "google_unlinked", meta, { sessions_ended: ended.length });
    return ended;
  });
  for (const r of revoked) id.cache.purgeSession(r.token_hash.toString("hex"));
}

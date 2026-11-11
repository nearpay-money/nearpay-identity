/**
 * Continue with Google through the gateway (ADR-0026, lld/identity.md §22) against a local Google stand-in
 * (test/support/google.ts): sign-up, returning sign-in, every ID-token rule, state/cookie/replay, the
 * existing-email refusal, link/unlink with step-up, the first-passkey window and the feature switch.
 */
import { sql } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import { sendMessage } from "@nearpay-internal/spec";
import { DashboardSession } from "@nearpay-money/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sha256 } from "../../src/domain/session/session.js";
import { googleOidc } from "../../src/infra/clients/google.js";
import { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, type MockGoogle, startMockGoogle } from "../support/google.js";
import { ORIGIN, RP_ID, type Stack, startStack } from "../support/stack.js";
import { as, cookieOf, freshIp, signUp, stepUp, type User } from "../support/users.js";
import { softPasskey } from "../support/webauthn.js";

let s: Stack;
let g: MockGoogle;
let client: ReturnType<typeof googleOidc>;

beforeAll(async () => {
  g = await startMockGoogle();
  client = googleOidc({
    clientId: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    redirectUri: `${ORIGIN}/api/auth/google/callback`,
    endpoints: g.endpoints,
  });
  s = await startStack({ google: client });
});
afterAll(async () => {
  await s?.stop();
  await g?.stop();
});

const setCookies = (h: string | string[] | undefined) => (Array.isArray(h) ? h : h ? [h] : []);
const cookieNamed = (h: string | string[] | undefined, name: string) =>
  setCookies(h)
    .find((c) => c.startsWith(`${name}=`))
    ?.split(";")[0];

interface Started {
  url: string;
  cookie: string;
  setCookie: string;
}

async function start(body: Record<string, unknown> = {}, ip = freshIp()): Promise<Started> {
  const r = await s.gateway("POST", "/v1/auth/google/start", { body, ip });
  if (r.status !== 200) throw new Error(`start ${r.status} ${JSON.stringify(r.body)}`);
  const setCookie = setCookies(r.headers["set-cookie"])[0] as string;
  return { url: r.body.authorization_url, cookie: cookieOf(setCookie), setCookie };
}

async function back(query: Record<string, string>, cookie?: string) {
  const qs = new URLSearchParams(query).toString();
  return s.gateway("GET", `/v1/auth/google/callback?${qs}`, cookie ? { cookie } : {});
}

/** Start → approve at Google → callback; returns the redirect and the session cookie (if any). */
async function flow(
  user: { sub: string; email: string; claims?: Record<string, unknown>; rogue?: boolean },
  body: Record<string, unknown> = {},
) {
  const st = await start(body);
  const a = g.authorize(st.url, user);
  const r = await back({ code: a.code, state: a.state, scope: "openid email profile", authuser: "0" }, st.cookie);
  return {
    r,
    location: r.headers.location as string,
    session: cookieNamed(r.headers["set-cookie"], "__Host-np_session"),
    st,
    a,
  };
}

async function sessionOf(cookie: string) {
  const r = await s.gateway("GET", "/v1/auth/session", { cookie });
  if (r.status !== 200) throw new Error(`session ${r.status}`);
  return r.body;
}

/** Sets a session's step-up time in the database and drops authz's cached copy of the session. */
async function setStepUp(cookie: string, at: Date | null) {
  const token = cookie.split("=")[1] as string;
  await s.admin.db.updateTable("sessions").set({ step_up_at: at }).where("token_hash", "=", sha256(token)).execute();
  s.identity.cache.purgeSession(sha256(token).toString("hex"));
}

let n = 0;
const fresh = (tag: string) => {
  n += 1;
  return { sub: `10${Date.now()}${n}`, email: `${tag}${n}@gmail.test` };
};

describe("feature switch", () => {
  it("methods says on; start returns Google's URL with PKCE S256, state, nonce and our redirect URI", async () => {
    const m = await s.gateway("GET", "/v1/auth/methods");
    expect(m.body).toEqual({ object: "auth_methods", passkey: true, google: true });
    const st = await start({ intent: "signup" });
    const p = new URL(st.url).searchParams;
    expect(st.url.startsWith(g.endpoints.authorization)).toBe(true);
    expect(Object.fromEntries(p)).toMatchObject({
      response_type: "code",
      client_id: GOOGLE_CLIENT_ID,
      redirect_uri: `${ORIGIN}/api/auth/google/callback`,
      scope: "openid email profile",
      code_challenge_method: "S256",
    });
    expect(p.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get("nonce")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(st.setCookie).toMatch(
      /^__Host-np_google=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$/,
    );
    // only hashes and the encrypted verifier are stored
    const row = await s.admin.db
      .selectFrom("oauth_flows")
      .selectAll()
      .orderBy("created_at", "desc")
      .executeTakeFirstOrThrow();
    expect(row.state_hash.length).toBe(32);
    expect(row.code_verifier_enc.toString("utf8")).not.toContain(p.get("code_challenge") as string);
  });

  it("off: methods false, start 404, callback redirects with disabled; the dashboard hides the button", async () => {
    const id = s.identity as { google?: unknown };
    const saved = id.google;
    id.google = null;
    try {
      expect((await s.gateway("GET", "/v1/auth/methods")).body.google).toBe(false);
      const r = await s.gateway("POST", "/v1/auth/google/start", { body: {} });
      expect(r.status).toBe(404);
      expect(r.body.error.code).toBe("google_signin_disabled");
      const c = await back({ code: "x", state: "y" });
      expect(c.status).toBe(303);
      expect(c.headers.location).toBe(`${ORIGIN}/signin?google_error=disabled`);
    } finally {
      id.google = saved;
    }
  });
});

describe("sign-up and sign-in", () => {
  it("new verified email → user + account (owner) + linked identity, no magic link, session, onboarding", async () => {
    const u = fresh("new");
    const mailsBefore = s.notify.callsTo(sendMessage).length;
    const { r, location, session } = await flow(u, { intent: "signup" });
    expect(r.status).toBe(303);
    expect(location).toBe(`${ORIGIN}/setup`);
    expect(setCookies(r.headers["set-cookie"])).toContain(
      "__Host-np_google=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
    );
    expect(session).toMatch(/^__Host-np_session=/);
    expect(s.notify.callsTo(sendMessage).length).toBe(mailsBefore);

    const body = await sessionOf(session as string);
    expect(DashboardSession.safeParse(body).success).toBe(true);
    expect(body.user.email).toBe(u.email);
    expect(body.role).toBe("owner");
    expect(body.sign_in).toMatchObject({ method: "google", passkeys: 0, google_linked: true });
    expect(body.sign_in.passkey_setup_until).toBeGreaterThan(Date.now() / 1000 + 500);

    const user = await s.admin.db
      .selectFrom("users")
      .selectAll()
      .where("email", "=", u.email)
      .executeTakeFirstOrThrow();
    expect(user.email_verified_at).not.toBeNull();
    const link = await s.admin.db.selectFrom("linked_identities").selectAll().where("user_id", "=", user.id).execute();
    expect(link).toMatchObject([{ provider: "google", subject: u.sub, email_at_link: u.email }]);
    const acct = toUuid(body.account.id, "acct");
    const out = await sql<{ subject: string }>`select subject from outbox where account_id = ${acct}`.execute(
      s.admin.db,
    );
    expect(out.rows.map((x) => x.subject)).toEqual(["evt.identity.account.created"]);
    const audit = await s.admin.db
      .selectFrom("audit_events")
      .select(["action", "details"])
      .where("account_id", "=", acct)
      .execute();
    expect(audit.map((a) => a.action).sort()).toEqual(["account.created", "login", "user.google_linked"]);
    expect(audit.find((a) => a.action === "login")?.details).toMatchObject({ method: "google", new_user: true });
    // the PKCE verifier reached the token endpoint with the client secret
    const tr = g.tokenRequests.at(-1);
    expect(tr).toMatchObject({ grant_type: "authorization_code", client_secret: GOOGLE_CLIENT_SECRET });
    expect(tr?.code_verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("returning linked user signs in (keyed on sub, not email) and lands on next", async () => {
    const u = fresh("back");
    await flow(u);
    const again = await flow({ sub: u.sub, email: `renamed-${u.email}` }, { next: "/payments?status=succeeded" });
    expect(again.location).toBe(`${ORIGIN}/payments?status=succeeded`);
    const body = await sessionOf(again.session as string);
    expect(body.user.email).toBe(u.email);
    // a same-email Google account with another sub is a different identity: refused, never linked
    const other = await flow({ sub: `${u.sub}9`, email: u.email });
    expect(other.location).toBe(`${ORIGIN}/signin?google_error=email_exists`);
  });

  it("start refuses an unsafe next path", async () => {
    for (const next of ["//evil.test/x", "https://evil.test"]) {
      const r = await s.gateway("POST", "/v1/auth/google/start", { body: { next } });
      expect(r.status, next).toBe(400);
    }
  });

  it("a Google session is not a step-up: sensitive actions need a passkey the user does not have yet", async () => {
    const { session } = await flow(fresh("nostep"));
    const me = await sessionOf(session as string);
    const user = { cookie: session as string, csrf: me.csrf_token };
    const key = await s.gateway("POST", "/v1/api_keys", {
      ...user,
      body: { type: "secret", livemode: false, name: "k" },
    });
    expect(key.status).toBe(401);
    expect(key.body.error.code).toBe("step_up_required");
    const opts = await s.gateway("POST", "/v1/auth/step_up/options", { ...user, body: {} });
    expect(opts.status).toBe(403);
    expect(opts.body.error.code).toBe("passkey_required");
  });

  it("existing email without a Google link is refused (no auto-link) on both pages", async () => {
    const owner = await signUp(s, `passkey${Date.now()}@shop.test`);
    const users = await sql<{ n: string }>`select count(*) as n from users`.execute(s.admin.db);
    const signin = await flow({ sub: `9${Date.now()}`, email: owner.email });
    expect(signin.location).toBe(`${ORIGIN}/signin?google_error=email_exists`);
    expect(signin.session).toBeUndefined();
    const signup = await flow({ sub: `8${Date.now()}`, email: owner.email.toUpperCase() }, { intent: "signup" });
    expect(signup.location).toBe(`${ORIGIN}/signup?google_error=email_exists`);
    expect((await sql<{ n: string }>`select count(*) as n from users`.execute(s.admin.db)).rows).toEqual(users.rows);
    expect(
      await s.admin.db
        .selectFrom("linked_identities")
        .select("subject")
        .where("user_id", "=", toUuid(owner.userId, "usr"))
        .execute(),
    ).toEqual([]);
  });

  it("a disabled linked user is refused", async () => {
    const u = fresh("disabled");
    await flow(u);
    await s.admin.db.updateTable("users").set({ status: "disabled" }).where("email", "=", u.email).execute();
    expect((await flow(u)).location).toBe(`${ORIGIN}/signin?google_error=account_disabled`);
  });
});

describe("flow binding: state, cookie, replay", () => {
  it("unknown state, missing cookie and a foreign cookie fail; any attempt consumes the flow", async () => {
    const st = await start();
    const a = g.authorize(st.url, fresh("bind"));
    expect((await back({ code: a.code, state: "x".repeat(43) }, st.cookie)).headers.location).toBe(
      `${ORIGIN}/signin?google_error=state_invalid`,
    );
    const other = await start();
    expect((await back({ code: a.code, state: a.state }, other.cookie)).headers.location).toBe(
      `${ORIGIN}/signin?google_error=state_invalid`,
    );
    // the attempt with the wrong cookie used the flow up: the right browser cannot complete it any more
    expect((await back({ code: a.code, state: a.state }, st.cookie)).headers.location).toBe(
      `${ORIGIN}/signin?google_error=state_invalid`,
    );
    const st2 = await start({ intent: "signup" });
    const a2 = g.authorize(st2.url, fresh("bind"));
    expect((await back({ code: a2.code, state: a2.state })).headers.location).toBe(
      `${ORIGIN}/signup?google_error=state_invalid`,
    );
  });

  it("a replayed callback (same code and state) fails; a used code in a new flow fails at Google", async () => {
    const u = fresh("replay");
    const first = await flow(u);
    expect(first.location).toBe(`${ORIGIN}/setup`);
    const replay = await back({ code: first.a.code, state: first.a.state }, first.st.cookie);
    expect(replay.headers.location).toBe(`${ORIGIN}/signin?google_error=state_invalid`);
    expect(cookieNamed(replay.headers["set-cookie"], "__Host-np_session")).toBeUndefined();
    const st = await start();
    const state = new URL(st.url).searchParams.get("state") as string;
    const reuse = await back({ code: first.a.code, state }, st.cookie);
    expect(reuse.headers.location).toBe(`${ORIGIN}/signin?google_error=token_invalid`);
  });

  it("an expired flow fails", async () => {
    const st = await start();
    const a = g.authorize(st.url, fresh("late"));
    await s.admin.db
      .updateTable("oauth_flows")
      .set({ expires_at: new Date(Date.now() - 1000) })
      .where("used_at", "is", null)
      .execute();
    expect((await back({ code: a.code, state: a.state }, st.cookie)).headers.location).toBe(
      `${ORIGIN}/signin?google_error=state_invalid`,
    );
  });

  it("the user declining at Google, and Google unreachable", async () => {
    const st = await start();
    const state = new URL(st.url).searchParams.get("state") as string;
    expect((await back({ error: "access_denied", state }, st.cookie)).headers.location).toBe(
      `${ORIGIN}/signin?google_error=cancelled`,
    );
    g.failToken = 503;
    try {
      expect((await flow(fresh("down"))).location).toBe(`${ORIGIN}/signin?google_error=unavailable`);
    } finally {
      g.failToken = null;
    }
  });
});

describe("ID token verification", () => {
  const now = () => Math.floor(Date.now() / 1000);
  it.each([
    ["wrong nonce", { nonce: "not-the-flow-nonce" }, "token_invalid"],
    ["wrong audience", { aud: "someone-else.apps.googleusercontent.com" }, "token_invalid"],
    ["wrong issuer", { iss: "https://accounts.evil.test" }, "token_invalid"],
    ["expired", { iat: now() - 7200, exp: now() - 3600 }, "token_invalid"],
    ["azp of another client", { azp: "other.apps.googleusercontent.com" }, "token_invalid"],
    ["email not verified", { email_verified: false }, "email_unverified"],
    ["email_verified as a string", { email_verified: "true" }, "email_unverified"],
  ])("%s → %s", async (_name, claims, error) => {
    const u = fresh("tok");
    const r = await flow({ ...u, claims });
    expect(r.location).toBe(`${ORIGIN}/signin?google_error=${error}`);
    expect(r.session).toBeUndefined();
    expect(await s.admin.db.selectFrom("users").select("id").where("email", "=", u.email).execute()).toEqual([]);
  });

  it("legacy issuer form accounts.google.com is accepted", async () => {
    const r = await flow({ ...fresh("legacy"), claims: { iss: "accounts.google.com" } });
    expect(r.location).toBe(`${ORIGIN}/setup`);
  });

  it("a signature by a key outside Google's JWKS is refused", async () => {
    const r = await flow({ ...fresh("rogue"), rogue: true });
    expect(r.location).toBe(`${ORIGIN}/signin?google_error=token_invalid`);
  });
});

describe("first passkey for a Google-only user", () => {
  it("within 10 minutes of the Google sign-in; afterwards continue with Google again", async () => {
    const { session } = await flow(fresh("pk"));
    const me = await sessionOf(session as string);
    const u = { cookie: session as string, csrf: me.csrf_token };
    const opts = await s.gateway("POST", "/v1/auth/passkeys/registration/options", { ...u, body: {} });
    expect(opts.status).toBe(200);
    const passkey = softPasskey(RP_ID, ORIGIN);
    const reg = await s.gateway("POST", "/v1/auth/passkeys/registration/verify", {
      ...u,
      body: { credential: passkey.create(opts.body), passkey_name: "Phone" },
    });
    expect(reg.status).toBe(200);
    expect(reg.body.sign_in).toMatchObject({ method: "google", passkeys: 1, passkey_setup_until: null });
    // the registration itself is no step-up; a step-up with the new passkey works
    const user: User = {
      email: me.user.email,
      passkey,
      cookie: u.cookie,
      csrf: u.csrf,
      userId: me.user.id,
      accountId: me.account.id,
    };
    await stepUp(s, user);
    const key = await s.gateway(
      "POST",
      "/v1/api_keys",
      as(user, "test", { type: "secret", livemode: false, name: "k" }),
    );
    expect(key.status).toBe(201);
  });

  it("a stale Google session gets reauthentication_required", async () => {
    const { session } = await flow(fresh("stale"));
    const me = await sessionOf(session as string);
    await s.admin.db
      .updateTable("sessions")
      .set({ created_at: new Date(Date.now() - 11 * 60_000) })
      .where("user_id", "=", toUuid(me.user.id, "usr"))
      .execute();
    expect((await sessionOf(session as string)).sign_in.passkey_setup_until).toBeNull();
    const r = await s.gateway("POST", "/v1/auth/passkeys/registration/options", {
      cookie: session as string,
      csrf: me.csrf_token,
      body: {},
    });
    expect(r.status).toBe(401);
    expect(r.body.error.code).toBe("reauthentication_required");
  });

  it("a passkey user adds another passkey only after a fresh step-up", async () => {
    const owner = await signUp(s, `pk2-${Date.now()}@shop.test`);
    await setStepUp(owner.cookie, null);
    const r = await s.gateway("POST", "/v1/auth/passkeys/registration/options", as(owner, "test", {}));
    expect(r.status).toBe(401);
    expect(r.body.error.code).toBe("step_up_required");
    await stepUp(s, owner);
    expect((await s.gateway("POST", "/v1/auth/passkeys/registration/options", as(owner, "test", {}))).status).toBe(200);
  });
});

describe("connect and disconnect Google in Settings", () => {
  async function linkFlow(owner: User, google: { sub: string; email: string }) {
    const r = await s.gateway("POST", "/v1/auth/google/link", as(owner, "test", {}));
    if (r.status !== 200) return { status: r.status, body: r.body };
    const cookie = cookieOf(r.headers["set-cookie"]);
    const a = g.authorize(r.body.authorization_url, google);
    expect(a.params.get("prompt")).toBe("select_account");
    // Google's redirect is a cross-site navigation: the SameSite=Strict session cookie is not sent
    const cb = await back({ code: a.code, state: a.state }, cookie);
    return { status: cb.status, location: cb.headers.location as string };
  }

  it("needs a step-up, links, audits, emits; then Continue with Google signs that user in", async () => {
    const owner = await signUp(s, `link-${Date.now()}@shop.test`);
    await setStepUp(owner.cookie, null);
    const noStep = await s.gateway("POST", "/v1/auth/google/link", as(owner, "test", {}));
    expect(noStep.status).toBe(401);
    expect(noStep.body.error.code).toBe("step_up_required");
    await stepUp(s, owner);
    const google = { sub: `7${Date.now()}`, email: `other-address-${Date.now()}@gmail.test` };
    const r = await linkFlow(owner, google);
    expect(r.location).toBe(`${ORIGIN}/settings/account?google=linked`);
    const list = await s.gateway("GET", "/v1/auth/linked_identities", as(owner));
    expect(list.body.data).toMatchObject([{ object: "linked_identity", provider: "google", email: google.email }]);
    const acct = toUuid(owner.accountId, "acct");
    const audit = await s.admin.db
      .selectFrom("audit_events")
      .select(["action", "details"])
      .where("account_id", "=", acct)
      .where("action", "=", "user.google_linked")
      .execute();
    expect(audit).toMatchObject([{ details: { provider: "google", via: "settings" } }]);
    const ev = await sql<{ subject: string; payload: { data: { object: Record<string, unknown> } } }>`
      select subject, payload from outbox where subject = 'evt.identity.user.google_linked' order by created_at desc limit 1`.execute(
      s.admin.db,
    );
    expect(ev.rows[0]?.payload.data.object).toMatchObject({
      user_id: owner.userId,
      provider: "google",
      account_ids: [owner.accountId],
    });
    expect(JSON.stringify(ev.rows[0]?.payload)).not.toContain(google.email);

    const signin = await flow(google);
    expect(signin.location).toBe(`${ORIGIN}/`);
    expect((await sessionOf(signin.session as string)).user.id).toBe(owner.userId);

    // already linked → 409 at start
    await stepUp(s, owner);
    const again = await s.gateway("POST", "/v1/auth/google/link", as(owner, "test", {}));
    expect(again.status).toBe(409);
    expect(again.body.error.code).toBe("google_already_linked");
  });

  it("a Google account linked to another user is refused; a link whose session ended is refused", async () => {
    const taken = fresh("taken");
    await flow(taken);
    const owner = await signUp(s, `link2-${Date.now()}@shop.test`);
    expect((await linkFlow(owner, taken)).location).toBe(`${ORIGIN}/settings/account?google_error=identity_in_use`);

    const r = await s.gateway("POST", "/v1/auth/google/link", as(owner, "test", {}));
    const cookie = cookieOf(r.headers["set-cookie"]);
    const a = g.authorize(r.body.authorization_url, fresh("ended"));
    expect((await s.gateway("POST", "/v1/auth/logout", as(owner, "test", {}))).status).toBe(204);
    expect((await back({ code: a.code, state: a.state }, cookie)).headers.location).toBe(
      `${ORIGIN}/settings/account?google_error=link_session_invalid`,
    );
  });

  it("disconnect needs a step-up and a passkey, ends other Google sessions, audits and emits", async () => {
    const owner = await signUp(s, `unlink-${Date.now()}@shop.test`);
    const google = fresh("unlink");
    expect((await linkFlow(owner, google)).location).toBe(`${ORIGIN}/settings/account?google=linked`);
    const googleSession = (await flow(google)).session as string;
    expect((await s.gateway("GET", "/v1/auth/session", { cookie: googleSession })).status).toBe(200);

    await setStepUp(owner.cookie, null);
    const noStep = await s.gateway("DELETE", "/v1/auth/linked_identities/google", as(owner));
    expect(noStep.body.error.code).toBe("step_up_required");
    await stepUp(s, owner);
    const del = await s.gateway("DELETE", "/v1/auth/linked_identities/google", as(owner));
    expect(del.status).toBe(204);
    expect((await s.gateway("GET", "/v1/auth/linked_identities", as(owner))).body.data).toEqual([]);
    expect((await s.gateway("GET", "/v1/auth/session", { cookie: googleSession })).status).toBe(401);
    expect((await s.gateway("GET", "/v1/auth/session", { cookie: owner.cookie })).status).toBe(200);
    const audit = await s.admin.db
      .selectFrom("audit_events")
      .select("details")
      .where("account_id", "=", toUuid(owner.accountId, "acct"))
      .where("action", "=", "user.google_unlinked")
      .execute();
    expect(audit).toMatchObject([{ details: { provider: "google", sessions_ended: 1 } }]);
    const ev = await sql<{ n: string }>`
      select count(*) as n from outbox where subject = 'evt.identity.user.google_unlinked'`.execute(s.admin.db);
    expect(Number(ev.rows[0]?.n)).toBeGreaterThan(0);
    // the Google account no longer signs in as this user (its own address has no user: a new account)
    const after = await flow(google);
    expect(after.location).toBe(`${ORIGIN}/setup`);
    expect((await sessionOf(after.session as string)).user.id).not.toBe(owner.userId);
    // nothing linked any more
    await stepUp(s, owner);
    expect((await s.gateway("DELETE", "/v1/auth/linked_identities/google", as(owner))).status).toBe(404);
  });

  it("a Google-only user cannot disconnect (no passkey to sign in with afterwards)", async () => {
    const { session } = await flow(fresh("only"));
    const me = await sessionOf(session as string);
    // even a (forged) fresh step-up does not help: the passkey rule is checked on its own
    await setStepUp(session as string, new Date());
    const del = await s.gateway("DELETE", "/v1/auth/linked_identities/google", {
      cookie: session as string,
      csrf: me.csrf_token,
    });
    expect(del.status).toBe(403);
    expect(del.body.error.code).toBe("passkey_required");
  });
});

describe("rate limit", () => {
  it("starts are limited per client IP", async () => {
    const ip = freshIp().replace("198.51.100.", "203.0.113.");
    let last = { status: 0, headers: {} as Record<string, unknown> };
    for (let i = 0; i < 31; i++) last = await s.gateway("POST", "/v1/auth/google/start", { body: {}, ip });
    expect(last.status).toBe(429);
    expect(last.headers["retry-after"]).toBeDefined();
  });
});

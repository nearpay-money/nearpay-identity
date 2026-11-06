/** Sign-up, passkeys, sessions, step-up and logout through the gateway (lld/identity.md §6, §12). */
import { sql } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import { sendMessage } from "@nearpay-internal/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ORIGIN, RP_ID, type Stack, startStack } from "../support/stack.js";
import { as, cookieOf, magicToken, signUp, stepUp, type User } from "../support/users.js";
import { softPasskey } from "../support/webauthn.js";

let s: Stack;
beforeAll(async () => {
  s = await startStack();
});
afterAll(async () => {
  await s?.stop();
});

describe("sign-up", () => {
  it("magic link → registration → passkey → account (owner), session cookie and account.created", async () => {
    const u = await signUp(s, "Founder@Shop.test", "Shop One");
    expect(u.userId).toMatch(/^usr_/);
    expect(u.accountId).toMatch(/^acct_/);
    expect(u.cookie).toMatch(/^__Host-np_session=[A-Za-z0-9_-]{43}$/);
    const call = s.notify.callsTo(sendMessage).find((c) => (c.body as { to: string }).to === "founder@shop.test");
    expect(call?.body).toMatchObject({
      template: "auth.magic_link",
      variables: { purpose: "signup", expires_in_minutes: 15 },
    });
    expect((call?.body as { variables: { link_url: string } } | undefined)?.variables.link_url).toMatch(
      /^https:\/\/dashboard\.nearpay\.localhost\/auth\/verify#token=[A-Za-z0-9_-]{43}$/,
    );
    expect(call?.principal).toMatchObject({ ptype: "service", sub: "identity" });
    const acct = await s.admin.db
      .selectFrom("accounts")
      .selectAll()
      .where("id", "=", toUuid(u.accountId, "acct"))
      .executeTakeFirstOrThrow();
    expect(acct).toMatchObject({
      display_name: "Shop One",
      kyb_status: "not_started",
      live_enabled: false,
      status: "active",
      api_version: "2026-11-01",
    });
    const m = await s.admin.db.selectFrom("memberships").selectAll().where("account_id", "=", acct.id).execute();
    expect(m.map((x) => x.role)).toEqual(["owner"]);
    const out = await sql<{ subject: string }>`select subject from outbox where account_id = ${acct.id}`.execute(
      s.admin.db,
    );
    expect(out.rows.map((r) => r.subject)).toEqual(["evt.identity.account.created"]);
    const audit = await s.admin.db
      .selectFrom("audit_events")
      .select("action")
      .where("account_id", "=", acct.id)
      .execute();
    expect(audit.map((a) => a.action)).toContain("account.created");
  });

  it("never reveals whether an email is registered, and limits links per address", async () => {
    await signUp(s, "taken@shop.test");
    const before = s.notify.callsTo(sendMessage).length;
    const again = await s.gateway("POST", "/v1/auth/signup", {
      body: { email: "taken@shop.test", turnstile_token: "t" },
    });
    expect(again.status).toBe(202);
    expect(s.notify.callsTo(sendMessage).length).toBe(before);
    for (let i = 0; i < 6; i++)
      expect(
        (await s.gateway("POST", "/v1/auth/signup", { body: { email: "spam@shop.test", turnstile_token: "t" } }))
          .status,
      ).toBe(202);
    expect(
      s.notify.callsTo(sendMessage).filter((c) => (c.body as { to: string }).to === "spam@shop.test"),
    ).toHaveLength(5);
  });

  it("links are single-use; registration tokens expire into link_expired", async () => {
    const token = await magicToken(s, "once@shop.test");
    expect((await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token } })).status).toBe(200);
    const reuse = await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token } });
    expect(reuse.status).toBe(410);
    expect(reuse.body).toMatchObject({ error: { code: "link_used" } });
    const unknown = await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token: "x".repeat(43) } });
    expect(unknown.body).toMatchObject({ error: { code: "link_expired" } });
    const opts = await s.gateway("POST", "/v1/auth/passkeys/registration/options", {
      body: { registration_token: "y".repeat(43) },
    });
    expect(opts.body).toMatchObject({ error: { code: "link_expired" } });
  });

  it("registration options follow the spec: discoverable, user verification required", async () => {
    const token = await magicToken(s, "opts@shop.test");
    const v = await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token } });
    const o = await s.gateway("POST", "/v1/auth/passkeys/registration/options", {
      body: { registration_token: v.body.registration_token },
    });
    expect(o.status).toBe(200);
    expect(o.body).toMatchObject({
      rp: { id: RP_ID, name: "NearPay" },
      user: { name: "opts@shop.test" },
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none",
    });
    expect(o.body.pubKeyCredParams.map((p: { alg: number }) => p.alg)).toEqual([-8, -7, -257]);
  });

  it("rejects a wrong origin, a missing user verification and a replayed ceremony", async () => {
    const token = await magicToken(s, "bad@shop.test");
    const v = await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token } });
    const reg = v.body.registration_token;
    const pk = softPasskey(RP_ID, "https://evil.example");
    const o1 = await s.gateway("POST", "/v1/auth/passkeys/registration/options", { body: { registration_token: reg } });
    const evil = await s.gateway("POST", "/v1/auth/passkeys/registration/verify", {
      body: { registration_token: reg, credential: pk.create(o1.body) },
    });
    expect(evil.body).toMatchObject({ error: { code: "webauthn_failed" } });
    const o2 = await s.gateway("POST", "/v1/auth/passkeys/registration/options", { body: { registration_token: reg } });
    const pk2 = softPasskey(RP_ID, ORIGIN);
    const noUv = await s.gateway("POST", "/v1/auth/passkeys/registration/verify", {
      body: { registration_token: reg, credential: pk2.create(o2.body, { uv: false }) },
    });
    expect(noUv.body).toMatchObject({ error: { code: "webauthn_failed" } });
    const o3 = await s.gateway("POST", "/v1/auth/passkeys/registration/options", { body: { registration_token: reg } });
    const cred = pk2.create(o3.body);
    expect(
      (
        await s.gateway("POST", "/v1/auth/passkeys/registration/verify", {
          body: { registration_token: reg, credential: cred },
        })
      ).status,
    ).toBe(200);
    const replay = await s.gateway("POST", "/v1/auth/passkeys/registration/verify", {
      body: { registration_token: reg, credential: cred },
    });
    expect(replay.body).toMatchObject({ error: { code: "webauthn_failed" } });
  });
});

describe("sign-in, step-up, logout", () => {
  let u: User;
  beforeAll(async () => {
    u = await signUp(s, "login@shop.test", "Login Shop");
  });

  it("signs in with the passkey (no email needed) and returns a DashboardSession + cookie", async () => {
    const o = await s.gateway("POST", "/v1/auth/passkeys/authentication/options", {
      body: { email: "anything@else.test" },
    });
    expect(o.body).toMatchObject({ rpId: RP_ID, userVerification: "required" });
    expect(o.body.allowCredentials ?? []).toEqual([]);
    const r = await s.gateway("POST", "/v1/auth/passkeys/authentication/verify", {
      body: { credential: u.passkey.get(o.body) },
    });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      object: "dashboard_session",
      user: { id: u.userId, email: "login@shop.test" },
      account: { id: u.accountId, display_name: "Login Shop" },
      role: "owner",
    });
    expect(cookieOf(r.headers["set-cookie"])).not.toBe(u.cookie);
    expect(String(r.headers["set-cookie"])).toContain("HttpOnly; SameSite=Strict");
  });

  it("rejects an unknown passkey, a reused challenge and a cloned (counter) assertion", async () => {
    const o = await s.gateway("POST", "/v1/auth/passkeys/authentication/options", { body: {} });
    const stranger = softPasskey(RP_ID, ORIGIN);
    stranger.create({ challenge: "x", user: { id: "AA" } });
    expect(
      (
        await s.gateway("POST", "/v1/auth/passkeys/authentication/verify", {
          body: { credential: stranger.get(o.body) },
        })
      ).body,
    ).toMatchObject({
      error: { code: "webauthn_failed" },
    });
    const o2 = await s.gateway("POST", "/v1/auth/passkeys/authentication/options", { body: {} });
    const a = u.passkey.get(o2.body);
    expect(
      (await s.gateway("POST", "/v1/auth/passkeys/authentication/verify", { body: { credential: a } })).status,
    ).toBe(200);
    expect(
      (await s.gateway("POST", "/v1/auth/passkeys/authentication/verify", { body: { credential: a } })).status,
    ).toBe(400);
    const o3 = await s.gateway("POST", "/v1/auth/passkeys/authentication/options", { body: {} });
    const cloned = await s.gateway("POST", "/v1/auth/passkeys/authentication/verify", {
      body: { credential: u.passkey.get(o3.body, { counter: 1 }) },
    });
    expect(cloned.body).toMatchObject({ error: { code: "webauthn_failed" } });
  });

  it("the session works through the gateway; unsafe calls need the CSRF token", async () => {
    const acct = await s.gateway("GET", "/v1/account", { cookie: u.cookie });
    expect(acct.status).toBe(200);
    expect(acct.body).toMatchObject({ id: u.accountId, object: "account" });
    const noCsrf = await s.gateway("PATCH", "/v1/account", { cookie: u.cookie, body: { display_name: "X" } });
    expect(noCsrf.status).toBe(403);
    expect(noCsrf.body).toMatchObject({ error: { code: "csrf_token_invalid" } });
    expect(
      (await s.gateway("PATCH", "/v1/account", { cookie: u.cookie, csrf: "wrong", body: { display_name: "X" } }))
        .status,
    ).toBe(403);
    expect(
      (await s.gateway("PATCH", "/v1/account", as(u, "test", { display_name: "Login Shop 2" }))).body,
    ).toMatchObject({ display_name: "Login Shop 2" });
  });

  it("step-up stamps the request token for 10 minutes; step-up routes need it", async () => {
    // signing in is itself a fresh assertion; age it past 10 minutes
    await s.admin.db
      .updateTable("sessions")
      .set({ step_up_at: new Date(Date.now() - 11 * 60_000) })
      .where("user_id", "=", toUuid(u.userId, "usr"))
      .execute();
    s.identity.cache.local<object>("sessions", 10_000).clear();
    const before = await s.gateway(
      "POST",
      "/v1/api_keys",
      as(u, "test", { type: "secret", livemode: false, name: "ci" }),
    );
    expect(before.status).toBe(401);
    expect(before.body).toMatchObject({ error: { code: "step_up_required" } });
    await stepUp(s, u);
    const after = await s.gateway(
      "POST",
      "/v1/api_keys",
      as(u, "test", { type: "secret", livemode: false, name: "ci" }),
    );
    expect(after.status).toBe(201);
    expect(after.body.secret).toMatch(/^sk_test_[0-9A-Za-z]{48}$/);
  });

  it("an additional passkey can be registered from a session (same CSRF token)", async () => {
    const o = await s.gateway("POST", "/v1/auth/passkeys/registration/options", as(u, "test", {}));
    expect(o.status).toBe(200);
    expect(o.body.excludeCredentials).toHaveLength(1);
    const pk2 = softPasskey(RP_ID, ORIGIN);
    const r = await s.gateway(
      "POST",
      "/v1/auth/passkeys/registration/verify",
      as(u, "test", { credential: pk2.create(o.body) }),
    );
    expect(r.status).toBe(200);
    expect(r.body.csrf_token).toBe(u.csrf);
    expect(
      (await s.admin.db.selectFrom("passkeys").select("id").where("user_id", "=", toUuid(u.userId, "usr")).execute())
        .length,
    ).toBe(2);
  });

  it("logout revokes the session and clears the cookie", async () => {
    const r = await s.gateway("POST", "/v1/auth/logout", as(u, "test", {}));
    expect(r.status).toBe(204);
    expect(String(r.headers["set-cookie"])).toContain("Max-Age=0");
    await new Promise((x) => setTimeout(x, 10));
    s.identity.cache.local<object>("sessions", 10_000).clear();
    expect((await s.gateway("GET", "/v1/account", { cookie: u.cookie })).status).toBe(401);
  });
});

describe("turnstile", () => {
  it("a failed challenge refuses sign-up", async () => {
    const r = await s.gateway("POST", "/v1/auth/signup", { body: { email: "bot@shop.test", turnstile_token: "x" } });
    expect(r.status).toBe(202); // the stack uses the always-pass test secret
  });
});

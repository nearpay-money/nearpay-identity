/** Gateway authorisation, API keys and the internal routes (lld/identity.md §6, §8.1). */
import { toUuid, uuidv7 } from "@nearpay-internal/ids";
import { getSettlementContext } from "@nearpay-internal/spec";
import { mintServiceToken } from "@nearpay-internal/testing";
import { createLocalJWKSet, jwtVerify } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { newSecret, sha256 } from "../../src/domain/session/session.js";
import { PAYMENTS_CLIENT_SECRET, type Stack, startStack } from "../support/stack.js";
import { as, signUp, type User } from "../support/users.js";

let s: Stack;
let u: User;
beforeAll(async () => {
  s = await startStack();
  u = await signUp(s, "keys@shop.test", "Keys Shop");
});
afterAll(async () => {
  await s?.stop();
});

const claimsOf = (token: string) => JSON.parse(Buffer.from(token.split(".")[1] as string, "base64url").toString());
const authz = (h: Record<string, string>) => s.direct("GET", "/internal/authz", { headers: h });
const fwd = (method: string, uri: string, extra: Record<string, string> = {}) => ({
  "x-forwarded-method": method,
  "x-forwarded-uri": uri,
  "x-forwarded-host": "api.nearpay.localhost",
  "x-forwarded-for": `192.0.2.${Math.floor(Math.random() * 250) + 1}`,
  ...extra,
});
const newKey = async (body: Record<string, unknown>) => {
  const r = await s.gateway(
    "POST",
    "/v1/api_keys",
    as(u, "test", { type: "secret", livemode: false, name: "k", ...body }),
  );
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  return r.body as { id: string; secret: string };
};

describe("request tokens", () => {
  it("a session mints {sub, acct, lm from NearPay-Mode, ptype session, role, step_up_until, rid}", async () => {
    const r = await authz(
      fwd("GET", "/v1/account", {
        cookie: u.cookie,
        "nearpay-mode": "live",
        "x-request-id": "req_01m6pq018ne9tv0kqymb9je8pv",
      }),
    );
    expect(r.status).toBe(200);
    expect(r.headers["x-request-id"]).toBe("req_01m6pq018ne9tv0kqymb9je8pv");
    const c = claimsOf(r.headers["x-nearpay-token"] as string);
    expect(c).toMatchObject({
      sub: u.userId,
      acct: u.accountId,
      lm: true,
      ptype: "session",
      role: "owner",
      scp: [],
      rid: "req_01m6pq018ne9tv0kqymb9je8pv",
      iss: "nearpay-identity",
      aud: "nearpay",
    });
    expect(c.step_up_until).toBeGreaterThan(Date.now() / 1000);
    expect(c.exp - c.iat).toBe(60);
    const test = claimsOf(
      (await authz(fwd("GET", "/v1/account", { cookie: u.cookie, "x-request-id": "bogus" }))).headers[
        "x-nearpay-token"
      ] as string,
    );
    expect(test.lm).toBe(false);
    expect(test.rid).toMatch(/^req_/);
    expect(test.rid).not.toBe("bogus");
  });

  it("tokens verify against the published JWKS", async () => {
    const jwks = (await s.direct("GET", "/internal/jwks")).body;
    expect(jwks.keys).toHaveLength(2);
    expect(jwks.keys[0]).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig" });
    const token = (await authz(fwd("GET", "/v1/account", { cookie: u.cookie }))).headers["x-nearpay-token"] as string;
    await expect(
      jwtVerify(token, createLocalJWKSet(jwks), { issuer: "nearpay-identity", audience: "nearpay" }),
    ).resolves.toBeDefined();
  });

  it("open routes get an anonymous token; everything else needs a credential", async () => {
    const anon = await authz(fwd("POST", "/v1/auth/signup"));
    expect(claimsOf(anon.headers["x-nearpay-token"] as string)).toMatchObject({
      sub: "anonymous",
      ptype: "anonymous",
      scp: [],
    });
    const cs = await authz(fwd("GET", "/v1/checkout/sessions/cs_123/public"));
    expect(cs.status).toBe(200);
    const none = await authz(fwd("GET", "/v1/account"));
    expect(none.status).toBe(401);
    expect(none.body).toMatchObject({ error: { code: "authentication_required" } });
    expect((await authz(fwd("GET", "/v1/nope"))).status).toBe(401);
    // a garbage cookie on an open route is just anonymous
    expect(
      (await authz(fwd("POST", "/v1/auth/signup", { cookie: "__Host-np_session=garbagegarbagegarbage" }))).status,
    ).toBe(200);
  });

  it("rate-limits anonymous clients per IP (10 rps, burst 20) with Retry-After", async () => {
    const h = fwd("POST", "/v1/auth/passkeys/authentication/options", { "x-forwarded-for": "203.0.113.200" });
    const codes: number[] = [];
    for (let i = 0; i < 25; i++) codes.push((await authz(h)).status);
    expect(codes.filter((c) => c === 200).length).toBeGreaterThanOrEqual(20);
    expect(codes.filter((c) => c === 200).length).toBeLessThan(25);
    const limited = await authz(h);
    expect(limited.status).toBe(429);
    expect(limited.headers["retry-after"]).toBe("1");
    expect(limited.body).toMatchObject({
      error: { code: "rate_limited", message: "Too many requests; retry after 1 seconds." },
    });
    expect(
      (await authz(fwd("POST", "/v1/auth/passkeys/authentication/options", { "x-forwarded-for": "203.0.113.201" })))
        .status,
    ).toBe(200);
  });
});

describe("API keys", () => {
  it("a secret key authenticates as {sub key_, acct, lm, ptype secret_key}", async () => {
    const k = await newKey({});
    const r = await authz(fwd("GET", "/v1/settlement_destinations", { authorization: `Bearer ${k.secret}` }));
    expect(claimsOf(r.headers["x-nearpay-token"] as string)).toMatchObject({
      sub: k.id,
      acct: u.accountId,
      lm: false,
      ptype: "secret_key",
      scp: [],
    });
    const list = await s.gateway("GET", "/v1/settlement_destinations", { bearer: k.secret });
    expect(list.status).toBe(200);
    // dashboard-only routes refuse keys (route auth from the spec)
    const acct = await s.gateway("GET", "/v1/account", { bearer: k.secret });
    expect(acct.status).toBe(403);
    expect((await s.gateway("POST", "/v1/settlement_destinations", { bearer: k.secret, body: {} })).status).toBe(403);
  });

  it("lists keys of the current mode without secrets", async () => {
    await newKey({ name: "live one", livemode: true });
    const test = await s.gateway("GET", "/v1/api_keys", { cookie: u.cookie });
    expect(
      test.body.data.every((k: { livemode: boolean; secret?: string }) => !k.livemode && k.secret === undefined),
    ).toBe(true);
    const live = await s.gateway("GET", "/v1/api_keys?limit=1", { cookie: u.cookie, mode: "live" });
    expect(live.body.data).toHaveLength(1);
    expect(live.body.data[0]).toMatchObject({ livemode: true, display_prefix: "sk_live_", name: "live one" });
  });

  it("revocation takes effect at once and is idempotent", async () => {
    const k = await newKey({});
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: k.secret })).status).toBe(200);
    expect((await s.gateway("DELETE", `/v1/api_keys/${k.id}`, as(u))).status).toBe(204);
    expect((await s.gateway("DELETE", `/v1/api_keys/${k.id}`, as(u))).status).toBe(204);
    const r = await s.gateway("GET", "/v1/settlement_destinations", { bearer: k.secret });
    expect(r.status).toBe(401);
    expect(r.body).toMatchObject({ error: { code: "invalid_api_key" } });
  });

  it("rolling: the new key is shown once; the old one lives for the grace period", async () => {
    const k = await newKey({});
    const graced = await s.gateway("POST", `/v1/api_keys/${k.id}/roll`, as(u, "test", { expire_old_in_seconds: 3600 }));
    expect(graced.status).toBe(201);
    expect(graced.body.secret).toMatch(/^sk_test_/);
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: k.secret })).status).toBe(200);
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: graced.body.secret })).status).toBe(200);
    expect((await s.gateway("POST", `/v1/api_keys/${k.id}/roll`, as(u, "test", {}))).status).toBe(409);
    const immediate = await s.gateway(
      "POST",
      `/v1/api_keys/${graced.body.id}/roll`,
      as(u, "test", { expire_old_in_seconds: 0 }),
    );
    expect(immediate.status).toBe(201);
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: graced.body.secret })).status).toBe(401);
  });

  it("expired keys, IP allowlists, publishable keys and malformed bearers", async () => {
    const k = await newKey({ ip_allowlist: ["10.0.0.0/8"] });
    expect(
      (await s.gateway("GET", "/v1/settlement_destinations", { bearer: k.secret, ip: "192.0.2.9" })).body,
    ).toMatchObject({ error: { code: "ip_not_allowed" } });
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: k.secret, ip: "10.3.4.5" })).status).toBe(
      200,
    );
    const exp = await newKey({ expires_at: Math.floor(Date.now() / 1000) + 60 });
    await s.admin.db
      .updateTable("api_keys")
      .set({ expires_at: new Date(Date.now() - 1000) })
      .where("id", "=", toUuid(exp.id, "key"))
      .execute();
    await s.identity.cache.purgeKey(sha256(exp.secret).toString("hex"));
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: exp.secret })).status).toBe(401);
    const pk = await newKey({ type: "publishable" });
    expect(pk.secret).toMatch(/^pk_test_/);
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: pk.secret })).body).toMatchObject({
      error: { code: "permission_denied" },
    });
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: "sk_test_nope" })).status).toBe(401);
    expect(
      (
        await s.gateway(
          "POST",
          "/v1/api_keys",
          as(u, "test", { type: "secret", livemode: false, name: "x", expires_at: 1 }),
        )
      ).status,
    ).toBe(400);
  });
});

describe("account state", () => {
  it("a suspended account cannot make live writes; live money routes need live_enabled", async () => {
    const live = await newKey({ livemode: true });
    const create = fwd("POST", "/v1/checkout/sessions", { authorization: `Bearer ${live.secret}` });
    const notLive = await authz(create);
    expect(notLive.status).toBe(403);
    expect(notLive.body).toMatchObject({
      error: { code: "account_not_live", message: "Live mode is not enabled for this account (kyb)." },
    });
    const test = await newKey({});
    expect((await authz(fwd("POST", "/v1/checkout/sessions", { authorization: `Bearer ${test.secret}` }))).status).toBe(
      200,
    );
    await s.admin.db
      .updateTable("accounts")
      .set({ status: "suspended" })
      .where("id", "=", toUuid(u.accountId, "acct"))
      .execute();
    s.identity.cache.local<object>("accounts", 10_000).clear();
    expect((await authz(create)).body).toMatchObject({ error: { code: "account_suspended" } });
    expect(
      (await authz(fwd("GET", "/v1/settlement_destinations", { authorization: `Bearer ${live.secret}` }))).status,
    ).toBe(200);
    expect((await authz(fwd("POST", "/v1/checkout/sessions", { authorization: `Bearer ${test.secret}` }))).status).toBe(
      200,
    );
    await s.admin.db
      .updateTable("accounts")
      .set({ status: "active" })
      .where("id", "=", toUuid(u.accountId, "acct"))
      .execute();
    s.identity.cache.local<object>("accounts", 10_000).clear();
  });
});

describe("console sessions (ops principals)", () => {
  it("an operator's console session mints ptype ops with the ops scopes; revoked operators are refused", async () => {
    const userUuid = toUuid(u.userId, "usr");
    await s.admin.db.insertInto("ops_operators").values({ user_id: userUuid, role: "ops" }).execute();
    const token = newSecret();
    const now = new Date();
    await s.admin.db
      .insertInto("sessions")
      .values({
        id: uuidv7(),
        kind: "ops",
        user_id: userUuid,
        account_id: null,
        token_hash: sha256(token),
        csrf_hash: sha256("c".repeat(43)),
        csrf_enc: Buffer.alloc(80),
        expires_at: new Date(now.getTime() + 3_600_000),
        last_seen_at: now,
      })
      .execute();
    const h = fwd("GET", "/v1/account", {
      "x-forwarded-host": "ops.nearpay.localhost",
      cookie: `__Host-np_ops=${token}`,
    });
    const r = await authz(h);
    expect(claimsOf(r.headers["x-nearpay-token"] as string)).toMatchObject({
      sub: u.userId,
      ptype: "ops",
      scp: ["compliance.kyb.decide", "compliance.cases.write", "sentinel.killswitch", "rails.read", "payments.read"],
    });
    // a dashboard cookie is not a console session
    expect((await authz({ ...h, cookie: u.cookie.replace("__Host-np_session", "__Host-np_ops") })).status).toBe(401);
    await s.admin.db
      .updateTable("ops_operators")
      .set({ revoked_at: new Date() })
      .where("user_id", "=", userUuid)
      .execute();
    s.identity.cache.local<object>("sessions", 10_000).clear();
    expect((await authz(h)).status).toBe(401);
  });
});

describe("internal routes", () => {
  it("service tokens: client credentials → 5-minute token with the catalogue scopes", async () => {
    const basic = (secret: string) => `Basic ${Buffer.from(`payments:${secret}`).toString("base64")}`;
    const r = await s.direct("POST", "/internal/service-tokens", {
      headers: { authorization: basic(PAYMENTS_CLIENT_SECRET), "content-type": "application/json" },
      body: {},
    });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ token_type: "Bearer", expires_in: 300 });
    expect(claimsOf(r.body.access_token)).toMatchObject({
      sub: "payments",
      ptype: "service",
      scp: expect.arrayContaining(["identity.context.read", "rails.read"]),
    });
    const bad = await s.direct("POST", "/internal/service-tokens", {
      headers: { authorization: basic("wrong"), "content-type": "application/json" },
      body: {},
    });
    expect(bad.status).toBe(401);
    expect(bad.body).toMatchObject({ error: { code: "invalid_client" } });
  });

  it("settlement context for payments (identity.context.read), validated by the spec", async () => {
    const token = await mintServiceToken("payments");
    const r = await s.direct("GET", `/internal/accounts/${u.accountId}/settlement-context?livemode=false`, { token });
    expect(r.status).toBe(200);
    expect(getSettlementContext.response.safeParse(r.body).success).toBe(true);
    expect(r.body.fee_schedule).toMatchObject({
      name: "standard",
      rules: {
        same_asset: { total_bps: 20 },
        stable_pair: { total_bps: 50 },
        volatile: { total_bps: 100 },
        intents_transfer: { total_bps: 30, min_fee_usd_micros: 1000 },
      },
      provider_split: { oneclick: { share_bps: 5000, floor_bps: 20, stable_floor_bps: 1 } },
    });
    expect(
      (
        await s.direct("GET", `/internal/accounts/${u.accountId}/settlement-context?livemode=false`, {
          token: await mintServiceToken("notify"),
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await s.direct("GET", `/internal/accounts/acct_01m6pq018ne9tv0kqymb9je8pv/settlement-context?livemode=false`, {
          token,
        })
      ).status,
    ).toBe(404);
  });

  it("notification recipients by kind", async () => {
    const token = await mintServiceToken("notify");
    const sec = await s.direct("GET", `/internal/accounts/${u.accountId}/notification-recipients?kind=security`, {
      token,
    });
    expect(sec.body).toEqual({ recipients: [{ user_id: u.userId, email: "keys@shop.test", role: "owner" }] });
    const billing = await s.direct("GET", `/internal/accounts/${u.accountId}/notification-recipients?kind=billing`, {
      token,
    });
    expect(billing.body.recipients).toHaveLength(1);
    expect(
      (
        await s.direct("GET", `/internal/accounts/${u.accountId}/notification-recipients?kind=security`, {
          token: await mintServiceToken("payments"),
        })
      ).status,
    ).toBe(403);
  });
});

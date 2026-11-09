/**
 * Console auth settings over HTTP (lld/identity.md §6.1): the BETA platform-passkey flag
 * (`NP_OPS_ALLOW_PLATFORM_PASSKEYS`), the Cloudflare Access mode (`NP_OPS_AUTH_MODE=cloudflare_access`,
 * first-operator bootstrap) and identity's two-person claims (`ops_admins`, `ops_auth_at`).
 */
import { generateKeyPairSync } from "node:crypto";
import { sql } from "@nearpay-internal/db";
import { sendMessage } from "@nearpay-internal/spec";
import { createLocalJWKSet, decodeJwt, exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { accessVerifier } from "../../src/app/console-access.js";
import { bootstrapOperator } from "../../src/app/operators.js";
import { runOps } from "../../src/ops/cli.js";
import { eventually, OPS_HOST, OPS_ORIGIN, type Stack, startStack, TEST_AAGUID } from "../support/stack.js";
import { freshIp, mailedToken } from "../support/users.js";
import { type SoftPasskey, softPasskey } from "../support/webauthn.js";

const quiet = { actor: "t", out: () => {}, err: () => {} };

describe("BETA platform passkeys (NP_OPS_ALLOW_PLATFORM_PASSKEYS=true; remove before the VPS)", () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack({ console: { allowPlatformPasskeys: true } });
  });
  afterAll(async () => {
    await s?.stop();
  });
  const ops = (method: string, path: string, o: { cookie?: string; csrf?: string; body?: unknown } = {}) =>
    s.gateway(method, path, { host: OPS_HOST, ip: freshIp(), ...o });

  async function enrol(email: string, key: SoftPasskey, mutate?: (c: Record<string, unknown>) => void) {
    expect(await runOps(["operator-add", email, "ops_admin"], s.identity, quiet)).toBe(0);
    const v = await ops("POST", "/ops/auth/enrolment/verify", {
      body: { token: mailedToken(s, email, "ops.enrolment") },
    });
    expect(v.body).toMatchObject({ object: "ops_registration", platform_passkeys_allowed: true });
    const opts = await ops("POST", "/ops/auth/passkeys/registration/options", {
      body: { registration_token: v.body.registration_token },
    });
    // the console must not be forced to a roaming key; UV and resident keys stay required
    expect(opts.body.authenticatorSelection).toMatchObject({ residentKey: "required", userVerification: "required" });
    expect(opts.body.authenticatorSelection).not.toHaveProperty("authenticatorAttachment");
    const credential = key.create(opts.body) as unknown as Record<string, unknown>;
    mutate?.(credential);
    return ops("POST", "/ops/auth/passkeys/registration/verify", {
      body: { registration_token: v.body.registration_token, credential },
    });
  }

  let platform: SoftPasskey;
  let cookie: string;
  it("admits a synced, unattested platform passkey; records it on the operator and audits it", async () => {
    platform = softPasskey(OPS_HOST, OPS_ORIGIN, { fmt: "none", synced: true });
    const r = await enrol("mac@nearpay.test", platform);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      object: "ops_session",
      auth_mode: "passkey",
      passkey: { policy: "platform_beta", attachment: "platform", synced: true, label: "platform passkey — beta" },
    });
    const setCookie = r.headers["set-cookie"];
    cookie = String(Array.isArray(setCookie) ? setCookie[0] : setCookie).split(";")[0] as string;
    const row = await s.admin.db
      .selectFrom("ops_operators")
      .innerJoin("users", "users.id", "ops_operators.user_id")
      .select(["passkey_policy", "passkey_attachment", "passkey_synced", "passkey_registered_at"])
      .where("users.email", "=", "mac@nearpay.test")
      .executeTakeFirstOrThrow();
    expect(row).toMatchObject({
      passkey_policy: "platform_beta",
      passkey_attachment: "platform",
      passkey_synced: true,
    });
    expect(row.passkey_registered_at).not.toBeNull();
    const ev = await s.admin.db
      .selectFrom("audit_events")
      .select(["action", "details"])
      .where("action", "=", "ops.passkey_platform_registered")
      .executeTakeFirstOrThrow();
    expect(ev.details).toMatchObject({ beta: true, attachment: "platform", synced: true, fmt: "none" });
    // the ops CLI lists it
    let listed = "";
    await runOps(["operator-list"], s.identity, { ...quiet, out: (l) => (listed = l) });
    expect(JSON.parse(listed).operators[0]).toMatchObject({
      email: "mac@nearpay.test",
      passkey: { policy: "platform_beta", label: "platform passkey — beta" },
    });
  });

  it("still requires user verification and a resident key", async () => {
    const noUv = softPasskey(OPS_HOST, OPS_ORIGIN, { fmt: "none", synced: true });
    const r1 = await enrol("nouv@nearpay.test", { ...noUv, create: (o) => noUv.create(o, { uv: false }) });
    expect(r1.status).toBe(400);
    expect(r1.body.error.code).toBe("webauthn_failed");
    const r2 = await enrol("nork@nearpay.test", softPasskey(OPS_HOST, OPS_ORIGIN, { fmt: "none" }), (c) => {
      c.clientExtensionResults = { credProps: { rk: false } };
    });
    expect(r2.status).toBe(403);
    expect(r2.body.error.code).toBe("authenticator_not_allowed");
  });

  it("a hardware key is still recorded as hardware", async () => {
    const r = await enrol(
      "yubi@nearpay.test",
      softPasskey(OPS_HOST, OPS_ORIGIN, { fmt: "packed", aaguid: TEST_AAGUID }),
    );
    expect(r.status).toBe(200);
    expect(r.body.passkey).toMatchObject({ policy: "hardware", attachment: "cross-platform", synced: false });
    expect(r.body.passkey).not.toHaveProperty("label");
  });

  it("mints the two-person claims: active ops_admins and the last verification", async () => {
    const authz = await s.direct("GET", "/internal/authz", {
      headers: {
        "x-forwarded-method": "GET",
        "x-forwarded-uri": "/ops/auth/session",
        "x-forwarded-host": OPS_HOST,
        cookie,
      },
    });
    const claims = decodeJwt(authz.headers["x-nearpay-token"] as string);
    // every active ops_admin counts, enrolled key or not: mac, nouv, nork (refused keys) and yubi
    expect(claims).toMatchObject({ ptype: "ops", ops_admins: 4 });
    expect(Math.abs((claims.ops_auth_at as number) - Date.now() / 1000)).toBeLessThan(60);
  });

  it("with the flag off again, the platform passkey no longer signs in", async () => {
    const id = s.identity as unknown as { console: Record<string, unknown> };
    id.console = { ...id.console, allowPlatformPasskeys: false };
    try {
      const o = await ops("POST", "/ops/auth/passkeys/authentication/options", { body: {} });
      const r = await ops("POST", "/ops/auth/passkeys/authentication/verify", {
        body: { credential: platform.get(o.body) },
      });
      expect(r.status).toBe(400);
      expect(r.body.error.code).toBe("webauthn_failed");
    } finally {
      id.console = { ...id.console, allowPlatformPasskeys: true };
    }
  });
});

describe("Cloudflare Access console mode (NP_OPS_AUTH_MODE=cloudflare_access)", () => {
  const TEAM = "nearpay.cloudflareaccess.com";
  const AUD = "aud-console-test";
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const foreign = generateKeyPairSync("rsa", { modulusLength: 2048 });
  let s: Stack;
  beforeAll(async () => {
    const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256" };
    s = await startStack({
      console: {
        authMode: "cloudflare_access",
        access: accessVerifier({
          teamDomain: TEAM,
          audience: AUD,
          csrfKey: Buffer.alloc(32, 3),
          keys: createLocalJWKSet({ keys: [jwk] }),
        }),
        bootstrapEmail: "owner@nearpay.money",
      },
    });
  });
  afterAll(async () => {
    await s?.stop();
  });
  const nowS = () => Math.floor(Date.now() / 1000);
  const assertion = (email: string, o: { iat?: number; key?: typeof privateKey } = {}) =>
    new SignJWT({ email, type: "app" })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(`https://${TEAM}`)
      .setAudience(AUD)
      .setIssuedAt(o.iat ?? nowS() - 5)
      .setExpirationTime(nowS() + 3600)
      .sign(o.key ?? privateKey);
  const ops = (
    method: string,
    path: string,
    o: { accessJwt?: string; csrf?: string; cookie?: string; body?: unknown } = {},
  ) => s.gateway(method, path, { host: OPS_HOST, ip: freshIp(), ...o });
  const mint = async (jwt: string) => {
    const r = await s.direct("GET", "/internal/authz", {
      headers: {
        "x-forwarded-method": "GET",
        "x-forwarded-uri": "/ops/auth/session",
        "x-forwarded-host": OPS_HOST,
        "cf-access-jwt-assertion": jwt,
      },
    });
    return decodeJwt(r.headers["x-nearpay-token"] as string);
  };

  it("bootstraps the first operator from NP_OPS_BOOTSTRAP_EMAIL, once", async () => {
    await eventually(async () => {
      const r = await s.admin.db
        .selectFrom("ops_operators")
        .innerJoin("users", "users.id", "ops_operators.user_id")
        .select(["users.email", "ops_operators.role"])
        .execute();
      expect(r).toEqual([{ email: "owner@nearpay.money", role: "ops_admin" }]);
      return true;
    });
    expect(await bootstrapOperator(s.identity, "someone@else.test")).toBeNull();
    const ev = await s.admin.db
      .selectFrom("audit_events")
      .select("action")
      .where("action", "=", "operator.bootstrapped")
      .execute();
    expect(ev).toHaveLength(1);
  });

  it("the verified Access login is the console session; re-authentication = login within 5 minutes", async () => {
    const jwt = await assertion("Owner@NearPay.money");
    const me = await ops("GET", "/ops/auth/session", { accessJwt: jwt });
    expect(me.status).toBe(200);
    expect(me.body).toMatchObject({
      object: "ops_session",
      auth_mode: "cloudflare_access",
      reauth_url: "/cdn-cgi/access/logout",
      role: "ops_admin",
      operator: { email: "owner@nearpay.money" },
    });
    expect(me.body.step_up_until).toBeGreaterThan(nowS() + 200);
    const claims = await mint(jwt);
    expect(claims).toMatchObject({ ptype: "ops", ops_role: "ops_admin", ops_admins: 1, sub: me.body.operator.id });
    expect(claims.ops_auth_at).toBe(decodeJwt(jwt).iat);
    // one sign-in audit event per Access login
    await ops("GET", "/ops/auth/session", { accessJwt: jwt });
    const signIns = await s.admin.db
      .selectFrom("audit_events")
      .select("details")
      .where("action", "=", "ops.signed_in")
      .execute();
    expect(signIns).toHaveLength(1);
    expect(signIns[0]?.details).toMatchObject({ auth_mode: "cloudflare_access" });

    // an older login: no step-up (the console sends the operator to re-login through Access)
    const old = await assertion("owner@nearpay.money", { iat: nowS() - 600 });
    expect((await ops("GET", "/ops/auth/session", { accessJwt: old })).body.step_up_until).toBeNull();
    expect((await mint(old)).step_up_until).toBeUndefined();

    // unsafe requests need the CSRF token of this login
    expect((await ops("POST", "/ops/auth/logout", { accessJwt: jwt, body: {} })).status).toBe(403);
    expect((await ops("POST", "/ops/auth/logout", { accessJwt: old, csrf: me.body.csrf_token, body: {} })).status).toBe(
      403,
    );
    expect((await ops("POST", "/ops/auth/logout", { accessJwt: jwt, csrf: me.body.csrf_token, body: {} })).status).toBe(
      204,
    );
  });

  it("refuses requests without a valid assertion — even with a console cookie — and unenrolled accounts", async () => {
    expect((await ops("GET", "/ops/auth/session")).status).toBe(401);
    expect((await ops("GET", "/ops/auth/session", { cookie: "__Host-np_ops=forged" })).status).toBe(401);
    expect((await ops("GET", "/ops/auth/session", { accessJwt: "x.y.z" })).status).toBe(401);
    const forged = await assertion("owner@nearpay.money", { key: foreign.privateKey });
    expect((await ops("GET", "/ops/auth/session", { accessJwt: forged })).status).toBe(401);
    // anonymous console routes do not exist in this mode
    expect((await ops("POST", "/ops/auth/passkeys/authentication/options", { body: {} })).status).toBe(401);
    const stranger = await ops("GET", "/ops/auth/session", { accessJwt: await assertion("stranger@gmail.com") });
    expect(stranger.status).toBe(403);
    // passkey ceremonies are off even with a valid login
    const jwt = await assertion("owner@nearpay.money");
    const me = await ops("GET", "/ops/auth/session", { accessJwt: jwt });
    const r = await ops("POST", "/ops/auth/step_up/options", { accessJwt: jwt, csrf: me.body.csrf_token, body: {} });
    expect(r.body.error.code).toBe("authenticator_not_allowed");
  });

  it("operators are enrolled by email (no link); a second ops_admin raises the two-person count", async () => {
    const before = s.notify.callsTo(sendMessage).length;
    let out = "";
    expect(
      await runOps(["operator-add", "second@nearpay.money", "ops_admin"], s.identity, {
        ...quiet,
        out: (l) => (out = l),
      }),
    ).toBe(0);
    expect(JSON.parse(out)).toMatchObject({ enrolment: "by email (Cloudflare Access)" });
    expect(s.notify.callsTo(sendMessage).length).toBe(before);
    expect((await mint(await assertion("second@nearpay.money"))).ops_admins).toBe(2);
    // revoking is audited and drops the count back to one
    expect(await runOps(["operator-revoke", "second@nearpay.money"], s.identity, quiet)).toBe(0);
    expect((await mint(await assertion("owner@nearpay.money"))).ops_admins).toBe(1);
    expect((await ops("GET", "/ops/auth/session", { accessJwt: await assertion("second@nearpay.money") })).status).toBe(
      403,
    );
    const revoked = await sql<{
      n: string;
    }>`select count(*) as n from audit_events where action = 'operator.revoked'`.execute(s.admin.db);
    expect(Number(revoked.rows[0]?.n)).toBe(1);
  });
});

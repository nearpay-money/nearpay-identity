/**
 * CLI login (lld/identity.md §6.2) through the gateway: device authorization → restricted test key,
 * slow_down, expiry and the uncollected-key revocation, the anonymous allow-list (CLI login and
 * hosted invoice routes, §11), and billing's service client (spec 0.3.0 SERVICE_CLIENT_SCOPES).
 */

import { sql } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import { getSettlementContext } from "@nearpay-internal/spec";
import {
  CLI_KEY_SCOPES,
  CLI_KEY_TTL_SECONDS,
  CliLogin,
  CliLoginPoll,
  CliLoginRequest,
  SERVICE_CLIENT_SCOPES,
} from "@nearpay-money/spec";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { expireCliLogins } from "../../src/app/cli-logins.js";
import { deviceCodeHash } from "../../src/domain/cli-login/cli-login.js";
import { purgeAuth } from "../../src/workers/jobs.js";
import { BILLING_CLIENT_SECRET, type Stack, startStack } from "../support/stack.js";
import { as, joinByInvite, signUp, stepUp, type User } from "../support/users.js";

let s: Stack;
let owner: User;
let other: User;
beforeAll(async () => {
  s = await startStack();
  owner = await signUp(s, "cli-owner@shop.test", "CLI Shop");
  other = await signUp(s, "cli-other@shop.test", "Other Shop");
});
afterAll(async () => {
  await s?.stop();
});

const LOGIN_IP = "203.0.113.77";
const create = (ip = LOGIN_IP, device_name = "adarsh-mbp") =>
  s.gateway("POST", "/v1/cli/logins", {
    ip,
    body: { device_name, client_version: "0.3.0" },
    headers: { "cf-ipcountry": "de", "user-agent": "nearpay-cli/0.3.0 (darwin)" },
  });
const poll = (device_code: string) => s.gateway("POST", "/v1/cli/logins/poll", { body: { device_code } });
/** Pretend the CLI waited its interval (polls are paced by the database clock). */
const waited = (device_code: string) =>
  sql`update cli_logins set last_polled_at = last_polled_at - interval '10 seconds'
      where device_code_sha256 = ${deviceCodeHash(device_code)}`.execute(s.admin.db);
const row = (device_code: string) =>
  s.admin.db
    .selectFrom("cli_logins")
    .selectAll()
    .where("device_code_sha256", "=", deviceCodeHash(device_code))
    .executeTakeFirstOrThrow();
const approve = (u: User, code: string, mode: "test" | "live" = "test") =>
  s.gateway("POST", `/v1/cli/logins/${code}/approve`, as(u, mode, {}));
const deny = (u: User, code: string) => s.gateway("POST", `/v1/cli/logins/${code}/deny`, as(u, "test", {}));

describe("device authorization", () => {
  it("create → show → approve (step-up) → the first poll gets the key once → redeemed", async () => {
    const c = await create();
    expect(c.status).toBe(201);
    expect(CliLogin.safeParse(c.body).success).toBe(true);
    expect(c.body).toMatchObject({
      object: "cli_login",
      interval: 5,
      verification_url: "https://dashboard.nearpay.localhost/cli/authorize",
      verification_url_complete: `https://dashboard.nearpay.localhost/cli/authorize?code=${c.body.user_code}`,
    });
    expect(c.body.expires_at - Date.now() / 1000).toBeGreaterThan(890);
    expect(c.body.expires_at - Date.now() / 1000).toBeLessThan(910);
    const { device_code, user_code } = c.body;

    // stored: hash of the device code only, IP encrypted, country/UA cleaned
    const stored = await row(device_code);
    expect(stored).toMatchObject({ status: "pending", user_code, device_name: "adarsh-mbp", country: "DE" });
    expect(stored.ip_enc?.toString("latin1")).not.toContain(LOGIN_IP);
    const raw = await sql<{ n: number }>`select count(*)::int as n from cli_logins
      where position(convert_to(${device_code.slice(5, 20)}, 'UTF8') in device_code_sha256) > 0`.execute(s.admin.db);
    expect(raw.rows[0]?.n).toBe(0);

    expect((await poll(device_code)).body).toMatchObject({ object: "cli_login_poll", status: "pending", interval: 5 });

    // the approving user sees where it came from
    const shown = await s.gateway("GET", `/v1/cli/logins/${user_code}`, as(owner));
    expect(shown.status).toBe(200);
    expect(CliLoginRequest.safeParse(shown.body).success).toBe(true);
    expect(shown.body).toMatchObject({
      object: "cli_login_request",
      user_code,
      device_name: "adarsh-mbp",
      status: "pending",
      requested_from: { ip: LOGIN_IP, country: "DE", user_agent: "nearpay-cli/0.3.0 (darwin)" },
      account: null,
      key: null,
    });

    // approval needs a fresh step-up; the session's NearPay-Mode does not matter (always a test key)
    await sql`update sessions set step_up_at = null where user_id = ${toUuid(owner.userId, "usr")}`.execute(s.admin.db);
    s.identity.cache.local<object>("sessions", 10_000).clear();
    const noStepUp = await approve(owner, user_code);
    expect(noStepUp.status).toBe(401);
    expect(noStepUp.body.error.code).toBe("step_up_required");
    await stepUp(s, owner);
    const ok = await approve(owner, user_code, "live");
    expect(ok.status).toBe(200);
    expect(CliLoginRequest.safeParse(ok.body).success).toBe(true);
    expect(ok.body).toMatchObject({ status: "approved", account: owner.accountId });
    expect(ok.body.key).toMatch(/^key_/);
    expect((await approve(owner, user_code)).body.error.code).toBe("state_conflict");
    expect((await deny(owner, user_code)).body.error.code).toBe("state_conflict");

    // secret encrypted at rest until collected
    const approved = await row(device_code);
    expect(approved.key_secret_enc).not.toBeNull();

    await waited(device_code);
    const got = await poll(device_code);
    expect(got.status).toBe(200);
    expect(CliLoginPoll.safeParse(got.body).success).toBe(true);
    expect(got.body).toMatchObject({
      status: "approved",
      account: { id: owner.accountId, display_name: "CLI Shop" },
      key: {
        id: ok.body.key,
        type: "restricted",
        livemode: false,
        display_prefix: "rk_test_",
        name: "CLI · adarsh-mbp",
        scopes: [...CLI_KEY_SCOPES].sort(),
      },
    });
    expect(got.body.key.secret).toMatch(/^rk_test_[0-9A-Za-z]{48}$/);
    expect(got.body.key.expires_at - Date.now() / 1000).toBeGreaterThan(CLI_KEY_TTL_SECONDS - 60);
    expect(got.body.key.expires_at - Date.now() / 1000).toBeLessThan(CLI_KEY_TTL_SECONDS + 60);
    const redeemed = await row(device_code);
    expect(redeemed).toMatchObject({ status: "redeemed", key_secret_enc: null });

    // exactly once
    await waited(device_code);
    const again = await poll(device_code);
    expect(again.body).toEqual({ object: "cli_login_poll", status: "redeemed", interval: 5 });

    // an ordinary restricted test key: works on routes its scopes cover, listed with the session's keys
    const secret = got.body.key.secret as string;
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: secret })).status).toBe(200);
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: secret, mode: "live" })).status).toBe(200);
    expect((await s.gateway("GET", "/v1/api_keys", { bearer: secret })).status).toBe(403);
    const keys = await s.gateway("GET", "/v1/api_keys", as(owner));
    expect(keys.body.data.map((k: { id: string }) => k.id)).toContain(ok.body.key);

    // audited as api_key.created via the CLI; the login IP is kept encrypted, never in details
    const audits = await s.gateway("GET", "/v1/account/audit_events?action=api_key.created", as(owner));
    const a = audits.body.data.find((e: { target: { id: string } }) => e.target.id === ok.body.key);
    expect(a).toMatchObject({
      actor: { type: "user", id: owner.userId },
      details: { via: "cli_login", livemode: false, type: "restricted", login_country: "DE", client_version: "0.3.0" },
    });
    expect(JSON.stringify(a)).not.toContain(LOGIN_IP);
    const auditRow = await s.admin.db
      .selectFrom("audit_events")
      .select(["id", "origin_ip_enc"])
      .where("id", "=", toUuid(a.id, "aud"))
      .executeTakeFirstOrThrow();
    expect(
      s.identity.cipher.decrypt(auditRow.origin_ip_enc as Buffer, `audit:${auditRow.id}:origin_ip`).toString(),
    ).toBe(LOGIN_IP);
    // the key creation event is in the outbox (cache purge across replicas)
    const ev = await sql<{ n: number }>`select count(*)::int as n from outbox
      where subject = 'evt.identity.api_key.created' and aggregate_id = ${toUuid(ok.body.key, "key")}`.execute(
      s.admin.db,
    );
    expect(ev.rows[0]?.n).toBe(1);

    // another account no longer sees it
    expect((await s.gateway("GET", `/v1/cli/logins/${user_code}`, as(other))).status).toBe(404);
    expect((await s.gateway("GET", `/v1/cli/logins/${user_code}`, as(owner))).body.status).toBe("redeemed");
  });

  it("slow_down: polling faster than the interval is 429 rate_limited with Retry-After", async () => {
    const c = await create("203.0.113.78");
    expect((await poll(c.body.device_code)).status).toBe(200);
    const fast = await poll(c.body.device_code);
    expect(fast.status).toBe(429);
    expect(fast.body.error.code).toBe("rate_limited");
    expect(Number(fast.headers["retry-after"])).toBeGreaterThanOrEqual(1);
    expect(Number(fast.headers["retry-after"])).toBeLessThanOrEqual(5);
    await waited(c.body.device_code);
    expect((await poll(c.body.device_code)).status).toBe(200);
  });

  it("unknown device codes are 404 without echoing the code; malformed ones 400", async () => {
    const code = `npdc_${"A".repeat(43)}`;
    const r = await poll(code);
    expect(r.status).toBe(404);
    expect(r.body.error.code).toBe("resource_missing");
    expect(JSON.stringify(r.body)).not.toContain("AAAAAAAAAA");
    expect((await poll("npdc_short")).status).toBe(400);
  });

  it("deny: the CLI learns `denied`; nothing is minted", async () => {
    const c = await create("203.0.113.79");
    const d = await deny(owner, c.body.user_code);
    expect(d.status).toBe(200);
    expect(d.body).toMatchObject({ status: "denied", account: null, key: null });
    expect((await poll(c.body.device_code)).body.status).toBe("denied");
    await stepUp(s, owner);
    expect((await approve(owner, c.body.user_code)).body.error.code).toBe("state_conflict");
    expect((await s.gateway("GET", `/v1/cli/logins/${c.body.user_code}`, as(other))).status).toBe(404);
    expect(await row(c.body.device_code)).toMatchObject({ key_id: null, key_secret_enc: null });
  });

  it("roles: owner/admin/developer only; finance and viewers are refused", async () => {
    const dev = await joinByInvite(s, owner, "cli-dev@shop.test", "developer");
    const fin = await joinByInvite(s, owner, "cli-fin@shop.test", "finance");
    const c = await create("203.0.113.80");
    expect((await s.gateway("GET", `/v1/cli/logins/${c.body.user_code}`, as(fin))).status).toBe(403);
    await stepUp(s, fin);
    expect((await approve(fin, c.body.user_code)).status).toBe(403);
    expect((await s.gateway("GET", `/v1/cli/logins/${c.body.user_code}`, as(dev))).status).toBe(200);
    await stepUp(s, dev);
    expect((await approve(dev, c.body.user_code)).body.status).toBe("approved");
    const got = (await poll(c.body.device_code)).body;
    expect(got.status).toBe("approved");
    // a CLI key cannot approve further logins (session-only routes)
    const c2 = await create("203.0.113.81");
    const viaKey = await s.gateway("POST", `/v1/cli/logins/${c2.body.user_code}/approve`, {
      bearer: got.key.secret,
      body: {},
    });
    expect(viaKey.status).toBe(403);
    expect((await row(c2.body.device_code)).status).toBe("pending");
  });

  it("anonymous callers and API keys cannot read or decide logins", async () => {
    const c = await create("203.0.113.82");
    expect((await s.gateway("GET", `/v1/cli/logins/${c.body.user_code}`)).status).toBe(401);
    expect((await s.gateway("POST", `/v1/cli/logins/${c.body.user_code}/approve`, { body: {} })).status).toBe(401);
    expect((await s.gateway("GET", "/v1/cli/logins/BCDF-GHJK", as(owner))).status).toBe(404);
  });

  it("expiry: an unapproved login expires after 15 min; the job makes it durable", async () => {
    const c = await create("203.0.113.83");
    await sql`update cli_logins set expires_at = now() - interval '1 second', created_at = now() - interval '16 minutes'
      where device_code_sha256 = ${deviceCodeHash(c.body.device_code)}`.execute(s.admin.db);
    expect((await poll(c.body.device_code)).body.status).toBe("expired");
    await stepUp(s, owner);
    const late = await approve(owner, c.body.user_code);
    expect(late.status).toBe(409);
    expect(late.body.error.code).toBe("state_conflict");
    expect((await s.gateway("GET", `/v1/cli/logins/${c.body.user_code}`, as(other))).body.status).toBe("expired");
    const r = await expireCliLogins(s.identity);
    expect(r.expired).toBeGreaterThanOrEqual(1);
    expect((await row(c.body.device_code)).status).toBe("expired");
    // 24 h after expiry it is gone from the dashboard; purged after 7 days
    await sql`update cli_logins set expires_at = now() - interval '25 hours', created_at = now() - interval '8 days'
      where device_code_sha256 = ${deviceCodeHash(c.body.device_code)}`.execute(s.admin.db);
    expect((await s.gateway("GET", `/v1/cli/logins/${c.body.user_code}`, as(owner))).status).toBe(404);
    expect((await purgeAuth(s.identity)).cli_logins).toBeGreaterThanOrEqual(1);
    await waited(c.body.device_code).catch(() => {});
    expect((await poll(c.body.device_code)).status).toBe(404);
  });

  it("an approved key nobody collects within 15 min is revoked and its secret erased", async () => {
    const c = await create("203.0.113.84");
    await stepUp(s, owner);
    const ok = await approve(owner, c.body.user_code);
    expect(ok.body.status).toBe("approved");
    await sql`update cli_logins set decided_at = now() - interval '16 minutes'
      where device_code_sha256 = ${deviceCodeHash(c.body.device_code)}`.execute(s.admin.db);
    // the CLI coming back late gets no key
    const late = await poll(c.body.device_code);
    expect(late.body).toEqual({ object: "cli_login_poll", status: "expired", interval: 5 });
    const r = await expireCliLogins(s.identity);
    expect(r.uncollected).toBe(1);
    expect(await row(c.body.device_code)).toMatchObject({ status: "expired", key_secret_enc: null });
    const key = await s.admin.db
      .selectFrom("api_keys")
      .select("revoked_at")
      .where("id", "=", toUuid(ok.body.key, "key"))
      .executeTakeFirstOrThrow();
    expect(key.revoked_at).not.toBeNull();
    const revoked = await sql<{ n: number }>`select count(*)::int as n from outbox
      where subject = 'evt.identity.api_key.revoked' and aggregate_id = ${toUuid(ok.body.key, "key")}`.execute(
      s.admin.db,
    );
    expect(revoked.rows[0]?.n).toBe(1);
    const audit = await s.admin.db
      .selectFrom("audit_events")
      .select(["actor_type", "details"])
      .where("action", "=", "api_key.revoked")
      .where("target_id", "=", ok.body.key)
      .executeTakeFirstOrThrow();
    expect(audit).toMatchObject({ actor_type: "system", details: { via: "cli_login", reason: "not_collected" } });
    expect((await expireCliLogins(s.identity)).uncollected).toBe(0);
  });

  it("creation is limited to 10 per 10 min per client IP", async () => {
    const ip = "203.0.113.99";
    for (let i = 0; i < 10; i++) expect((await create(ip)).status).toBe(201);
    const limited = await create(ip);
    expect(limited.status).toBe(429);
    expect(limited.body.error.code).toBe("rate_limited");
    expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
    expect((await create("203.0.113.100")).status).toBe(201);
  });

  it("user codes stay unique among pending logins", async () => {
    const codes = new Set<string>();
    for (let i = 0; i < 9; i++) codes.add((await create(`198.18.0.${i + 1}`)).body.user_code);
    expect(codes.size).toBe(9);
    const dup = await s.admin.db
      .selectFrom("cli_logins")
      .select("user_code")
      .where("status", "=", "pending")
      .limit(1)
      .executeTakeFirstOrThrow();
    await expect(
      sql`insert into cli_logins (id, device_code_sha256, user_code, device_name, expires_at)
        values (gen_random_uuid(), ${deviceCodeHash("npdc_x")}, ${dup.user_code}, 'x', now() + interval '1 minute')`.execute(
        s.admin.db,
      ),
    ).rejects.toThrow(/cli_logins_user_code_pending/);
  });
});

describe("anonymous allow-list (§11)", () => {
  const authz = (method: string, uri: string) =>
    s.direct("GET", "/internal/authz", {
      headers: {
        "x-forwarded-method": method,
        "x-forwarded-uri": uri,
        "x-forwarded-host": "api.nearpay.localhost",
        "x-forwarded-for": "198.51.100.200",
      },
    });
  it("CLI login create/poll and the hosted invoice routes need no credential; the rest of CLI login does", async () => {
    const inv = "in_01jbz9k3m4n5p6q7r8s9t0v1w2";
    for (const [m, u] of [
      ["POST", "/v1/cli/logins"],
      ["POST", "/v1/cli/logins/poll"],
      ["GET", `/v1/invoices/${inv}/public`],
      ["POST", `/v1/invoices/${inv}/public/sessions`],
      ["GET", `/v1/invoices/${inv}/public/pdf`],
    ] as const) {
      const r = await authz(m, u);
      expect(r.status, `${m} ${u}`).toBe(200);
      expect(decodeJwt(r.headers["x-nearpay-token"] as string)).toMatchObject({ ptype: "anonymous" });
    }
    for (const [m, u] of [
      ["GET", "/v1/cli/logins/BCDF-GHJK"],
      ["POST", "/v1/cli/logins/BCDF-GHJK/approve"],
      ["POST", "/v1/cli/logins/BCDF-GHJK/deny"],
      ["GET", `/v1/invoices/${inv}`],
    ] as const)
      expect((await authz(m, u)).status, `${m} ${u}`).toBe(401);
  });
});

describe("billing service client (spec 0.3.0)", () => {
  it("mints billing's token with the spec scopes; it reads the settlement context", async () => {
    const r = await s.direct("POST", "/internal/service-tokens", {
      headers: {
        authorization: `Basic ${Buffer.from(`billing:${BILLING_CLIENT_SECRET}`).toString("base64")}`,
        "content-type": "application/json",
      },
      body: {},
    });
    expect(r.status).toBe(200);
    const claims = decodeJwt(r.body.access_token);
    expect(claims).toMatchObject({ sub: "billing", ptype: "service" });
    expect([...(claims.scp as string[])].sort()).toEqual([...SERVICE_CLIENT_SCOPES.billing].sort());
    expect(claims.scp).toEqual(expect.arrayContaining(["identity.context.read", "rails.read"]));
    const ctx = await s.direct("GET", `/internal/accounts/${owner.accountId}/settlement-context?livemode=false`, {
      token: r.body.access_token,
    });
    expect(ctx.status).toBe(200);
    expect(getSettlementContext.response.safeParse(ctx.body).success).toBe(true);
    // billing holds no recipients scope (notify's)
    const rec = await s.direct("GET", `/internal/accounts/${owner.accountId}/notification-recipients?kind=billing`, {
      token: r.body.access_token,
    });
    expect(rec.status).toBe(403);
  });
});

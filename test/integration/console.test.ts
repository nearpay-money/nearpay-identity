/**
 * Console (ops) sign-in and reads (lld/identity.md §6.1, §8.1): operator enrolment by the ops CLI,
 * hardware-key registration (AAGUID allow-list, attestation required), console sessions on the ops
 * host only, ops tokens with `ops_role`, step-up, logout, merchant and audit reads, the unified
 * audit trail and the KYB-driven legal name (worker consumers).
 */
import { toUuid } from "@nearpay-internal/ids";
import { domainEvent, mintServiceToken } from "@nearpay-internal/testing";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runOps } from "../../src/ops/cli.js";
import { eventually, OPS_HOST, OPS_ORIGIN, type Stack, startStack, TEST_AAGUID } from "../support/stack.js";
import { as, cookieOf, freshIp, mailedToken, signUp, type User } from "../support/users.js";
import { type SoftPasskey, softPasskey } from "../support/webauthn.js";

let s: Stack;
let merchant: User;
beforeAll(async () => {
  s = await startStack({ worker: true });
  merchant = await signUp(s, "owner@console.test", "Console Shop");
});
afterAll(async () => {
  await s?.stop();
});

const ops = (method: string, path: string, o: { cookie?: string; csrf?: string; body?: unknown } = {}) =>
  s.gateway(method, path, { host: OPS_HOST, ip: freshIp(), ...o });

async function enrol(email: string, role: "ops" | "ops_admin", key: SoftPasskey) {
  const code = await runOps(["operator-add", email, role], s.identity, { actor: "t", out: () => {}, err: () => {} });
  expect(code).toBe(0);
  const token = mailedToken(s, email, "ops.enrolment");
  const v = await ops("POST", "/ops/auth/enrolment/verify", { body: { token } });
  expect(v.body).toMatchObject({ object: "ops_registration", email });
  const opts = await ops("POST", "/ops/auth/passkeys/registration/options", {
    body: { registration_token: v.body.registration_token },
  });
  expect(opts.body).toMatchObject({ attestation: "direct", rp: { id: OPS_HOST } });
  const r = await ops("POST", "/ops/auth/passkeys/registration/verify", {
    body: { registration_token: v.body.registration_token, credential: key.create(opts.body) },
  });
  return { r, token };
}

const hwKey = () => softPasskey(OPS_HOST, OPS_ORIGIN, { fmt: "packed", aaguid: TEST_AAGUID });

describe("enrolment and sign-in", () => {
  let op: { cookie: string; csrf: string; key: SoftPasskey; id: string };

  it("registers an allow-listed hardware key and opens a console session", async () => {
    const key = hwKey();
    const { r, token } = await enrol("op@nearpay.test", "ops_admin", key);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ object: "ops_session", role: "ops_admin", operator: { email: "op@nearpay.test" } });
    expect(r.body.expires_at - r.body.idle_expires_at).toBeGreaterThan(11 * 3600 - 60);
    expect(r.headers["set-cookie"]).toMatch(/^__Host-np_ops=.*Max-Age=43200/);
    op = { cookie: cookieOf(r.headers["set-cookie"]), csrf: r.body.csrf_token, key, id: r.body.operator.id };
    // the enrolment link is single use
    expect((await ops("POST", "/ops/auth/enrolment/verify", { body: { token } })).body.error.code).toBe("link_used");
  });

  it("refuses keys off the allow-list, unattested and synced passkeys (authenticator_not_allowed)", async () => {
    for (const key of [
      softPasskey(OPS_HOST, OPS_ORIGIN, { fmt: "packed", aaguid: "00000000-0000-0000-0000-0000000000ff" }),
      softPasskey(OPS_HOST, OPS_ORIGIN, { fmt: "none", aaguid: TEST_AAGUID }),
      softPasskey(OPS_HOST, OPS_ORIGIN, { fmt: "packed", aaguid: TEST_AAGUID, synced: true }),
    ]) {
      const { r } = await enrol("op2@nearpay.test", "ops", key);
      expect(r.status).toBe(403);
      expect(r.body.error.code).toBe("authenticator_not_allowed");
    }
  });

  it("console sessions mint ops tokens with ops_role and live only on the ops host", async () => {
    const authz = await s.direct("GET", "/internal/authz", {
      headers: {
        "x-forwarded-method": "GET",
        "x-forwarded-uri": "/ops/auth/session",
        "x-forwarded-host": OPS_HOST,
        cookie: op.cookie,
      },
    });
    expect(decodeJwt(authz.headers["x-nearpay-token"] as string)).toMatchObject({
      ptype: "ops",
      ops_role: "ops_admin",
      sub: op.id,
    });
    const me = await ops("GET", "/ops/auth/session", { cookie: op.cookie });
    expect(me.body).toMatchObject({ object: "ops_session", csrf_token: op.csrf, role: "ops_admin" });
    // the ops cookie is no dashboard session; the dashboard cookie is no console session; keys never reach /ops
    expect(
      (await s.gateway("GET", "/v1/account", { cookie: op.cookie.replace("__Host-np_ops", "__Host-np_session") }))
        .status,
    ).toBe(401);
    expect((await ops("GET", "/ops/auth/session", { cookie: merchant.cookie })).status).toBe(401);
    expect((await ops("GET", "/v1/account", { cookie: op.cookie })).status).toBe(403);
    expect((await s.gateway("GET", "/ops/merchants", { cookie: merchant.cookie })).status).toBe(403);
    // dashboard passkeys do not sign in to the console, console keys do
    const o = await ops("POST", "/ops/auth/passkeys/authentication/options", { body: {} });
    const refused = await ops("POST", "/ops/auth/passkeys/authentication/verify", {
      body: { credential: merchant.passkey.get(o.body) },
    });
    // catalogue status (spec 0.2.1 kept 400; the route text once said 401)
    expect(refused.status).toBe(400);
    expect(refused.body.error.code).toBe("webauthn_failed");
    const o2 = await ops("POST", "/ops/auth/passkeys/authentication/options", { body: {} });
    const signIn = await ops("POST", "/ops/auth/passkeys/authentication/verify", {
      body: { credential: op.key.get(o2.body) },
    });
    expect(signIn.status).toBe(200);
    expect(signIn.body.step_up_until).toBeGreaterThan(Date.now() / 1000);
  });

  it("step-up and logout", async () => {
    const o = await ops("POST", "/ops/auth/step_up/options", { cookie: op.cookie, csrf: op.csrf, body: {} });
    const r = await ops("POST", "/ops/auth/step_up/verify", {
      cookie: op.cookie,
      csrf: op.csrf,
      body: { credential: op.key.get(o.body) },
    });
    expect(r.body).toMatchObject({ object: "ops_session" });
    expect(r.body.step_up_until).toBeGreaterThan(Date.now() / 1000 + 500);
    // CSRF on unsafe console requests
    expect((await ops("POST", "/ops/auth/logout", { cookie: op.cookie, body: {} })).status).toBe(403);
  });

  it("merchant search, merchant detail and the platform audit log", async () => {
    const byEmail = await ops("GET", "/ops/merchants?q=owner%40console.test", { cookie: op.cookie });
    expect(byEmail.body.data).toHaveLength(1);
    expect(byEmail.body.data[0]).toMatchObject({
      id: merchant.accountId,
      owners: [{ id: merchant.userId, email: "owner@console.test" }],
      member_count: 1,
      active_live_destinations: 0,
      recovered_at: null,
    });
    expect((await ops("GET", `/ops/merchants?q=${merchant.accountId}`, { cookie: op.cookie })).body.data).toHaveLength(
      1,
    );
    expect((await ops("GET", "/ops/merchants?q=Console%20S", { cookie: op.cookie })).body.data[0].id).toBe(
      merchant.accountId,
    );
    expect((await ops("GET", "/ops/merchants?q=zz-none", { cookie: op.cookie })).body.data).toEqual([]);
    const one = await ops("GET", `/ops/merchants/${merchant.accountId}`, { cookie: op.cookie });
    expect(one.body).toMatchObject({ object: "account", display_name: "Console Shop" });
    const audit = await ops("GET", "/ops/audit_events?actor_type=operator&action=ops.enrolled", { cookie: op.cookie });
    expect(audit.body.data[0]).toMatchObject({ actor: { type: "operator", id: op.id }, account: null });
  });

  it("revoked operators lose the console; getInternalOpsOperator reports them inactive (spec 0.2.1)", async () => {
    const token = await mintServiceToken("compliance");
    const read = (id: string, t = token) => s.direct("GET", `/internal/ops_operators/${id}`, { token: t });
    const active = await read(op.id);
    expect(active.status, JSON.stringify(active.body)).toBe(200);
    expect(active.body).toMatchObject({ user_id: op.id, role: "ops_admin", active: true, revoked_at: null });
    expect(JSON.stringify(active.body)).not.toContain("@");
    expect((await read(merchant.userId)).status).toBe(404);
    expect((await read(op.id, await mintServiceToken("notify"))).status).toBe(403);

    await runOps(["operator-revoke", "op@nearpay.test"], s.identity, { actor: "t", out: () => {}, err: () => {} });
    s.identity.cache.local<object>("sessions", 10_000).clear();
    expect((await ops("GET", "/ops/auth/session", { cookie: op.cookie })).status).toBe(401);
    const revoked = await read(op.id);
    expect(revoked.body).toMatchObject({ user_id: op.id, active: false });
    expect(typeof revoked.body.revoked_at).toBe("string");
  });
});

describe("worker consumers", () => {
  it("KYB: submitted → pending; approved → the ops-approved legal name and country; rejected clears the name", async () => {
    const acct = toUuid(merchant.accountId, "acct");
    const meta = (version: number) => ({ accountUuid: acct, livemode: null, version });
    await s.publishEvent(
      domainEvent(
        "evt.compliance.kyb.submitted",
        { account_id: merchant.accountId, status: "pending", submitted_at: new Date().toISOString() },
        meta(1),
      ),
    );
    await eventually(
      async () => (await s.gateway("GET", "/v1/account", { cookie: merchant.cookie })).body.kyb_status === "pending",
    );
    await s.publishEvent(
      domainEvent(
        "evt.compliance.kyb.approved",
        { account_id: merchant.accountId, status: "approved", reason: "ok" },
        meta(2),
      ),
    );
    const a = await eventually(async () => {
      const r = (await s.gateway("GET", "/v1/account", { cookie: merchant.cookie })).body;
      return r.kyb_status === "approved" ? r : null;
    });
    expect(a).toMatchObject({ verified_legal_name: "Acme Trading GmbH", country: "DE" });
    const ev = await eventually(async () =>
      s.admin.db
        .selectFrom("outbox")
        .select(["payload"])
        .where("subject", "=", "evt.identity.account.updated")
        .where("account_id", "=", acct)
        .orderBy("created_at", "desc")
        .executeTakeFirst(),
    );
    expect((ev.payload as { livemode: unknown }).livemode).toBeNull();
    await s.publishEvent(
      domainEvent(
        "evt.compliance.kyb.rejected",
        { account_id: merchant.accountId, status: "rejected", reason: "x" },
        meta(3),
      ),
    );
    await eventually(async () => {
      const r = (await s.gateway("GET", "/v1/account", { cookie: merchant.cookie })).body;
      return r.kyb_status === "rejected" && r.verified_legal_name === null;
    });
  });

  it("operator actions of other services join the audit trail once, hidden from the merchant's own log", async () => {
    const actionId = "019a6000-0000-7000-8000-00000000abcd";
    const object = {
      id: actionId,
      actor: { sub: merchant.userId, ops_role: "ops_admin" },
      action: "kill_switch.engaged",
      target: { type: "kill_switch", id: "global" },
      account_id: merchant.accountId,
      approval: null,
      occurred_at: new Date().toISOString(),
    };
    await s.publishEvent(
      domainEvent("evt.sentinel.ops_action.recorded", object, { accountUuid: null, livemode: null, version: 1 }),
    );
    await s.publishEvent(
      domainEvent("evt.sentinel.ops_action.recorded", object, {
        accountUuid: null,
        livemode: null,
        version: 1,
      }),
    );
    const rows = await eventually(async () => {
      const r = await s.admin.db.selectFrom("audit_events").selectAll().where("id", "=", actionId).execute();
      return r.length ? r : null;
    });
    await new Promise((r) => setTimeout(r, 300));
    expect(await s.admin.db.selectFrom("audit_events").select("id").where("id", "=", actionId).execute()).toHaveLength(
      1,
    );
    expect(rows[0]).toMatchObject({
      actor_type: "operator",
      action: "kill_switch.engaged",
      details: { source: "sentinel", ops_role: "ops_admin", approval: null },
    });
    const mine = await s.gateway("GET", "/v1/account/audit_events?limit=100", as(merchant));
    expect(mine.body.data.map((x: { action: string }) => x.action)).not.toContain("kill_switch.engaged");
  });

  it("a two-person action completed by a single operator keeps its single_operator marker", async () => {
    const actionId = "019a6000-0000-7000-8000-00000000abce";
    await s.publishEvent(
      domainEvent(
        "evt.compliance.ops_action.recorded",
        {
          id: actionId,
          actor: { sub: merchant.userId, ops_role: "ops_admin" },
          action: "ops_approval.approved_single_operator",
          target: { type: "ops_approval", id: "opa_01m701vavvegsv8st5rmt7k54h" },
          account_id: merchant.accountId,
          approval: "opa_01m701vavvegsv8st5rmt7k54h",
          occurred_at: new Date().toISOString(),
          single_operator: true,
        },
        { accountUuid: null, livemode: null, version: 1 },
      ),
    );
    const row = await eventually(async () =>
      s.admin.db.selectFrom("audit_events").selectAll().where("id", "=", actionId).executeTakeFirst(),
    );
    expect(row).toMatchObject({
      action: "ops_approval.approved_single_operator",
      details: { source: "compliance", single_operator: true },
    });
  });
});

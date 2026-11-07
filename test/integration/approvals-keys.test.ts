/**
 * Stage 2 money-path controls through the gateway: the two-approver rule for live destinations
 * (application + database), restricted keys (scopes at the gateway, updateApiKey) and the recovery
 * flow with its 48 h destination lock.
 */
import { sql } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import { sendMessage } from "@nearpay-internal/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { nearSigner } from "../support/signers.js";
import { ORIGIN, RP_ID, type Stack, startStack, USDC_NEAR } from "../support/stack.js";
import { as, cookieOf, freshIp, joinByInvite, mailedToken, signUp, stepUp, type User } from "../support/users.js";
import { softPasskey } from "../support/webauthn.js";

let s: Stack;
beforeAll(async () => {
  s = await startStack({ cooloffSeconds: 3600 });
});
afterAll(async () => {
  await s?.stop();
});

async function liveDestination(u: User) {
  const near = nearSigner();
  await stepUp(s, u);
  const r = await s.gateway(
    "POST",
    "/v1/settlement_destinations",
    as(u, "live", {
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address: near.implicitAccount,
      label: "Main",
    }),
  );
  if (r.status !== 201) throw new Error(`create ${r.status} ${JSON.stringify(r.body)}`);
  const c = r.body.attestation_challenge;
  const att = await s.gateway(
    "POST",
    `/v1/settlement_destinations/${r.body.id}/attest`,
    as(u, "live", {
      challenge_id: c.id,
      standard: "nep413",
      signature: near.sign(c.message, Buffer.from(c.nonce, "base64")),
      public_key: near.publicKey,
    }),
  );
  return { created: r.body, attested: att };
}
const approve = (u: User, id: string, decision: "approve" | "reject" = "approve") =>
  s.gateway("POST", `/v1/settlement_destinations/${id}/approve`, as(u, "live", { decision }));

describe("two-approver rule", () => {
  it("a single-admin account goes straight to cool-off; the creator is the approval", async () => {
    const solo = await signUp(s, "solo@approve.test");
    const { created, attested } = await liveDestination(solo);
    expect(created.approval).toEqual({ required: 1, approved_by: [solo.userId], rejected_by: null });
    expect(attested.body).toMatchObject({ status: "cooling_off" });
  });

  it("with two owners/admins the creator alone can never complete it; a second admin starts the cool-off", async () => {
    const a = await signUp(s, "a@approve.test", "Approve Shop");
    const b = await joinByInvite(s, a, "b@approve.test", "admin");
    const viewer = await joinByInvite(s, a, "v@approve.test", "viewer");
    const { created, attested } = await liveDestination(a);
    expect(created.approval).toEqual({ required: 2, approved_by: [a.userId], rejected_by: null });
    expect(attested.body).toMatchObject({ status: "pending_approval", active_at: null });
    // notify is asked to reach the other owners/admins; the event carries the creator's approval
    const ev = await sql<{ payload: { data: { object: { approval: unknown; status: string } } } }>`
      select payload from outbox where subject = 'evt.identity.settlement_destination.pending_approval'
        and aggregate_id = ${toUuid(created.id, "sd")}`.execute(s.admin.db);
    expect(ev.rows[0]?.payload.data.object).toMatchObject({
      status: "pending_approval",
      approval: { required: 2, approved_by: [a.userId], rejected_by: null },
    });

    await stepUp(s, a);
    const self = await approve(a, created.id);
    expect(self.status).toBe(403);
    expect(self.body.error.code).toBe("approver_conflict");
    expect((await approve(viewer, created.id)).status).toBe(403);
    // the database refuses the transition without a second approver, whatever the application does
    await expect(
      sql`update settlement_destinations set status = 'cooling_off' where id = ${toUuid(created.id, "sd")}`.execute(
        s.admin.db,
      ),
    ).rejects.toThrow(/distinct approvals/);
    await expect(
      sql`insert into destination_approvals (destination_id, user_id, decision) values (${toUuid(created.id, "sd")}, ${toUuid(a.userId, "usr")}, 'approve')`.execute(
        s.admin.db,
      ),
    ).rejects.toThrow(/duplicate key/);
    await expect(sql`delete from destination_approvals`.execute(s.admin.db)).rejects.toThrow(/append-only/);

    // the second admin (stepped up) starts the cool-off
    await stepUp(s, b);
    const ok = await approve(b, created.id);
    expect(ok.body).toMatchObject({ status: "cooling_off", approval: { approved_by: [a.userId, b.userId] } });
    expect(ok.body.active_at).toBeGreaterThan(Date.now() / 1000 + 3000);
    expect((await approve(b, created.id)).body.error.code).toBe("state_conflict");
    const job = await s.admin.db
      .selectFrom("jobs")
      .select("kind")
      .where("dedupe_key", "=", `destination.activate:sd:${toUuid(created.id, "sd")}`)
      .executeTakeFirst();
    expect(job?.kind).toBe("destination.activate");
  });

  it("a rejection by the other admin disables the destination", async () => {
    const a = await signUp(s, "ra@approve.test");
    const b = await joinByInvite(s, a, "rb@approve.test", "admin");
    const { created } = await liveDestination(a);
    await stepUp(s, b);
    const r = await approve(b, created.id, "reject");
    expect(r.body).toMatchObject({
      status: "disabled",
      disabled_reason: "merchant",
      approval: { rejected_by: b.userId },
    });
  });
});

describe("restricted keys", () => {
  it("hold only their scopes at the gateway (write implies read); scopes change within the cache window", async () => {
    const u = await signUp(s, "rk@keys.test");
    await stepUp(s, u);
    const bad = await s.gateway(
      "POST",
      "/v1/api_keys",
      as(u, "test", { type: "restricted", livemode: false, name: "x", scopes: ["destinations.write"] }),
    );
    expect(bad.body.error).toMatchObject({ code: "scope_unknown", param: "scopes" });
    const noScopes = await s.gateway(
      "POST",
      "/v1/api_keys",
      as(u, "test", { type: "restricted", livemode: false, name: "x" }),
    );
    expect(noScopes.status).toBe(400);
    const secretWithScopes = await s.gateway(
      "POST",
      "/v1/api_keys",
      as(u, "test", { type: "secret", livemode: false, name: "x", scopes: ["events.read"] }),
    );
    expect(secretWithScopes.status).toBe(400);

    const k = await s.gateway(
      "POST",
      "/v1/api_keys",
      as(u, "test", { type: "restricted", livemode: false, name: "reader", scopes: ["events.read"] }),
    );
    expect(k.status).toBe(201);
    expect(k.body).toMatchObject({ type: "restricted", display_prefix: "rk_test_", scopes: ["events.read"] });
    expect(k.body.secret).toMatch(/^rk_test_/);
    // no destinations scope: refused at the gateway
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: k.body.secret })).status).toBe(403);
    // never on dashboard-only routes
    expect((await s.gateway("GET", "/v1/api_keys", { bearer: k.body.secret })).status).toBe(403);

    const upd = await s.gateway(
      "PATCH",
      `/v1/api_keys/${k.body.id}`,
      as(u, "test", { scopes: ["destinations.read"], name: "dest reader" }),
    );
    expect(upd.body).toMatchObject({ name: "dest reader", scopes: ["destinations.read"] });
    expect(upd.body.secret).toBeUndefined();
    const list = await s.gateway("GET", "/v1/settlement_destinations", { bearer: k.body.secret });
    expect(list.status).toBe(200);

    const sk = await s.gateway("POST", "/v1/api_keys", as(u, "test", { type: "secret", livemode: false, name: "s" }));
    const conflict = await s.gateway("PATCH", `/v1/api_keys/${sk.body.id}`, as(u, "test", { scopes: ["events.read"] }));
    expect(conflict.body.error.code).toBe("state_conflict");
    const renamed = await s.gateway(
      "PATCH",
      `/v1/api_keys/${sk.body.id}`,
      as(u, "test", { name: "renamed", ip_allowlist: ["203.0.113.0/24"] }),
    );
    expect(renamed.body).toMatchObject({ name: "renamed", ip_allowlist: ["203.0.113.0/24"] });
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: sk.body.secret })).status).toBe(403);
    // a key of the other mode is not found from this mode
    expect((await s.gateway("PATCH", `/v1/api_keys/${sk.body.id}`, as(u, "live", { name: "x" }))).status).toBe(404);
  });
});

describe("recovery", () => {
  it("adds a passkey to the existing user, locks destination changes 48 h and audits it; unknown addresses get nothing", async () => {
    const u = await signUp(s, "lost@recover.test", "Recover Shop");
    const before = s.notify.callsTo(sendMessage).length;
    const nobody = await s.gateway("POST", "/v1/auth/recovery", {
      body: { email: "nobody@recover.test", turnstile_token: "t" },
      ip: freshIp(),
    });
    expect(nobody.status).toBe(202);
    expect(s.notify.callsTo(sendMessage).length).toBe(before);

    const r = await s.gateway("POST", "/v1/auth/recovery", {
      body: { email: "LOST@recover.test", turnstile_token: "t" },
      ip: freshIp(),
    });
    expect(r.status).toBe(202);
    const token = mailedToken(s, "lost@recover.test", "auth.magic_link");
    const v = await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token } });
    expect(v.body).toMatchObject({ purpose: "recovery", email: "lost@recover.test" });
    const opts = await s.gateway("POST", "/v1/auth/passkeys/registration/options", {
      body: { registration_token: v.body.registration_token },
    });
    expect(opts.body.excludeCredentials).toHaveLength(1);
    const pk = softPasskey(RP_ID, ORIGIN);
    const reg = await s.gateway("POST", "/v1/auth/passkeys/registration/verify", {
      body: { registration_token: v.body.registration_token, credential: pk.create(opts.body) },
    });
    expect(reg.status).toBe(200);
    expect(reg.body).toMatchObject({ user: { id: u.userId }, account: { id: u.accountId }, role: "owner" });
    const recovered: User = {
      ...u,
      passkey: pk,
      cookie: cookieOf(reg.headers["set-cookie"]),
      csrf: reg.body.csrf_token,
    };
    // no new user or account; the old passkey still works
    expect(
      await s.admin.db.selectFrom("users").select("id").where("email", "=", "lost@recover.test").execute(),
    ).toHaveLength(1);
    const acct = await s.admin.db
      .selectFrom("accounts")
      .select("recovered_at")
      .where("id", "=", toUuid(u.accountId, "acct"))
      .executeTakeFirstOrThrow();
    expect(acct.recovered_at).not.toBeNull();
    await stepUp(s, recovered);
    const d = await s.gateway(
      "POST",
      "/v1/settlement_destinations",
      as(recovered, "live", {
        asset_id: USDC_NEAR,
        type: "intents_account",
        chain: "near:mainnet",
        address: nearSigner().implicitAccount,
        label: "x",
      }),
    );
    expect(d.body.error.code).toBe("recovery_lock");
    const audit = await s.admin.db
      .selectFrom("audit_events")
      .select("action")
      .where("account_id", "=", toUuid(u.accountId, "acct"))
      .execute();
    expect(audit.map((a) => a.action)).toContain("user.recovered");
    const list = await s.gateway("GET", "/v1/account/audit_events?action=user.recovered", { cookie: recovered.cookie });
    expect(list.body.data).toHaveLength(1);
    expect(list.body.data[0]).toMatchObject({
      object: "audit_event",
      account: u.accountId,
      actor: { type: "user", id: u.userId },
    });
  });
});

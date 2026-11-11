/**
 * Stage 2 money-path controls through the gateway: the two-approver rule for live destinations
 * (application + database), restricted keys (scopes at the gateway, updateApiKey) and the recovery
 * flow with its 48 h destination lock. Runs with an explicit cool-off (3600 s) to keep the operator-set
 * cool-off path covered (cooling_off → activation job); the default (no cool-off) is covered in
 * destinations.test.ts.
 */
import { sql } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import { sendMessage } from "@nearpay-internal/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { activateDestination, expirePendingDestinations } from "../../src/app/destinations.js";
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

/** Moves every owner/admin grant of the account `days` into the past (a long-standing team). */
async function ageTeam(accountId: string, days: number) {
  await sql`update manager_grants set granted_at = granted_at - make_interval(days => ${days}),
      qualifies_at = qualifies_at - make_interval(days => ${days}),
      revoked_at = revoked_at - make_interval(days => ${days})
    where account_id = ${toUuid(accountId, "acct")}`.execute(s.admin.db);
}
const grantOf = (u: User) =>
  s.admin.db
    .selectFrom("manager_grants")
    .selectAll()
    .where("account_id", "=", toUuid(u.accountId, "acct"))
    .where("user_id", "=", toUuid(u.userId, "usr"))
    .orderBy("id", "desc")
    .executeTakeFirstOrThrow();
const destRow = (id: string) =>
  s.admin.db
    .selectFrom("settlement_destinations")
    .selectAll()
    .where("id", "=", toUuid(id, "sd"))
    .executeTakeFirstOrThrow();
const setRole = async (by: User, u: User, role: string) => {
  await stepUp(s, by);
  return s.gateway("PATCH", `/v1/account/members/${u.userId}`, as(by, "test", { role }));
};

describe("two-approver rule", () => {
  it("with a cool-off set, a single-admin account goes straight to cool-off; the creator is the approval", async () => {
    const solo = await signUp(s, "solo@approve.test");
    const { created, attested } = await liveDestination(solo);
    expect(created.approval).toEqual({ required: 1, approved_by: [solo.userId], rejected_by: null });
    expect(attested.body).toMatchObject({ status: "cooling_off" });
  });

  it("with two owners/admins the creator alone can never complete it; a second admin starts the cool-off", async () => {
    const a = await signUp(s, "a@approve.test", "Approve Shop");
    const b = await joinByInvite(s, a, "b@approve.test", "admin");
    const viewer = await joinByInvite(s, a, "v@approve.test", "viewer");
    await ageTeam(a.accountId, 60);
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
    ).rejects.toThrow(/distinct approvals by qualified owners\/admins/);
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

// audit finding 1 (HIGH): one person must not satisfy the two-approver rule
describe("two-approver rule against one person", () => {
  it("scenario A: a puppet admin invited by one manager cannot approve (application and database)", async () => {
    const a = await signUp(s, "pa@puppet.test", "Puppet Shop");
    await joinByInvite(s, a, "pb@puppet.test", "admin"); // the honest second manager, never acts
    await ageTeam(a.accountId, 60);
    // the attacker creates the destination, then invites an admin at an address they control
    const { created, attested } = await liveDestination(a);
    expect(attested.body.status).toBe("pending_approval");
    const p = await joinByInvite(s, a, "pp@puppet.test", "admin");
    // next to two managers a new grant waits 30 days, not 7
    const g = await grantOf(p);
    expect(g.qualifies_at.getTime() - g.granted_at.getTime()).toBe(30 * 86_400_000);
    await stepUp(s, p);
    const r = await approve(p, created.id);
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe("approver_conflict");
    // even with its tenure waived, a grant younger than the destination never counts — in the database too
    await sql`update manager_grants set qualifies_at = granted_at where user_id = ${toUuid(p.userId, "usr")}`.execute(
      s.admin.db,
    );
    expect((await approve(p, created.id)).body.error.code).toBe("approver_conflict");
    const sd = toUuid(created.id, "sd");
    await sql`insert into destination_approvals (destination_id, user_id, decision)
      values (${sd}, ${toUuid(p.userId, "usr")}, 'approve')`.execute(s.admin.db);
    await expect(
      sql`update settlement_destinations set status = 'cooling_off' where id = ${sd}`.execute(s.admin.db),
    ).rejects.toThrow(/needs 2 distinct approvals by qualified owners\/admins, has 1/);
  });

  it("scenario A': a puppet that waited out its tenure before the destination still needs 30 days next to two managers", async () => {
    const a = await signUp(s, "qa@puppet.test", "Puppet Shop 2");
    await joinByInvite(s, a, "qb@puppet.test", "admin");
    await ageTeam(a.accountId, 60);
    const p = await joinByInvite(s, a, "qp@puppet.test", "admin");
    // 8 days later (7-day tenure would have passed): still not qualified
    await sql`update manager_grants set granted_at = granted_at - interval '8 days', qualifies_at = qualifies_at - interval '8 days'
      where user_id = ${toUuid(p.userId, "usr")}`.execute(s.admin.db);
    const { created } = await liveDestination(a);
    await stepUp(s, p);
    expect((await approve(p, created.id)).body.error.code).toBe("approver_conflict");
  });

  it("scenario B: demoting the other manager first does not lower the requirement; re-promoting does not qualify them", async () => {
    const a = await signUp(s, "ba@demote.test", "Demote Shop");
    const b = await joinByInvite(s, a, "bb@demote.test", "admin");
    await ageTeam(a.accountId, 60);
    expect((await setRole(a, b, "viewer")).status).toBe(200);
    const { created, attested } = await liveDestination(a);
    // the 30-day high-water mark of managers is 2
    expect(created.approval).toMatchObject({ required: 2 });
    expect(attested.body.status).toBe("pending_approval");
    expect((await setRole(a, b, "admin")).status).toBe(200);
    await stepUp(s, b);
    const r = await approve(b, created.id);
    expect(r.body.error.code).toBe("approver_conflict");
    // the role changes were published for notify (security.member_changed)
    const ev = await sql<{ subject: string }>`select subject from outbox
      where subject = 'evt.identity.member.role_changed' and payload->'data'->'object'->>'user_id' = ${b.userId}`.execute(
      s.admin.db,
    );
    expect(ev.rows).toHaveLength(2);
  });

  it("an approver who loses the role, or a new manager, sends a cooling-off destination back to approval at activation", async () => {
    const a = await signUp(s, "aa@activate.test", "Activate Shop");
    const { created, attested } = await liveDestination(a);
    expect(attested.body.status).toBe("cooling_off");
    await joinByInvite(s, a, "ab@activate.test", "admin");
    await sql`update settlement_destinations set active_at = now() - interval '1 minute' where id = ${toUuid(created.id, "sd")}`.execute(
      s.admin.db,
    );
    expect(await activateDestination(s.identity, toUuid(created.id, "sd"))).toBe("reapproval");
    const d = await destRow(created.id);
    expect(d).toMatchObject({ status: "pending_approval", approvals_required: 2, active_at: null });
    const ev = await sql`select 1 from outbox where subject = 'evt.identity.settlement_destination.pending_approval'
      and aggregate_id = ${d.id}`.execute(s.admin.db);
    expect(ev.rows).toHaveLength(1);
    // and the database refuses a direct activation as well
    await expect(
      sql`update settlement_destinations set status = 'active' where id = ${d.id}`.execute(s.admin.db),
    ).rejects.toThrow(/qualified owners/);
  });

  it("pending destinations expire after 7 days and cannot be approved any more", async () => {
    const a = await signUp(s, "ea@expire.test", "Expire Shop");
    const b = await joinByInvite(s, a, "eb@expire.test", "admin");
    await ageTeam(a.accountId, 60);
    const { created } = await liveDestination(a);
    const sd = toUuid(created.id, "sd");
    await sql`update settlement_destinations set created_at = created_at - interval '8 days' where id = ${sd}`.execute(
      s.admin.db,
    );
    await stepUp(s, b);
    const r = await approve(b, created.id);
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe("state_conflict");
    expect(await expirePendingDestinations(s.identity)).toBeGreaterThanOrEqual(1);
    expect(await destRow(created.id)).toMatchObject({ status: "disabled", disabled_reason: "expired" });
    // spec 0.2.1: the public object names the creator and the expiry reason
    expect(created.created_by).toBe(a.userId);
    const got = await s.gateway("GET", `/v1/settlement_destinations/${created.id}`, as(a, "live"));
    expect(got.body).toMatchObject({ status: "disabled", disabled_reason: "expired", created_by: a.userId });
    const t = await s.admin.db
      .selectFrom("settlement_destination_transitions")
      .select("cause")
      .where("destination_id", "=", sd)
      .orderBy("created_at", "desc")
      .executeTakeFirstOrThrow();
    expect(t.cause).toBe("expired");
  });

  it("manager grants follow every membership change; typeid_uuid decodes ids for the backfill", async () => {
    const a = await signUp(s, "ga@grants.test", "Grants Shop");
    const v = await joinByInvite(s, a, "gv@grants.test", "viewer");
    expect(
      await s.admin.db
        .selectFrom("manager_grants")
        .select("id")
        .where("user_id", "=", toUuid(v.userId, "usr"))
        .execute(),
    ).toHaveLength(0);
    await setRole(a, v, "admin");
    await setRole(a, v, "owner"); // owner <-> admin keeps the grant
    const open = await grantOf(v);
    expect(open.revoked_at).toBeNull();
    // a solo owner's first co-manager waits 7 days
    expect(open.qualifies_at.getTime() - open.granted_at.getTime()).toBe(7 * 86_400_000);
    await stepUp(s, a);
    await s.gateway("DELETE", `/v1/account/members/${v.userId}`, as(a));
    expect((await grantOf(v)).revoked_at).not.toBeNull();
    const r = await sql<{ u: string }>`select typeid_uuid(${a.userId}) as u`.execute(s.admin.db);
    expect(r.rows[0]?.u).toBe(toUuid(a.userId, "usr"));
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
    const adm = await joinByInvite(s, u, "adm@recover.test", "admin");
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
    // spec 0.2.1: evt.identity.user.recovered (platform event, version = recovery count, ids only)
    const outboxed = await s.admin.db
      .selectFrom("outbox")
      .selectAll()
      .where("subject", "=", "evt.identity.user.recovered")
      .where("aggregate_id", "=", toUuid(u.userId, "usr"))
      .execute();
    expect(outboxed).toHaveLength(1);
    const ev = outboxed[0] as (typeof outboxed)[number];
    expect(ev).toMatchObject({ account_id: null, livemode: null, aggregate_type: "user", aggregate_version: 1 });
    const obj = (ev.payload as { data: { object: Record<string, string | string[]> } }).data.object;
    expect(obj).toMatchObject({ user_id: u.userId, account_ids: [u.accountId] });
    expect(Date.parse(obj.lock_until as string) - Date.parse(obj.recovered_at as string)).toBe(48 * 3_600_000);
    expect(JSON.stringify(ev.payload)).not.toContain("@recover.test");
    // and the member's security summary
    const members = await s.gateway("GET", "/v1/account/members", { cookie: recovered.cookie });
    const me = members.body.data.find((m: { user: { id: string } }) => m.user.id === u.userId);
    expect(me.security).toEqual({
      passkeys: 2,
      recovered_at: Math.floor(Date.parse(obj.recovered_at as string) / 1000),
    });
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
    // audit finding 1 (d): no owner/admin can be invited, promoted or removed during the lock either
    const inviteAdmin = await s.gateway(
      "POST",
      "/v1/account/invitations",
      as(recovered, "test", { email: "helper@recover.test", role: "admin" }),
    );
    expect(inviteAdmin.status).toBe(403);
    expect(inviteAdmin.body.error.code).toBe("recovery_lock");
    const inviteViewer = await s.gateway(
      "POST",
      "/v1/account/invitations",
      as(recovered, "test", { email: "viewer@recover.test", role: "viewer" }),
    );
    expect(inviteViewer.status).toBe(201);
    const demote = await setRole(recovered, adm, "viewer");
    expect(demote.body.error.code).toBe("recovery_lock");
    await stepUp(s, recovered);
    const remove = await s.gateway("DELETE", `/v1/account/members/${adm.userId}`, as(recovered));
    expect(remove.body.error.code).toBe("recovery_lock");
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

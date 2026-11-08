/**
 * Contract (foundations §16): every Stage-1 identity route is bound; every subject routed to
 * identity is handled; every subject identity produces is emitted; the sentinel registry view has
 * the columns sentinel reads.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  challengeSettlementDestination,
  createSettlementDestination,
  DashboardSession,
  ERRORS,
  getDashboardSession,
  PUBLIC_ROUTES,
  SettlementDestination,
  SPEC_VERSION,
} from "@nearpay/spec";
import { unhandledSubjects } from "@nearpay-internal/bus";
import { sql } from "@nearpay-internal/db";
import { unimplementedRoutes } from "@nearpay-internal/service";
import { INTERNAL_ROUTES, OPS_ROUTES, SUBJECTS, type Subject } from "@nearpay-internal/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { identityRoutes } from "../../src/api/routes.js";
import { identityHandlers } from "../../src/consumers/handlers.js";
import { type Stack, startStack } from "../support/stack.js";

const ALL = [...PUBLIC_ROUTES, ...INTERNAL_ROUTES];

describe("routes and events", () => {
  it("binds every Stage-1 and Stage-2 identity route (incl. console routes), and nothing else", () => {
    const bindings = identityRoutes({} as never, { touches: {} as never, serviceClients: new Map() });
    expect(unimplementedRoutes("identity", ALL, bindings).map((r) => r.id)).toEqual([]);
    expect(bindings.map((b) => b.route.id).sort()).toEqual(
      ALL.filter((r) => r.service === "identity" && r.stage <= 2)
        .map((r) => r.id)
        .sort(),
    );
  });

  it("binds every console route identity serves, with ops roles", () => {
    const bound = new Set(
      identityRoutes({} as never, { touches: {} as never, serviceClients: new Map() }).map((b) => b.route.id),
    );
    const mine = OPS_ROUTES.filter((r) => r.service === "identity");
    expect(mine.length).toBeGreaterThanOrEqual(12);
    for (const r of mine) {
      expect(bound.has(r.id), r.id).toBe(true);
      if (!r.auth.includes("anonymous")) expect(r.opsRoles).toEqual(["ops", "ops_admin"]);
    }
  });

  it("is built against spec 0.2.1; Stage 1 routes keep their shape", () => {
    expect(SPEC_VERSION).toBe("0.2.1");
    const bound = identityRoutes({} as never, { touches: {} as never, serviceClients: new Map() }).map(
      (b) => b.route.id,
    );
    expect(bound).toEqual(expect.arrayContaining(["getDashboardSession", "challengeSettlementDestination"]));
    // session auth, any role, read-only; the response is the sign-in DashboardSession
    expect(getDashboardSession).toMatchObject({ method: "GET", path: "/v1/auth/session", auth: ["session"] });
    expect(getDashboardSession).not.toHaveProperty("roles");
    expect(getDashboardSession).not.toHaveProperty("stepUp");
    expect(getDashboardSession.response).toBe(DashboardSession);
    // the same access as creating a destination: stepped-up owner/admin session, idempotent
    expect(challengeSettlementDestination).toMatchObject({
      method: "POST",
      path: "/v1/settlement_destinations/{id}/challenge",
      auth: ["session"],
      roles: ["owner", "admin"],
      stepUp: true,
      idempotent: true,
      errors: ["state_conflict"],
    });
    expect(challengeSettlementDestination.auth).toEqual(createSettlementDestination.auth);
    expect(challengeSettlementDestination.roles).toEqual(createSettlementDestination.roles);
    expect(challengeSettlementDestination.response).toBe(SettlementDestination);
    expect(ERRORS.challenge_expired.message).toMatch(/request a new challenge for the destination/);
  });

  it("handles every subject the catalogue routes to identity", () => {
    const handlers = identityHandlers({} as never, { purgeKey: async () => {} });
    expect(unhandledSubjects("identity", handlers)).toEqual([]);
    for (const subject of Object.keys(handlers) as Subject[]) expect(SUBJECTS[subject].consumers).toContain("identity");
  });

  it("emits every subject identity produces", () => {
    const produced = (Object.keys(SUBJECTS) as Subject[]).filter(
      (k) => SUBJECTS[k].producer === "identity" && SUBJECTS[k].stage <= 2,
    );
    const files = (dir: string): string[] =>
      readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)) : [join(dir, f)]));
    const src = files(new URL("../../src", import.meta.url).pathname)
      .map((f) => readFileSync(f, "utf8"))
      .join("\n");
    const literal = new Set(src.match(/evt\.identity\.[a-z_]+\.[a-z_]+/g));
    // settlement_destination.<event> is built from the event name (app/destinations.ts)
    for (const e of ["created", "pending_approval", "cooling_off", "activated", "disabled", "default_changed"])
      literal.add(`evt.identity.settlement_destination.${e}`);
    expect([...literal].filter((x) => produced.includes(x as Subject)).sort()).toEqual([...produced].sort());
  });
});

describe("sentinel registry view", () => {
  let s: Stack;
  beforeAll(async () => {
    s = await startStack();
  });
  afterAll(async () => {
    await s?.stop();
  });
  it("exposes the merchant name, KYB flag, verification and disabled_at only", async () => {
    const cols = await sql<{ column_name: string }>`
      select column_name from information_schema.columns where table_name = 'sentinel_destination_registry' order by ordinal_position`.execute(
      s.admin.db,
    );
    expect(cols.rows.map((c) => c.column_name)).toEqual([
      "id",
      "account_id",
      "livemode",
      "asset_id",
      "type",
      "chain",
      "address_norm",
      "status",
      "active_at",
      "merchant_name",
      "kyb_verified",
      "verification",
      "disabled_at",
    ]);
  });
  it("lists active destinations and once-active disabled ones, never pending ones", async () => {
    const acct = "01900000-0000-7000-8000-0000000a0c01";
    await sql`insert into accounts (id, display_name, verified_legal_name, fee_schedule_id, api_version, settings)
      values (${acct}, 'Acme', 'Acme GmbH', '01900000-0000-7000-8000-000000000001', '2026-11-01', '{}')`.execute(
      s.admin.db,
    );
    const row = (id: string, status: string, activeAt: string | null, disabledAt: string | null) =>
      sql`insert into settlement_destinations (id, account_id, livemode, asset_id, type, chain, address, address_norm, label,
            status, verification, active_at, created_by, disabled_at, disabled_reason)
          values (${id}, ${acct}, false, 'nep141:usdc.near', 'chain_address', 'near:mainnet', ${`d${id.slice(-4)}.near`}, ${`d${id.slice(-4)}.near`},
            'x', ${status}, 'test', ${activeAt}, ${acct}, ${disabledAt}, ${disabledAt ? "merchant" : null})`.execute(
        s.admin.db,
      );
    await row("01900000-0000-7000-8000-0000000d0001", "active", "2026-11-01T00:00:00Z", null);
    await row("01900000-0000-7000-8000-0000000d0002", "disabled", "2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z");
    await row("01900000-0000-7000-8000-0000000d0003", "disabled", null, "2026-11-02T00:00:00Z");
    await row("01900000-0000-7000-8000-0000000d0004", "pending_verification", null, null);
    const got = await sql<{
      id: string;
      status: string;
      merchant_name: string;
      kyb_verified: boolean;
      disabled_at: Date | null;
    }>`
      select id, status, merchant_name, kyb_verified, disabled_at from sentinel_destination_registry where account_id = ${acct} order by id`.execute(
      s.admin.db,
    );
    expect(
      got.rows.map((r) => [r.id.slice(-1), r.status, r.merchant_name, r.kyb_verified, r.disabled_at !== null]),
    ).toEqual([
      ["1", "active", "Acme GmbH", true, false],
      ["2", "disabled", "Acme GmbH", true, true],
    ]);
  });
  it("attestation challenges can be superseded (migration 0003)", async () => {
    const cols = await sql<{ column_name: string; is_nullable: string }>`
      select column_name, is_nullable from information_schema.columns
      where table_name = 'attestation_challenges' and column_name = 'superseded_at'`.execute(s.admin.db);
    expect(cols.rows).toEqual([{ column_name: "superseded_at", is_nullable: "YES" }]);
  });
  it("migration 0004: invitations, ops passkeys, the two-approver trigger and append-only approvals", async () => {
    const tables = await sql<{ table_name: string }>`
      select table_name from information_schema.tables where table_name in ('invitations') `.execute(s.admin.db);
    expect(tables.rows).toHaveLength(1);
    const triggers = await sql<{ tgname: string }>`
      select tgname from pg_trigger where tgname in ('destination_approvals_complete', 'destination_approvals_no_update') order by tgname`.execute(
      s.admin.db,
    );
    expect(triggers.rows.map((r) => r.tgname)).toEqual([
      "destination_approvals_complete",
      "destination_approvals_no_update",
    ]);
  });
  it("migration 0006 (spec 0.2.1): website, user recovery columns, the expired reason", async () => {
    const cols = await sql<{ table_name: string; column_name: string }>`
      select table_name, column_name from information_schema.columns
      where (table_name = 'accounts' and column_name = 'website')
         or (table_name = 'users' and column_name in ('recovered_at', 'recovery_count'))
      order by table_name, column_name`.execute(s.admin.db);
    expect(cols.rows.map((c) => `${c.table_name}.${c.column_name}`)).toEqual([
      "accounts.website",
      "users.recovered_at",
      "users.recovery_count",
    ]);
    const check = await sql<{ def: string }>`
      select pg_get_constraintdef(oid) as def from pg_constraint
      where conname = 'settlement_destinations_disabled_reason_check'`.execute(s.admin.db);
    expect(check.rows[0]?.def).toContain("expired");
  });
  it("the audit log is append-only even for the app role", async () => {
    await s.admin.db
      .insertInto("audit_events")
      .values({
        id: "01900000-0000-7000-8000-0000000000aa",
        actor_type: "system",
        actor_id: "t",
        action: "t",
        details: "{}",
      })
      .execute();
    await expect(sql`update audit_events set action = 'x'`.execute(s.admin.db)).rejects.toThrow(/append-only/);
    await expect(sql`delete from audit_events`.execute(s.admin.db)).rejects.toThrow(/append-only/);
  });
});

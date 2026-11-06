/**
 * Contract (foundations §16): every Stage-1 identity route is bound; every subject routed to
 * identity is handled; every subject identity produces is emitted; the sentinel registry view has
 * the columns sentinel reads.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { PUBLIC_ROUTES } from "@nearpay/spec";
import { unhandledSubjects } from "@nearpay-internal/bus";
import { sql } from "@nearpay-internal/db";
import { unimplementedRoutes } from "@nearpay-internal/service";
import { INTERNAL_ROUTES, SUBJECTS, type Subject } from "@nearpay-internal/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { identityRoutes } from "../../src/api/routes.js";
import { identityHandlers } from "../../src/consumers/handlers.js";
import { type Stack, startStack } from "../support/stack.js";

const ALL = [...PUBLIC_ROUTES, ...INTERNAL_ROUTES];

describe("routes and events", () => {
  it("binds every Stage-1 identity route, and nothing else", () => {
    const bindings = identityRoutes({} as never, { touches: {} as never, serviceClients: new Map() });
    expect(unimplementedRoutes("identity", ALL, bindings).map((r) => r.id)).toEqual([]);
    expect(bindings.map((b) => b.route.id).sort()).toEqual(
      ALL.filter((r) => r.service === "identity" && r.stage <= 1)
        .map((r) => r.id)
        .sort(),
    );
  });

  it("handles every subject the catalogue routes to identity", () => {
    const handlers = identityHandlers({} as never, { purgeKey: async () => {} });
    expect(unhandledSubjects("identity", handlers)).toEqual([]);
    for (const subject of Object.keys(handlers) as Subject[]) expect(SUBJECTS[subject].consumers).toContain("identity");
  });

  it("emits every subject identity produces", () => {
    const produced = (Object.keys(SUBJECTS) as Subject[]).filter(
      (k) => SUBJECTS[k].producer === "identity" && SUBJECTS[k].stage <= 1,
    );
    const files = (dir: string): string[] =>
      readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? files(join(dir, f)) : [join(dir, f)]));
    const src = files(new URL("../../src", import.meta.url).pathname)
      .map((f) => readFileSync(f, "utf8"))
      .join("\n");
    const literal = new Set(src.match(/evt\.identity\.[a-z_]+\.[a-z_]+/g));
    // settlement_destination.<event> is built from the event name (app/destinations.ts)
    for (const e of ["created", "cooling_off", "activated", "disabled", "default_changed"])
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

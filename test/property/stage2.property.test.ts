/**
 * Stage 2 properties (lld/identity.md §15): the two-approver rule, restricted-key scope evaluation,
 * console session expiry and the last-owner rule.
 */

import { authorizeRoute } from "@nearpay-internal/auth";
import { KEY_SCOPES, PUBLIC_ROUTES } from "@nearpay-money/spec";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { checkScopes, expandScopes, restrictedAllows } from "../../src/domain/api-key/key.js";
import {
  type ApprovalRecord,
  afterAttestation,
  applyRoleChange,
  approvedBy,
  atActivation,
  currentManagers,
  type Decision,
  decide,
  effectiveRequired,
  isExpired,
  type ManagerGrant,
  recentManagers,
} from "../../src/domain/approval/approval.js";
import { idleExpiresAt, OPS_ABSOLUTE_MS, OPS_IDLE_MS, sessionState } from "../../src/domain/session/session.js";
import { approvalsRequired } from "../../src/domain/settlement-destination/destination.js";
import { canChangeRole, canRemove, type Role } from "../../src/domain/team/team.js";

// ---------------------------------------------------------------------------------------------
// Two-approver rule
// ---------------------------------------------------------------------------------------------

type Step = { kind: "attest" } | { kind: "decide"; by: number; decision: Decision };

const DAY = 86_400_000;
const T0 = 10_000 * DAY;

/** `managers` tenured owners/admins: the creator and the first others of u0…u5. */
function tenuredTeam(managers: number, creator: number): ManagerGrant[] {
  const ids = [creator, ...[0, 1, 2, 3, 4, 5].filter((i) => i !== creator)].slice(0, managers);
  return ids.map((i) => ({ userId: `u${i}`, grantedAt: T0 - 90 * DAY, qualifiesAt: T0 - 80 * DAY, revokedAt: null }));
}

/** Runs a destination through attestation and decisions; returns the trace of statuses and approvals. */
function run(managers: number, creator: number, steps: readonly Step[]) {
  const required = approvalsRequired(managers, true);
  const ctx = { createdAt: T0 - DAY, now: T0, cooloffMs: DAY, grants: tenuredTeam(managers, creator) };
  let status = "pending_verification";
  let approvals: ApprovalRecord[] = [{ userId: `u${creator}`, decision: "approve" }];
  const trace: { status: string; approvals: ApprovalRecord[] }[] = [];
  for (const st of steps) {
    if (status === "disabled" || status === "cooling_off") break;
    if (st.kind === "attest") {
      if (status === "pending_verification") status = afterAttestation(ctx, required, approvals).to;
    } else {
      const out = decide({ ...ctx, status, required, createdBy: `u${creator}`, approvals }, `u${st.by}`, st.decision);
      if (out.ok) {
        approvals = [...approvals, out.record];
        status = out.to;
      }
    }
    trace.push({ status, approvals });
  }
  return { required, trace };
}

const step = (users: number) =>
  fc.oneof(
    fc.constant<Step>({ kind: "attest" }),
    fc.record({
      kind: fc.constant("decide" as const),
      by: fc.integer({ min: 0, max: users - 1 }),
      decision: fc.constantFrom<Decision>("approve", "reject"),
    }),
  );

describe("two-approver rule", () => {
  it("a multi-admin account never reaches cool-off without two distinct approving users", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 6 }),
        fc.integer({ min: 0, max: 5 }),
        fc.array(step(6), { maxLength: 25 }),
        (managers, creator, steps) => {
          const { required, trace } = run(managers, creator, steps);
          for (const t of trace) {
            if (t.status !== "cooling_off") continue;
            const by = approvedBy(t.approvals);
            expect(by.length).toBeGreaterThanOrEqual(required);
            if (managers >= 2) {
              expect(by).toContain(`u${creator}`);
              expect(by.some((u) => u !== `u${creator}`)).toBe(true);
            }
          }
        },
      ),
    );
  });

  it("no single principal can complete a destination change on a multi-admin account", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 2, max: 6 }),
        fc.integer({ min: 0, max: 5 }),
        fc.array(fc.oneof(fc.constant("attest" as const), fc.constantFrom<Decision>("approve", "reject")), {
          maxLength: 25,
        }),
        (managers, p, actions) => {
          // the same user creates, attests and decides every time
          const steps: Step[] = actions.map((a) =>
            a === "attest" ? { kind: "attest" } : { kind: "decide", by: p, decision: a },
          );
          const { trace } = run(managers, p, steps);
          for (const t of trace) {
            expect(t.status).not.toBe("cooling_off");
            expect(approvedBy(t.approvals)).toEqual([`u${p}`]);
          }
        },
      ),
    );
  });

  it("a user decides at most once; a rejection is terminal", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 2, max: 6 }),
        fc.integer({ min: 0, max: 5 }),
        fc.array(step(6), { maxLength: 25 }),
        (m, c, steps) => {
          const { trace } = run(m, c, steps);
          const last = trace.at(-1);
          if (!last) return;
          const users = last.approvals.map((a) => a.userId);
          expect(new Set(users).size).toBe(users.length);
          if (last.approvals.some((a) => a.decision === "reject")) expect(last.status).toBe("disabled");
        },
      ),
    );
  });

  it("a single-admin account goes straight to cool-off on attestation (the creator's approval suffices)", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 5 }), (c) => {
        const { trace } = run(1, c, [{ kind: "attest" }]);
        expect(trace[0]?.status).toBe("cooling_off");
      }),
    );
  });
});

// ---------------------------------------------------------------------------------------------
// Audit finding 1: one human cannot satisfy the two-approver rule
// ---------------------------------------------------------------------------------------------
//
// Model of the account: the grant history (the memberships trigger, `applyRoleChange`) and the
// destination lifecycle driven only through the domain functions the use cases call (creation's
// requirement, afterAttestation, decide, atActivation, isExpired). The account starts with ≥ 2
// tenured managers: `L` (the attacker's session) and the honest `H0…` (passive: they never act).
// The attacker runs any sequence for up to 30 days: invite users they control (puppets) as owner or
// admin (they join), promote/demote/remove anyone (honest managers included), create destinations
// from any manager they control, attest, approve from any user they control, run the activation job,
// let time pass. No destination may ever reach `active`.

type Op =
  | { kind: "invite" }
  | { kind: "demote" | "promote" | "remove"; who: number }
  | { kind: "create"; by: number }
  | { kind: "attest"; dest: number }
  | { kind: "approve"; dest: number; by: number }
  | { kind: "activate"; dest: number }
  | { kind: "wait"; hours: number };

// weighted towards the attack shape (invite, age, create, attest, approve, activate) so shrinking finds it
const op = fc.oneof(
  { arbitrary: fc.constant<Op>({ kind: "invite" }), weight: 2 },
  {
    arbitrary: fc.record({
      kind: fc.constantFrom("demote" as const, "promote" as const, "remove" as const),
      who: fc.nat(5),
    }),
    weight: 2,
  },
  { arbitrary: fc.record({ kind: fc.constant("create" as const), by: fc.nat(3) }), weight: 2 },
  { arbitrary: fc.record({ kind: fc.constant("attest" as const), dest: fc.nat(2) }), weight: 2 },
  { arbitrary: fc.record({ kind: fc.constant("approve" as const), dest: fc.nat(2), by: fc.nat(3) }), weight: 4 },
  { arbitrary: fc.record({ kind: fc.constant("activate" as const), dest: fc.nat(2) }), weight: 2 },
  {
    arbitrary: fc.record({ kind: fc.constant("wait" as const), hours: fc.integer({ min: 1, max: 24 * 10 }) }),
    weight: 3,
  },
);

interface Dest {
  status: string;
  stored: number;
  createdAt: number;
  createdBy: string;
  approvals: ApprovalRecord[];
  activeAt: number;
}

function attack(honest: number, ops: readonly Op[], cooloffMs: number): Dest[] {
  const start = T0;
  let now = start;
  const old = (u: string): ManagerGrant => ({
    userId: u,
    grantedAt: start - 400 * DAY,
    qualifiesAt: start - 390 * DAY,
    revokedAt: null,
  });
  const honestIds = Array.from({ length: honest }, (_, i) => `H${i}`);
  let grants: ManagerGrant[] = [old("L"), ...honestIds.map(old)];
  const members = new Set(["L", ...honestIds]);
  const role = new Map<string, boolean>([...members].map((u) => [u, true])); // manager?
  const controlled = ["L"];
  const everyone = () => [...controlled, ...honestIds];
  const dests: Dest[] = [];
  const setManager = (u: string, m: boolean) => {
    grants = applyRoleChange(grants, u, role.get(u) === true, m, now);
    role.set(u, m);
  };
  const ctxOf = (d: Dest) => ({ createdAt: d.createdAt, now, cooloffMs, grants });
  for (const o of ops) {
    if (now - start > 30 * DAY) break;
    switch (o.kind) {
      case "invite": {
        const p = `P${controlled.length}`;
        controlled.push(p);
        members.add(p);
        role.set(p, false);
        setManager(p, true);
        break;
      }
      case "demote":
      case "promote":
      case "remove": {
        const u = everyone()[o.who % everyone().length] as string;
        if (!members.has(u)) break;
        // the account keeps one manager (last owner rule); the attacker must hold a manager role to act
        if (o.kind !== "promote" && currentManagers(grants).length <= 1) break;
        if (o.kind === "remove") {
          setManager(u, false);
          members.delete(u);
        } else if (o.kind === "promote") setManager(u, true);
        else setManager(u, false);
        break;
      }
      case "create": {
        const by = controlled[o.by % controlled.length] as string;
        if (role.get(by) !== true) break;
        const managers = currentManagers(grants).length;
        dests.push({
          status: "pending_verification",
          stored: effectiveRequired(managers >= 2 ? 2 : 1, grants, now),
          createdAt: now,
          createdBy: by,
          approvals: [{ userId: by, decision: "approve" }],
          activeAt: 0,
        });
        break;
      }
      case "attest": {
        const d = dests[o.dest % Math.max(1, dests.length)];
        if (d?.status !== "pending_verification" || isExpired(d.createdAt, now)) break;
        const r = afterAttestation(ctxOf(d), d.stored, d.approvals);
        d.stored = r.required;
        d.status = r.to;
        if (r.to === "cooling_off") d.activeAt = now + cooloffMs;
        break;
      }
      case "approve": {
        const d = dests[o.dest % Math.max(1, dests.length)];
        const by = controlled[o.by % controlled.length] as string;
        if (!d || role.get(by) !== true) break;
        const out = decide(
          { ...ctxOf(d), status: d.status, required: d.stored, createdBy: d.createdBy, approvals: d.approvals },
          by,
          "approve",
        );
        if (!out.ok) break;
        d.approvals.push(out.record);
        d.stored = out.required;
        d.status = out.to;
        if (out.to === "cooling_off") d.activeAt = now + cooloffMs;
        break;
      }
      case "activate": {
        const d = dests[o.dest % Math.max(1, dests.length)];
        if (d?.status !== "cooling_off" || now < d.activeAt) break;
        const r = atActivation(ctxOf(d), d.stored, d.approvals);
        d.stored = r.required;
        d.status = r.to;
        break;
      }
      case "wait":
        now += o.hours * 3_600_000;
        for (const d of dests)
          if ((d.status === "pending_verification" || d.status === "pending_approval") && isExpired(d.createdAt, now))
            d.status = "disabled";
        break;
    }
  }
  return dests;
}

describe("two-approver rule against one human (audit finding 1)", () => {
  it("no sequence by one human within 30 days activates a destination on an account that had ≥ 2 managers", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 3 }),
        fc.array(op, { maxLength: 60 }),
        fc.constantFrom(0, DAY, 3 * DAY),
        (honest, ops, cooloff) => {
          for (const d of attack(honest, ops, cooloff)) {
            expect(d.status).not.toBe("active");
            expect(d.status).not.toBe("cooling_off");
          }
        },
      ),
      { numRuns: 10_000 },
    );
  });

  it("the targeted attacks: puppet approver, puppet creator, remove-then-create, re-add", () => {
    const wait = (days: number): Op => ({ kind: "wait", hours: days * 24 });
    const scenarios: Op[][] = [
      // A: invite a puppet, let it age, create, puppet approves
      [
        { kind: "invite" },
        wait(8),
        { kind: "create", by: 0 },
        { kind: "attest", dest: 0 },
        { kind: "approve", dest: 0, by: 1 },
        wait(2),
        { kind: "activate", dest: 0 },
      ],
      // A': the puppet creates, the attacker's own session approves
      [
        { kind: "invite" },
        wait(8),
        { kind: "create", by: 1 },
        { kind: "attest", dest: 0 },
        { kind: "approve", dest: 0, by: 0 },
        wait(2),
        { kind: "activate", dest: 0 },
      ],
      // B: remove the honest manager, create (alone), attest, activate
      [
        { kind: "remove", who: 1 },
        { kind: "create", by: 0 },
        { kind: "attest", dest: 0 },
        wait(2),
        { kind: "activate", dest: 0 },
      ],
      // B': remove, invite a puppet, wait, create, approve
      [
        { kind: "remove", who: 1 },
        { kind: "invite" },
        wait(9),
        { kind: "create", by: 0 },
        { kind: "attest", dest: 0 },
        { kind: "approve", dest: 0, by: 1 },
        wait(2),
        { kind: "activate", dest: 0 },
      ],
      // demote the honest manager instead of removing
      [
        { kind: "demote", who: 1 },
        { kind: "create", by: 0 },
        { kind: "attest", dest: 0 },
        wait(2),
        { kind: "activate", dest: 0 },
      ],
    ];
    for (const ops of scenarios)
      for (const d of attack(1, ops, DAY)) expect(d.status).not.toMatch(/active|cooling_off/);
  });

  it("is not vacuous: two honest tenured managers complete it, and a new two-founder team does after 7 days", () => {
    const ctx = (grants: ManagerGrant[], createdAt: number, now: number) => ({
      createdAt,
      now,
      cooloffMs: DAY,
      grants,
    });
    const team = tenuredTeam(2, 0);
    const out = decide(
      {
        ...ctx(team, T0 - DAY, T0),
        status: "pending_approval",
        required: 2,
        createdBy: "u0",
        approvals: [{ userId: "u0", decision: "approve" }],
      },
      "u1",
      "approve",
    );
    expect(out).toMatchObject({ ok: true, to: "cooling_off" });
    // founder signs up at T0, invites a co-founder at T0 + 1 d, creates at T0 + 2 d; approval at T0 + 8 d
    let g = applyRoleChange([], "f", false, true, T0);
    g = applyRoleChange(g, "c", false, true, T0 + DAY);
    expect(recentManagers(g, T0 + DAY)).toHaveLength(2);
    const founders = decide(
      {
        ...ctx(g, T0 + 2 * DAY, T0 + 8 * DAY),
        status: "pending_approval",
        required: 2,
        createdBy: "f",
        approvals: [{ userId: "f", decision: "approve" }],
      },
      "c",
      "approve",
    );
    expect(founders).toMatchObject({ ok: true, to: "cooling_off" });
  });
});

// ---------------------------------------------------------------------------------------------
// Restricted keys
// ---------------------------------------------------------------------------------------------

const scopeSet = fc.subarray([...KEY_SCOPES]);
const junk = fc.array(fc.constantFrom("admin", "destinations.write", "payment_intents.delete", "*", ""), {
  maxLength: 3,
});
const routeAuth = fc.constantFrom(...PUBLIC_ROUTES.map((r) => r.auth));

/** Reference: a route accepts a restricted key holding `held` iff it names a held scope, or the write of a read scope. */
function reference(auth: readonly string[], held: readonly string[]) {
  return auth.some((a) => {
    if (!a.startsWith("restricted_key:")) return false;
    const s = a.slice("restricted_key:".length);
    return held.includes(s) || (s.endsWith(".read") && held.includes(`${s.slice(0, -5)}.write`));
  });
}

describe("restricted-key scope evaluation", () => {
  it("matches the reference rule (write implies read) on every spec route, and the kit agrees", () => {
    fc.assert(
      fc.property(scopeSet, junk, routeAuth, (scopes, extra, auth) => {
        const expanded = expandScopes([...scopes, ...extra], KEY_SCOPES);
        const ok = restrictedAllows(auth, expanded);
        expect(ok).toBe(reference(auth, scopes));
        const route = { id: "r", auth, visibility: "public" } as unknown as Parameters<typeof authorizeRoute>[1];
        let kit = true;
        try {
          authorizeRoute(
            { sub: "key_x", ptype: "restricted_key", scp: expanded, iss: "", aud: "", iat: 0, exp: 0 } as never,
            route,
          );
        } catch {
          kit = false;
        }
        expect(kit).toBe(ok);
      }),
    );
  });

  it("expansion only ever yields catalogue scopes, is idempotent and monotonic", () => {
    fc.assert(
      fc.property(scopeSet, scopeSet, junk, routeAuth, (a, b, extra, auth) => {
        const ea = expandScopes([...a, ...extra], KEY_SCOPES);
        for (const s of ea) expect(KEY_SCOPES as readonly string[]).toContain(s);
        expect(expandScopes(ea, KEY_SCOPES)).toEqual(ea);
        const union = expandScopes([...a, ...b], KEY_SCOPES);
        if (restrictedAllows(auth, ea)) expect(restrictedAllows(auth, union)).toBe(true);
      }),
    );
  });

  it("validation accepts exactly non-empty catalogue subsets for restricted keys, and no scopes for the others", () => {
    fc.assert(
      fc.property(
        scopeSet,
        junk,
        fc.constantFrom("secret", "publishable", "restricted") as fc.Arbitrary<"secret" | "publishable" | "restricted">,
        (scopes, extra, type) => {
          const given = [...scopes, ...extra];
          const r = checkScopes(type, given, KEY_SCOPES);
          if (type !== "restricted") expect(r.ok).toBe(given.length === 0);
          else if (given.length === 0) expect(r).toMatchObject({ ok: false, error: "invalid_request" });
          else if (extra.length) expect(r).toMatchObject({ ok: false, error: "scope_unknown" });
          else expect(r).toEqual({ ok: true, scopes: [...new Set(scopes)].sort() });
        },
      ),
    );
  });
});

// ---------------------------------------------------------------------------------------------
// Console session expiry
// ---------------------------------------------------------------------------------------------

describe("console session expiry", () => {
  const T0 = Date.UTC(2026, 10, 7);
  it("valid iff not revoked, within 12 h of creation and active within the last 30 minutes, whatever the activity", () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 0, max: 20 * 3_600_000 }), { maxLength: 40 }),
        fc.integer({ min: 0, max: 20 * 3_600_000 }),
        fc.boolean(),
        (activity, at, revoked) => {
          // activity only counts while the session is valid (authz touches valid sessions only)
          let lastSeen = T0;
          const expires = new Date(T0 + OPS_ABSOLUTE_MS);
          for (const a of [...activity].sort((x, y) => x - y)) {
            const t = T0 + a;
            if (
              sessionState({ expires_at: expires, last_seen_at: new Date(lastSeen), revoked_at: null }, t, "ops") ===
              "valid"
            )
              lastSeen = t;
          }
          const now = T0 + Math.max(at, lastSeen - T0);
          const s = {
            expires_at: expires,
            last_seen_at: new Date(lastSeen),
            revoked_at: revoked ? new Date(T0) : null,
          };
          const valid = sessionState(s, now, "ops") === "valid";
          expect(valid).toBe(!revoked && now < T0 + OPS_ABSOLUTE_MS && now - lastSeen <= OPS_IDLE_MS);
          if (now >= T0 + OPS_ABSOLUTE_MS) expect(valid).toBe(false);
          expect(idleExpiresAt(s, "ops").getTime()).toBeLessThanOrEqual(expires.getTime());
          if (valid) expect(idleExpiresAt(s, "ops").getTime()).toBeGreaterThanOrEqual(now);
        },
      ),
    );
  });

  it("the console idle limit is never longer than the dashboard's", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 13 * 3_600_000 }), (idle) => {
        const s = { expires_at: new Date(T0 + 7 * 86_400_000), last_seen_at: new Date(T0), revoked_at: null };
        if (sessionState(s, T0 + idle, "ops") === "valid")
          expect(sessionState(s, T0 + idle, "dashboard")).toBe("valid");
      }),
    );
  });
});

// ---------------------------------------------------------------------------------------------
// Last owner
// ---------------------------------------------------------------------------------------------

describe("team rules", () => {
  const role = fc.constantFrom<Role>("owner", "admin", "developer", "finance", "support", "viewer");
  it("no sequence of allowed role changes and removals leaves an account without an owner", () => {
    fc.assert(
      fc.property(
        fc.array(role, { minLength: 1, maxLength: 6 }),
        fc.array(fc.record({ actor: fc.nat(5), target: fc.nat(5), op: fc.constantFrom("change", "remove"), role }), {
          maxLength: 30,
        }),
        (initial, ops) => {
          const members = new Map<number, Role>(initial.map((r, i) => [i, r]));
          members.set(0, "owner");
          for (const o of ops) {
            const actor = members.get(o.actor);
            const target = members.get(o.target);
            if (!actor || !target) continue;
            const owners = [...members.values()].filter((r) => r === "owner").length;
            if (o.op === "change") {
              if (canChangeRole(actor, target, o.role, owners).ok) members.set(o.target, o.role);
            } else if (canRemove(actor, target, owners).ok) members.delete(o.target);
            expect([...members.values()].filter((r) => r === "owner").length).toBeGreaterThanOrEqual(1);
          }
        },
      ),
    );
  });
});

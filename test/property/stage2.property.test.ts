/**
 * Stage 2 properties (lld/identity.md §15): the two-approver rule, restricted-key scope evaluation,
 * console session expiry and the last-owner rule.
 */
import { KEY_SCOPES, PUBLIC_ROUTES } from "@nearpay/spec";
import { authorizeRoute } from "@nearpay-internal/auth";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { checkScopes, expandScopes, restrictedAllows } from "../../src/domain/api-key/key.js";
import {
  type ApprovalRecord,
  afterAttestation,
  approvedBy,
  type Decision,
  decide,
} from "../../src/domain/approval/approval.js";
import { idleExpiresAt, OPS_ABSOLUTE_MS, OPS_IDLE_MS, sessionState } from "../../src/domain/session/session.js";
import { approvalsRequired } from "../../src/domain/settlement-destination/destination.js";
import { canChangeRole, canRemove, type Role } from "../../src/domain/team/team.js";

// ---------------------------------------------------------------------------------------------
// Two-approver rule
// ---------------------------------------------------------------------------------------------

type Step = { kind: "attest" } | { kind: "decide"; by: number; decision: Decision };

/** Runs a destination through attestation and decisions; returns the trace of statuses and approvals. */
function run(managers: number, creator: number, steps: readonly Step[]) {
  const required = approvalsRequired(managers, true);
  let status = "pending_verification";
  let approvals: ApprovalRecord[] = [{ userId: `u${creator}`, decision: "approve" }];
  const trace: { status: string; approvals: ApprovalRecord[] }[] = [];
  for (const st of steps) {
    if (status === "disabled" || status === "cooling_off") break;
    if (st.kind === "attest") {
      if (status === "pending_verification") status = afterAttestation(required, approvals);
    } else {
      const out = decide({ status, required, createdBy: `u${creator}`, approvals }, `u${st.by}`, st.decision);
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

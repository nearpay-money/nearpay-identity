import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { generateKey, parseKey } from "../../src/domain/api-key/key.js";
import { takeToken } from "../../src/domain/authz/authz.js";
import {
  type Command,
  type DestinationStatus,
  transition,
} from "../../src/domain/settlement-destination/destination.js";

describe("destination lifecycle properties", () => {
  const command = fc.constantFrom<Command>("challenge", "attest", "approve", "activate", "disable", "set_default");
  it("a destination is active only via attestation (and the cool-off, when one is set); disabled is terminal", () => {
    fc.assert(
      fc.property(
        fc.array(command, { maxLength: 30 }),
        fc.integer({ min: 1, max: 2 }),
        fc.boolean(),
        (cmds, approvals, cooloff) => {
          let s: DestinationStatus = "pending_verification";
          let attested = false;
          let cooled = false;
          for (const c of cmds) {
            const r = transition(s, c, { approvalsRequired: approvals, cooloff });
            if (!r.ok) {
              expect(r.state).toBe(s);
              continue;
            }
            if (s === "disabled") throw new Error("left disabled");
            if (c === "challenge") expect([s, r.to]).toEqual(["pending_verification", "pending_verification"]);
            if (c === "attest") attested = true;
            if (r.to === "cooling_off") cooled = true;
            // without a cool-off (the default, owner decision 2026-11-11) nothing ever cools off
            if (!cooloff) expect(r.to).not.toBe("cooling_off");
            // two approvers: never active straight from the attestation
            if (approvals > 1 && c === "attest") expect(r.to).toBe("pending_approval");
            s = r.to;
            if (s === "active") expect(attested && (cooled || !cooloff)).toBe(true);
          }
        },
      ),
    );
  });
});

describe("API key properties", () => {
  it("every generated key parses back to its type and mode, and keys do not repeat", () => {
    const seen = new Set<string>();
    fc.assert(
      fc.property(
        fc.constantFrom("secret" as const, "publishable" as const, "restricted" as const),
        fc.boolean(),
        (t, lm) => {
          const k = generateKey(t, lm);
          expect(parseKey(k)).toEqual({ type: t, livemode: lm });
          expect(seen.has(k)).toBe(false);
          seen.add(k);
        },
      ),
    );
  });
});

describe("rate limiter properties", () => {
  it("admits at most burst + rate × elapsed requests", () => {
    fc.assert(
      fc.property(
        fc.record({ rate: fc.integer({ min: 1, max: 200 }), burst: fc.integer({ min: 1, max: 400 }) }),
        fc.array(fc.integer({ min: 0, max: 250 }), { minLength: 1, maxLength: 300 }),
        (b, gaps) => {
          let state: Parameters<typeof takeToken>[0];
          let t = 0;
          let admitted = 0;
          for (const g of gaps) {
            t += g;
            const r = takeToken(state, b, t);
            state = r.state;
            if (r.allowed) admitted++;
            else expect(r.retryAfter).toBeGreaterThanOrEqual(1);
          }
          expect(admitted).toBeLessThanOrEqual(b.burst + Math.floor((b.rate * t) / 1000) + 1);
        },
      ),
    );
  });
});

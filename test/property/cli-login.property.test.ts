/**
 * CLI login state machine (lld/identity.md §6.2): random interleavings of time, approvals, denials,
 * polls and the expiry job, driven through the same domain functions the use cases call.
 */
import { CLI_LOGIN_POLL_INTERVAL_SECONDS, CLI_LOGIN_TTL_SECONDS } from "@nearpay-money/spec";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  type CliLoginStatus,
  decide,
  effectiveStatus,
  generateUserCode,
  POLL_JITTER_MS,
  pollOutcome,
  pollPace,
  REDEEM_WINDOW_MS,
  USER_CODE_ALPHABET,
  visibleTo,
} from "../../src/domain/cli-login/cli-login.js";

type Ev =
  | { kind: "advance"; ms: number }
  | { kind: "approve"; account: "A" | "B" }
  | { kind: "deny"; account: "A" | "B" }
  | { kind: "poll" }
  | { kind: "job" };

const ev: fc.Arbitrary<Ev> = fc.oneof(
  fc.record({ kind: fc.constant("advance" as const), ms: fc.integer({ min: 0, max: 600_000 }) }),
  fc.record({ kind: fc.constant("approve" as const), account: fc.constantFrom("A" as const, "B" as const) }),
  fc.record({ kind: fc.constant("deny" as const), account: fc.constantFrom("A" as const, "B" as const) }),
  fc.constant({ kind: "poll" as const }),
  fc.constant({ kind: "job" as const }),
);

const TERMINAL: readonly CliLoginStatus[] = ["denied", "expired", "redeemed"];

describe("CLI login lifecycle", () => {
  it("a key is delivered at most once, only after an approval in time and within the redeem window; terminal states stay", () => {
    fc.assert(
      fc.property(fc.array(ev, { maxLength: 60 }), (events) => {
        const t0 = 1_800_000_000_000;
        let now = t0;
        const l = {
          status: "pending" as CliLoginStatus,
          expires_at: new Date(t0 + CLI_LOGIN_TTL_SECONDS * 1000),
          decided_at: null as Date | null,
          account_id: null as string | null,
          revoked: false,
        };
        let delivered = 0;
        for (const e of events) {
          const before = l.status;
          if (e.kind === "advance") now += e.ms;
          else if (e.kind === "approve" || e.kind === "deny") {
            const d = decide(l, e.kind, now);
            if (d.ok) {
              expect(before).toBe("pending");
              expect(now).toBeLessThan(l.expires_at.getTime());
              l.status = d.to;
              l.decided_at = new Date(now);
              l.account_id = e.account;
            } else expect(d.state).toBe(effectiveStatus(l, now));
          } else if (e.kind === "poll") {
            const o = pollOutcome(l, now);
            if (o.redeem) {
              expect(l.status).toBe("approved");
              expect(l.revoked).toBe(false);
              expect(now).toBeLessThan((l.decided_at as Date).getTime() + REDEEM_WINDOW_MS);
              delivered++;
              l.status = "redeemed";
            }
          } else {
            // cli_logins.expire
            if (l.status === "pending" && now >= l.expires_at.getTime()) l.status = "expired";
            if (l.status === "approved" && now >= (l.decided_at as Date).getTime() + REDEEM_WINDOW_MS) {
              l.status = "expired";
              l.revoked = true;
            }
          }
          if (TERMINAL.includes(before)) expect(l.status).toBe(before);
          expect(delivered).toBeLessThanOrEqual(1);
          // the job never disagrees with what readers already see
          if (e.kind === "job") expect(effectiveStatus(l, now)).toBe(l.status);
          // a decided login is never visible to the other account
          if (l.account_id) expect(visibleTo(l, l.account_id === "A" ? "B" : "A", now)).toBe(false);
        }
        if (delivered === 1) expect(l.status).toBe("redeemed");
      }),
    );
  });

  it("slow_down: accepted polls are ≥ interval − jitter apart, and waiting Retry-After always succeeds", () => {
    fc.assert(
      fc.property(fc.array(fc.integer({ min: 0, max: 12_000 }), { minLength: 1, maxLength: 80 }), (gaps) => {
        let now = 0;
        let last: Date | null = null;
        for (const g of gaps) {
          now += g;
          const p = pollPace(last, now, CLI_LOGIN_POLL_INTERVAL_SECONDS);
          if (p.ok) {
            if (last)
              expect(now - last.getTime()).toBeGreaterThanOrEqual(
                CLI_LOGIN_POLL_INTERVAL_SECONDS * 1000 - POLL_JITTER_MS,
              );
            last = new Date(now);
          } else {
            expect(p.retryAfter).toBeGreaterThanOrEqual(1);
            expect(p.retryAfter).toBeLessThanOrEqual(CLI_LOGIN_POLL_INTERVAL_SECONDS);
            expect(pollPace(last, now + p.retryAfter * 1000, CLI_LOGIN_POLL_INTERVAL_SECONDS).ok).toBe(true);
          }
        }
      }),
    );
  });

  it("user codes are uniform over the alphabet (no modulo bias)", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 64, maxLength: 64 }), (bytes) => {
        let used = 0;
        const code = generateUserCode((n) => {
          const out = Buffer.from(bytes.subarray(used, used + n));
          used += n;
          return out.length === n ? out : Buffer.alloc(n, 0);
        });
        const accepted = [...bytes].filter((b) => b < 240).slice(0, 8);
        if (accepted.length === 8 && bytes.slice(0, 16).filter((b) => b < 240).length >= 8)
          expect(code.replace("-", "")).toBe(accepted.map((b) => USER_CODE_ALPHABET[b % 20]).join(""));
        expect(code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
      }),
    );
    // 240 = 12 × 20: every accepted byte value maps to each letter exactly 12 times
    const counts = new Map<string, number>();
    for (let b = 0; b < 240; b++)
      counts.set(USER_CODE_ALPHABET[b % 20] as string, (counts.get(USER_CODE_ALPHABET[b % 20] as string) ?? 0) + 1);
    expect([...counts.values()]).toEqual(Array(20).fill(12));
  });
});

import { CLI_LOGIN_POLL_INTERVAL_SECONDS, CliUserCode } from "@nearpay/spec";
import { describe, expect, it } from "vitest";
import {
  type CliLoginState,
  cleanCountry,
  cleanText,
  cliKeyName,
  DEVICE_CODE_RE,
  decide,
  deviceCodeHash,
  effectiveStatus,
  expiredAt,
  generateDeviceCode,
  generateUserCode,
  POLL_JITTER_MS,
  pollOutcome,
  pollPace,
  REDEEM_WINDOW_MS,
  USER_CODE_RE,
  VISIBLE_AFTER_EXPIRY_MS,
  visibleTo,
} from "../../src/domain/cli-login/cli-login.js";

const T0 = Date.UTC(2026, 10, 8, 12, 0, 0);
const EXP = new Date(T0 + 900_000);
const login = (o: Partial<CliLoginState & { account_id: string | null }> = {}) => ({
  status: "pending" as const,
  expires_at: EXP,
  decided_at: null,
  account_id: null,
  ...o,
});

describe("codes", () => {
  it("user codes are XXXX-XXXX from the spec alphabet", () => {
    for (let i = 0; i < 500; i++) {
      const c = generateUserCode();
      expect(c).toMatch(USER_CODE_RE);
      expect(CliUserCode.safeParse(c).success).toBe(true);
    }
  });

  it("user codes use rejection sampling: bytes ≥ 240 are skipped, others map mod 20", () => {
    let call = 0;
    const random = (n: number) => {
      call++;
      // first draw: all rejected; second: 0..15 → B…T
      return call === 1 ? Buffer.alloc(n, 250) : Buffer.from(Array.from({ length: n }, (_, i) => i));
    };
    expect(generateUserCode(random)).toBe("BCDF-GHJK");
    expect(call).toBe(2);
  });

  it("device codes are npdc_ + 43 base62 (≥ 256 bits) and hash to 32 bytes", () => {
    const a = generateDeviceCode();
    expect(a).toMatch(DEVICE_CODE_RE);
    expect(a).not.toBe(generateDeviceCode());
    expect(deviceCodeHash(a)).toHaveLength(32);
    expect(deviceCodeHash(a).equals(deviceCodeHash(a))).toBe(true);
    expect(43 * Math.log2(62)).toBeGreaterThanOrEqual(256);
  });
});

describe("status", () => {
  it("pending reads as expired from expires_at on", () => {
    expect(effectiveStatus(login(), T0)).toBe("pending");
    expect(effectiveStatus(login(), EXP.getTime() - 1)).toBe("pending");
    expect(effectiveStatus(login(), EXP.getTime())).toBe("expired");
  });

  it("an approval reads as expired once its redeem window is over", () => {
    const l = login({ status: "approved", decided_at: new Date(T0 + 60_000) });
    expect(effectiveStatus(l, T0 + 60_000 + REDEEM_WINDOW_MS - 1)).toBe("approved");
    expect(effectiveStatus(l, T0 + 60_000 + REDEEM_WINDOW_MS)).toBe("expired");
    // approved without a decision time (not written by the app) stays approved
    expect(effectiveStatus(login({ status: "approved" }), T0 + 10 * REDEEM_WINDOW_MS)).toBe("approved");
  });

  it("terminal statuses read as stored", () => {
    for (const status of ["denied", "expired", "redeemed"] as const)
      expect(effectiveStatus(login({ status, decided_at: new Date(T0) }), T0 + 99 * REDEEM_WINDOW_MS)).toBe(status);
  });

  it("expiredAt: expiry for pending logins, the window end for uncollected approvals", () => {
    expect(expiredAt(login())).toBe(EXP.getTime());
    expect(expiredAt(login({ status: "expired" }))).toBe(EXP.getTime());
    expect(expiredAt(login({ status: "denied", decided_at: new Date(T0) }))).toBe(EXP.getTime());
    expect(expiredAt(login({ status: "expired", decided_at: new Date(T0 + 840_000) }))).toBe(
      T0 + 840_000 + REDEEM_WINDOW_MS,
    );
    // a decision can never make it end before the login's own expiry
    expect(expiredAt(login({ status: "expired", decided_at: new Date(T0 - 999_999) }))).toBe(EXP.getTime());
  });
});

describe("decide", () => {
  it("approve/deny only while pending and unexpired", () => {
    expect(decide(login(), "approve", T0)).toEqual({ ok: true, to: "approved" });
    expect(decide(login(), "deny", T0)).toEqual({ ok: true, to: "denied" });
    expect(decide(login(), "approve", EXP.getTime())).toEqual({ ok: false, state: "expired" });
    for (const status of ["approved", "denied", "expired", "redeemed"] as const)
      expect(decide(login({ status, decided_at: new Date(T0) }), "approve", T0)).toEqual({ ok: false, state: status });
  });
});

describe("poll", () => {
  it("hands the key out only from approved (within the window)", () => {
    const approved = login({ status: "approved", decided_at: new Date(T0) });
    expect(pollOutcome(approved, T0 + 1)).toEqual({ status: "approved", redeem: true });
    expect(pollOutcome(approved, T0 + REDEEM_WINDOW_MS)).toEqual({ status: "expired", redeem: false });
    expect(pollOutcome(login(), T0)).toEqual({ status: "pending", redeem: false });
    expect(pollOutcome(login({ status: "redeemed", decided_at: new Date(T0) }), T0)).toEqual({
      status: "redeemed",
      redeem: false,
    });
  });

  it("slow_down: faster than the interval (minus jitter) is refused with the seconds left", () => {
    const i = CLI_LOGIN_POLL_INTERVAL_SECONDS;
    expect(pollPace(null, T0, i)).toEqual({ ok: true });
    const last = new Date(T0);
    expect(pollPace(last, T0 + i * 1000, i)).toEqual({ ok: true });
    expect(pollPace(last, T0 + i * 1000 - POLL_JITTER_MS, i)).toEqual({ ok: true });
    expect(pollPace(last, T0 + i * 1000 - POLL_JITTER_MS - 1, i)).toEqual({ ok: false, retryAfter: 2 });
    expect(pollPace(last, T0, i)).toEqual({ ok: false, retryAfter: 5 });
    expect(pollPace(last, T0 + 4_500 - POLL_JITTER_MS, i)).toEqual({ ok: false, retryAfter: 2 });
    // a clock that went backwards still answers a positive wait
    expect(pollPace(last, T0 - 10_000, i)).toEqual({ ok: false, retryAfter: 15 });
  });
});

describe("visibility (getCliLogin)", () => {
  const A = "acct-a";
  const B = "acct-b";
  it("pending logins: any signed-in account (the user code is the capability)", () => {
    expect(visibleTo(login(), A, T0)).toBe(true);
    expect(visibleTo(login(), B, T0)).toBe(true);
  });
  it("decided logins: only the deciding account", () => {
    for (const status of ["approved", "denied", "redeemed"] as const) {
      const l = login({ status, decided_at: new Date(T0), account_id: A });
      expect(visibleTo(l, A, T0 + 1)).toBe(true);
      expect(visibleTo(l, B, T0 + 1)).toBe(false);
    }
  });
  it("expired logins: visible for 24 h after expiry (undecided: to anyone; uncollected: to its account)", () => {
    const undecided = login();
    expect(visibleTo(undecided, B, EXP.getTime() + VISIBLE_AFTER_EXPIRY_MS - 1)).toBe(true);
    expect(visibleTo(undecided, B, EXP.getTime() + VISIBLE_AFTER_EXPIRY_MS)).toBe(false);
    const uncollected = login({ status: "expired", decided_at: new Date(T0), account_id: A });
    const end = T0 + REDEEM_WINDOW_MS;
    expect(visibleTo(uncollected, A, end + VISIBLE_AFTER_EXPIRY_MS - 1)).toBe(true);
    expect(visibleTo(uncollected, B, end)).toBe(false);
    expect(visibleTo(uncollected, A, end + VISIBLE_AFTER_EXPIRY_MS)).toBe(false);
  });
});

describe("metadata", () => {
  it("key name, text and country cleaning", () => {
    expect(cliKeyName("adarsh-mbp")).toBe("CLI · adarsh-mbp");
    expect(cleanText(undefined, 10)).toBeNull();
    expect(cleanText(null, 10)).toBeNull();
    expect(cleanText(" \u0007\n ", 10)).toBeNull();
    expect(cleanText("a\u0000b\u001bc", 10)).toBe("abc");
    expect(cleanText("x".repeat(300), 256)).toHaveLength(256);
    expect(cleanCountry("de")).toBe("DE");
    expect(cleanCountry("T1")).toBe("T1");
    expect(cleanCountry("DEU")).toBeNull();
    expect(cleanCountry(undefined)).toBeNull();
  });
});

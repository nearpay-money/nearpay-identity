import { describe, expect, it } from "vitest";
import {
  displayPrefix,
  generateKey,
  ipAllowed,
  KEY_RE,
  keyHash,
  last4,
  parseKey,
  randomBase62,
} from "../../src/domain/api-key/key.js";
import {
  ABSOLUTE_MS,
  clearCookie,
  matchesHash,
  newSecret,
  readCookie,
  SESSION_COOKIE,
  SLIDING_MS,
  STEP_UP_MS,
  sessionState,
  setCookie,
  sha256,
  stepUpUntil,
} from "../../src/domain/session/session.js";

describe("API keys", () => {
  it("generates and parses every type and mode", () => {
    for (const type of ["secret", "publishable", "restricted"] as const)
      for (const livemode of [true, false]) {
        const k = generateKey(type, livemode);
        expect(k).toMatch(KEY_RE);
        expect(k.startsWith(displayPrefix(type, livemode))).toBe(true);
        expect(parseKey(k)).toEqual({ type, livemode });
      }
    expect(displayPrefix("secret", true)).toBe("sk_live_");
    expect(displayPrefix("publishable", false)).toBe("pk_test_");
  });
  it("rejects malformed keys", () => {
    for (const bad of [
      "sk_live_short",
      "xk_live_" + "a".repeat(48),
      "sk_prod_" + "a".repeat(48),
      "sk_live_" + "a".repeat(47) + "!",
      "",
    ])
      expect(parseKey(bad)).toBeNull();
  });
  it("hashes with SHA-256 and shows the last four characters", () => {
    const k = generateKey("secret", false);
    expect(keyHash(k)).toHaveLength(32);
    expect(keyHash(k).equals(keyHash(k))).toBe(true);
    expect(last4(k)).toBe(k.slice(-4));
  });
  it("rejection-samples base62 (bytes ≥ 248 are skipped)", () => {
    let call = 0;
    const random = (n: number) => {
      call++;
      return Buffer.from(Array.from({ length: n }, (_, i) => (call === 1 && i % 2 === 0 ? 250 : 61)));
    };
    expect(randomBase62(10, random)).toBe("z".repeat(10));
  });
  it("checks IP allowlists (v4, v6, mapped, invalid)", () => {
    expect(ipAllowed("1.2.3.4", [])).toBe(true);
    expect(ipAllowed(null, [])).toBe(true);
    expect(ipAllowed(null, ["10.0.0.0/8"])).toBe(false);
    expect(ipAllowed("10.1.2.3", ["10.0.0.0/8"])).toBe(true);
    expect(ipAllowed("11.1.2.3", ["10.0.0.0/8"])).toBe(false);
    expect(ipAllowed("::ffff:10.1.2.3", ["10.0.0.0/8"])).toBe(true);
    expect(ipAllowed("192.168.1.1", ["192.168.1.1/32"])).toBe(true);
    expect(ipAllowed("192.168.1.1", ["192.168.1.1"])).toBe(true);
    expect(ipAllowed("2001:db8::1", ["2001:db8::/32"])).toBe(true);
    expect(ipAllowed("2001:db9::1", ["2001:db8::/32"])).toBe(false);
    expect(ipAllowed("2001:db8::1", ["10.0.0.0/8"])).toBe(false);
    expect(ipAllowed("::1", ["::1/128"])).toBe(true);
    expect(ipAllowed("999.1.1.1", ["0.0.0.0/0"])).toBe(false);
    expect(ipAllowed("not-an-ip", ["0.0.0.0/0"])).toBe(false);
    expect(ipAllowed("1.2.3.4", ["1.2.3.0/33"])).toBe(false);
    expect(ipAllowed("1:2:3", ["::/0"])).toBe(false);
    expect(ipAllowed("1::2::3", ["::/0"])).toBe(false);
  });
});

describe("sessions", () => {
  const now = Date.UTC(2026, 10, 6, 12);
  const s = (over: Partial<{ expires_at: Date; last_seen_at: Date; revoked_at: Date | null }> = {}) => ({
    expires_at: new Date(now + ABSOLUTE_MS),
    last_seen_at: new Date(now),
    revoked_at: null,
    ...over,
  });
  it("valid, revoked, expired (absolute) and idle (sliding 12 h)", () => {
    expect(sessionState(s(), now)).toBe("valid");
    expect(sessionState(s({ revoked_at: new Date(now) }), now)).toBe("revoked");
    expect(sessionState(s({ expires_at: new Date(now) }), now)).toBe("expired");
    expect(sessionState(s({ last_seen_at: new Date(now - SLIDING_MS - 1) }), now)).toBe("idle");
    expect(sessionState(s({ last_seen_at: new Date(now - SLIDING_MS) }), now)).toBe("valid");
  });
  it("step-up is fresh for 10 minutes", () => {
    expect(stepUpUntil(null, now)).toBeUndefined();
    expect(stepUpUntil(new Date(now - 1000), now)).toBe(Math.floor((now - 1000 + STEP_UP_MS) / 1000));
    expect(stepUpUntil(new Date(now - STEP_UP_MS), now)).toBeUndefined();
  });
  it("cookies: __Host- attributes and strict parsing", () => {
    expect(setCookie(SESSION_COOKIE, "abc", 60)).toBe(
      "__Host-np_session=abc; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=60",
    );
    expect(clearCookie(SESSION_COOKIE)).toContain("Max-Age=0");
    const token = newSecret();
    expect(readCookie(`a=b; ${SESSION_COOKIE}=${token}; c=d`, SESSION_COOKIE)).toBe(token);
    expect(readCookie(`${SESSION_COOKIE}=bad value`, SESSION_COOKIE)).toBeUndefined();
    expect(readCookie("junk; other=x", SESSION_COOKIE)).toBeUndefined();
    expect(readCookie(undefined, SESSION_COOKIE)).toBeUndefined();
  });
  it("compares secrets to hashes in constant time", () => {
    const t = newSecret();
    expect(matchesHash(t, sha256(t))).toBe(true);
    expect(matchesHash(`${t}x`, sha256(t))).toBe(false);
    expect(matchesHash(undefined, sha256(t))).toBe(false);
    expect(matchesHash(t, Buffer.alloc(3))).toBe(false);
  });
});

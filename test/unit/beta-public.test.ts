/** Public beta (Cloudflare → cloudflared → Traefik): client IP trust, server-stage Turnstile and WebAuthn rules. */
import { describe, expect, it } from "vitest";
import { checkServerConfig, isTurnstileTestSecret } from "../../src/config.js";
import { clientIp } from "../../src/domain/authz/authz.js";
import {
  clientIpRule,
  DEFAULT_TRUSTED_PROXIES,
  normalizeIp,
  resolveClientIp,
  trustedProxies,
} from "../../src/domain/client-ip.js";

describe("client IP behind the gateway", () => {
  const server = clientIpRule("server");
  const local = clientIpRule("local");

  it("server stage: CF-Connecting-IP from a trusted peer (Traefik on the Docker network)", () => {
    expect(server.header).toBe("cf-connecting-ip");
    expect(
      resolveClientIp(server, { peer: "172.18.0.5", cfConnectingIp: "203.0.113.7", xForwardedFor: "6.6.6.6" }),
    ).toBe("203.0.113.7");
    expect(resolveClientIp(server, { peer: "::ffff:172.18.0.5", cfConnectingIp: "2001:db8::1" })).toBe("2001:db8::1");
    // a client-supplied X-Forwarded-For never counts on the server stage
    expect(resolveClientIp(server, { peer: "172.18.0.5", xForwardedFor: "6.6.6.6" })).toBeNull();
  });

  it("an untrusted peer is the client itself: its headers are ignored", () => {
    expect(resolveClientIp(server, { peer: "198.51.100.9", cfConnectingIp: "1.2.3.4", xForwardedFor: "5.6.7.8" })).toBe(
      "198.51.100.9",
    );
    expect(resolveClientIp(local, { peer: "198.51.100.9", xForwardedFor: "5.6.7.8" })).toBe("198.51.100.9");
  });

  it("local: the rightmost X-Forwarded-For hop that is not a trusted proxy (never the client's own leftmost)", () => {
    expect(local.header).toBe("x-forwarded-for");
    expect(resolveClientIp(local, { peer: "127.0.0.1", xForwardedFor: "6.6.6.6, 203.0.113.7, 172.18.0.3" })).toBe(
      "203.0.113.7",
    );
    expect(resolveClientIp(local, { peer: "127.0.0.1", xForwardedFor: "10.0.0.8, 172.18.0.3" })).toBe("10.0.0.8");
    expect(resolveClientIp(local, { peer: "127.0.0.1", xForwardedFor: "evil, 172.18.0.3" })).toBeNull();
    expect(resolveClientIp(local, { peer: "127.0.0.1" })).toBeNull();
  });

  it("configurable: header and proxy list (exact cloudflared/Traefik addresses)", () => {
    const rule = clientIpRule("server", {
      header: "x-forwarded-for",
      trustedProxies: ["172.30.0.250", "172.30.0.2/32"],
    });
    expect(resolveClientIp(rule, { peer: "172.30.0.2", xForwardedFor: "6.6.6.6, 203.0.113.7, 172.30.0.250" })).toBe(
      "203.0.113.7",
    );
    // another container on the network is not a trusted proxy any more
    expect(resolveClientIp(rule, { peer: "172.30.0.9", xForwardedFor: "203.0.113.7" })).toBe("172.30.0.9");
    expect(() => trustedProxies(["nope"])).toThrow(/NP_TRUSTED_PROXIES/);
    expect(() => trustedProxies(["10.0.0.0/33"])).toThrow(/prefix/);
    expect(() => trustedProxies(["::/129"])).toThrow(/prefix/);
    expect(() => trustedProxies(DEFAULT_TRUSTED_PROXIES)).not.toThrow();
  });

  it("normalizes mapped IPv4 and refuses non-IPs; clientIp keeps the stage defaults", () => {
    expect(normalizeIp("::FFFF:192.0.2.1")).toBe("192.0.2.1");
    expect(normalizeIp(" <script> ")).toBeNull();
    expect(normalizeIp(undefined)).toBeNull();
    expect(clientIp("server", { peer: "10.1.2.3", cfConnectingIp: "192.0.2.4" })).toBe("192.0.2.4");
    expect(clientIp("staging", { cfConnectingIp: "192.0.2.4", xForwardedFor: "9.9.9.9" })).toBe("192.0.2.4");
  });
});

describe("server-stage configuration", () => {
  const ok = {
    env: "server",
    turnstileSecret: "0x4AAAAAAAreal-secret",
    webauthnRpId: "nearpay.money",
    webauthnOrigins: ["https://dashboard.nearpay.money", "https://ops.nearpay.money"],
    dashboardOrigin: "https://dashboard.nearpay.money",
    opsOrigin: "https://ops.nearpay.money",
  } as const;
  const check = (o: Partial<Record<keyof typeof ok, unknown>>) => () =>
    checkServerConfig({ ...ok, ...o } as Parameters<typeof checkServerConfig>[0]);

  it("accepts the nearpay.money setup, and anything locally", () => {
    expect(check({})).not.toThrow();
    expect(
      check({
        env: "local",
        turnstileSecret: "1x0000000000000000000000000000000AA",
        webauthnRpId: "nearpay.localhost",
      }),
    ).not.toThrow();
  });
  it("refuses Cloudflare test secrets", () => {
    expect(isTurnstileTestSecret("1x0000000000000000000000000000000AA")).toBe(true);
    expect(isTurnstileTestSecret("3x0000000000000000000000000000000AA")).toBe(true);
    expect(isTurnstileTestSecret("0x4AAAAAAA")).toBe(false);
    expect(check({ turnstileSecret: "2x0000000000000000000000000000000AA" })).toThrow(/test secret/);
  });
  it("refuses a localhost RP id, http or foreign origins, and a dashboard outside the origins", () => {
    expect(check({ webauthnRpId: "nearpay.localhost" })).toThrow(/NP_WEBAUTHN_RP_ID/);
    expect(check({ webauthnOrigins: ["http://dashboard.nearpay.money"] })).toThrow(/public https/);
    expect(check({ webauthnOrigins: ["https://dashboard.nearpay.money", "https://evil.example"] })).toThrow(
      /not under the RP id/,
    );
    expect(check({ webauthnOrigins: ["https://ops.nearpay.money"] })).toThrow(/include NP_DASHBOARD_ORIGIN/);
    expect(check({ opsOrigin: "https://ops.nearpay.localhost" })).toThrow(/NP_OPS_ORIGIN/);
  });
});

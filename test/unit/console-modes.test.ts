/**
 * Console auth settings (lld/identity.md §6.1): Cloudflare Access verification (app/console-access.ts),
 * the beta platform-passkey policy (domain/console/console.ts), their configuration and boot metrics,
 * and the destination cool-off gauge.
 */
import { generateKeyPairSync } from "node:crypto";
import { createMetrics, loadConfig } from "@nearpay-internal/service";
import { createLocalJWKSet, exportJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { announceConsole, announceCooloff, betaFlagValues } from "../../src/app/boot.js";
import { accessSignInEventId } from "../../src/app/console.js";
import {
  ACCESS_REAUTH_S,
  accessCsrf,
  accessCsrfValid,
  accessStepUpUntil,
  accessVerifier,
  normalizeTeamDomain,
  verifyAccess,
} from "../../src/app/console-access.js";
import { NO_CONSOLE } from "../../src/app/context.js";
import { apiShape, checkConsoleAuth, consoleConfig } from "../../src/config.js";
import { authenticatorProblem, platformPasskeyProblem } from "../../src/domain/console/console.js";

const TEAM = "nearpay.cloudflareaccess.com";
const AUD = "aud-tag-0123456789";
const NOW = 1_800_000_000;
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
const keys = createLocalJWKSet({ keys: [jwk] });
const v = accessVerifier({ teamDomain: TEAM, audience: AUD, csrfKey: Buffer.alloc(32, 7), keys });

async function token(
  o: { iat?: number; exp?: number; aud?: string; iss?: string; email?: string | null; key?: typeof privateKey } = {},
) {
  const claims: Record<string, unknown> = { type: "app", identity_nonce: "n" };
  if (o.email !== null) claims.email = o.email ?? "Owner@Example.com";
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(o.iss ?? `https://${TEAM}`)
    .setAudience(o.aud ?? AUD)
    .setSubject("cf-user")
    .setIssuedAt(o.iat ?? NOW - 60)
    .setExpirationTime(o.exp ?? NOW + 3600)
    .sign(o.key ?? privateKey);
}

describe("Cloudflare Access assertion", () => {
  it("accepts a valid RS256 token from the team for the audience; the email is normalised", async () => {
    expect(await verifyAccess(v, await token(), NOW)).toEqual({
      email: "owner@example.com",
      iat: NOW - 60,
      exp: NOW + 3600,
    });
  });

  it("refuses a missing, malformed, foreign-key, wrong-aud/iss, expired, not-yet-issued or email-less token", async () => {
    const bad = [
      undefined,
      "",
      "not.a.jwt",
      await token({ key: other.privateKey }),
      await token({ aud: "someone-else" }),
      await token({ iss: "https://evil.cloudflareaccess.com" }),
      await token({ iat: NOW - 7200, exp: NOW - 120 }),
      await token({ iat: NOW + 600 }),
      await token({ email: null }),
    ];
    for (const t of bad) expect(await verifyAccess(v, t, NOW)).toBeNull();
    // an HS256 token "signed" with the public key never passes (algorithm pinned)
    const hs = await new SignJWT({ email: "owner@example.com" })
      .setProtectedHeader({ alg: "HS256", kid: "k1" })
      .setIssuer(`https://${TEAM}`)
      .setAudience(AUD)
      .setIssuedAt(NOW - 60)
      .setExpirationTime(NOW + 60)
      .sign(new TextEncoder().encode("x".repeat(32)));
    expect(await verifyAccess(v, hs, NOW)).toBeNull();
  });

  it("re-authentication is fresh for 5 minutes after the Access login", () => {
    expect(accessStepUpUntil(NOW - 10, NOW)).toBe(NOW - 10 + ACCESS_REAUTH_S);
    expect(accessStepUpUntil(NOW - ACCESS_REAUTH_S, NOW)).toBeUndefined();
  });

  it("the CSRF token is bound to the operator and the login", () => {
    const t = accessCsrf(v, "usr_a", NOW);
    expect(accessCsrfValid(v, "usr_a", NOW, t)).toBe(true);
    expect(accessCsrfValid(v, "usr_b", NOW, t)).toBe(false);
    expect(accessCsrfValid(v, "usr_a", NOW + 1, t)).toBe(false);
    expect(accessCsrfValid(v, "usr_a", NOW, undefined)).toBe(false);
    expect(accessCsrfValid(v, "usr_a", NOW, `${t}x`)).toBe(false);
  });

  it("one sign-in audit event per Access login (deterministic uuid)", () => {
    const a = accessSignInEventId("0190a1b2-0000-7000-8000-000000000001", NOW);
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(accessSignInEventId("0190a1b2-0000-7000-8000-000000000001", NOW)).toBe(a);
    expect(accessSignInEventId("0190a1b2-0000-7000-8000-000000000001", NOW + 1)).not.toBe(a);
  });

  it("team domains: host names only (https:// and a trailing slash tolerated)", () => {
    expect(normalizeTeamDomain("https://NearPay.cloudflareaccess.com/")).toBe(TEAM);
    expect(() => normalizeTeamDomain("https://x/../y")).toThrow(/NP_CF_ACCESS_TEAM_DOMAIN/);
    expect(() => normalizeTeamDomain("localhost")).toThrow();
  });
});

describe("configuration", () => {
  const env = {
    NP_ENV: "test",
    NP_DB_URL_FILE: "/s/db",
    NP_PII_KEK_FILE: "/s/kek",
    NP_COMPLIANCE_URL: "http://compliance-api:8080",
    NP_VALKEY_URL: "redis://valkey:6379",
    NP_SERVICE_CLIENTS_FILE: "/s/clients",
    NP_TURNSTILE_SECRET_FILE: "/s/ts",
    NP_WEBAUTHN_ORIGINS: "https://dashboard.nearpay.localhost",
    NP_DASHBOARD_ORIGIN: "https://dashboard.nearpay.localhost",
    NP_RAILS_URL: "http://rails-api:8080",
    NP_NOTIFY_URL: "http://notify-api:8080",
    NP_NEAR_RPC_URLS: "https://rpc.mainnet.near.org",
  };
  const readFile = (p: string) =>
    p === "/s/db" ? "postgres://u:p@h:5432/d" : p === "/s/kek" ? Buffer.alloc(32, 1).toString("base64") : "x";
  const load = (extra: Record<string, string> = {}) => loadConfig(apiShape, { env: { ...env, ...extra }, readFile });

  it("defaults: passkey mode, hardware keys only, no cool-off (owner decision 2026-11-11)", () => {
    const c = load();
    expect([c.opsAuthMode, c.opsAllowPlatformPasskeys, c.cooloffSeconds]).toEqual(["passkey", false, 0]);
    const cc = consoleConfig(c);
    expect(betaFlagValues({ console: cc })).toEqual({
      NP_OPS_ALLOW_PLATFORM_PASSKEYS: 0,
      "NP_OPS_AUTH_MODE=cloudflare_access": 0,
    });
    expect(cc.access).toBeNull();
  });

  it("reads the flags and the Access settings; Access mode needs aud and team domain", () => {
    const c = load({
      NP_OPS_ALLOW_PLATFORM_PASSKEYS: "true",
      NP_OPS_AUTH_MODE: "cloudflare_access",
      NP_CF_ACCESS_AUD: AUD,
      NP_CF_ACCESS_TEAM_DOMAIN: TEAM,
      NP_OPS_BOOTSTRAP_EMAIL: "Owner@Example.com",
      NP_COOLOFF_SECONDS: "0",
      NP_ENV: "server",
    });
    expect(() => checkConsoleAuth(c)).not.toThrow();
    const cc = consoleConfig(c, keys);
    expect(cc).toMatchObject({ allowPlatformPasskeys: true, authMode: "cloudflare_access" });
    expect(cc.bootstrapEmail).toBe("owner@example.com");
    expect(cc.access?.issuer).toBe(`https://${TEAM}`);
    expect(c.cooloffSeconds).toBe(0); // allowed on the server stage
    expect(() => checkConsoleAuth({ ...c, cfAccessAud: undefined })).toThrow(/NP_CF_ACCESS_AUD/);
    expect(() => load({ NP_OPS_AUTH_MODE: "google" })).toThrow();
    expect(() => load({ NP_OPS_ALLOW_PLATFORM_PASSKEYS: "maybe" })).toThrow();
  });
});

describe("beta platform passkeys", () => {
  const facts = {
    env: "server",
    fmt: "none",
    hasX5c: false,
    aaguid: "00000000-0000-0000-0000-000000000000",
    synced: true,
    allowlist: new Set(["cb69481e-8ff7-4039-93ec-0a2729a154a8"]),
    rootsConfigured: true,
  };
  it("the hardware policy refuses a synced, unattested passkey; the beta policy admits it only with the flag", () => {
    expect(authenticatorProblem(facts)).not.toBeNull();
    expect(platformPasskeyProblem({ allowed: false, residentKey: true })).toMatch(/not accepted/);
    expect(platformPasskeyProblem({ allowed: true, residentKey: undefined })).toBeNull();
    expect(platformPasskeyProblem({ allowed: true, residentKey: true })).toBeNull();
    expect(platformPasskeyProblem({ allowed: true, residentKey: false })).toMatch(/resident key/);
  });
});

describe("boot metrics", () => {
  it("nearpay_ops_beta_flag{flag}, the active-operator gauge and nearpay_identity_destination_cooloff_seconds", async () => {
    const m = createMetrics("identity", { defaultMetrics: false });
    const lines: string[] = [];
    const log = {
      warn: (_o: unknown, l: string) => lines.push(`W ${l}`),
      info: (_o: unknown, l: string) => lines.push(`I ${l}`),
    } as never;
    const db = {
      selectFrom: () => ({
        innerJoin: () => ({
          select: () => ({
            where: () => ({
              where: () => ({ groupBy: () => ({ execute: async () => [{ role: "ops_admin", n: "1" }] }) }),
            }),
          }),
        }),
      }),
    } as never;
    announceConsole(log, m, { console: { ...NO_CONSOLE, allowPlatformPasskeys: true }, db });
    announceCooloff(log, m, { env: "server", cooloffSeconds: 0 });
    const text = await m.render();
    expect(text).toContain('nearpay_ops_beta_flag{flag="NP_OPS_ALLOW_PLATFORM_PASSKEYS"} 1');
    expect(text).toContain('nearpay_ops_beta_flag{flag="NP_OPS_AUTH_MODE=cloudflare_access"} 0');
    expect(text).toContain("nearpay_identity_destination_cooloff_seconds 0");
    expect(text).toContain('nearpay_identity_ops_operators_active{role="ops_admin"} 1');
    expect(lines.some((l) => l.startsWith("W BETA relaxation ON: NP_OPS_ALLOW_PLATFORM_PASSKEYS=true"))).toBe(true);
    // no cool-off is the intended default: an info line, never a warning
    expect(lines.some((l) => l.startsWith("I destination cool-off: none"))).toBe(true);
    expect(lines.some((l) => l.startsWith("W") && l.includes("cool-off"))).toBe(false);
  });
});

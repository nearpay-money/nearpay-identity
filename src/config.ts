/** Configuration (lld/identity.md §11, foundations §13). */
import { readFileSync } from "node:fs";
import { parseKek } from "@nearpay-internal/db";
import { baseConfigShape, flag, list, loadConfig, secret, url } from "@nearpay-internal/service";
import { GOOGLE_CALLBACK_DASHBOARD_PATH } from "@nearpay-money/spec";
import type { JWTVerifyGetKey } from "jose";
import { z } from "zod";
import { accessVerifier, deriveCsrfKey, normalizeTeamDomain } from "./app/console-access.js";
import type { ConsoleConfig } from "./app/context.js";
import { CLIENT_IP_HEADERS, clientIpRule } from "./domain/client-ip.js";
import { isDevEnv } from "./domain/env.js";

export const OPS_AUTH_MODES = ["passkey", "cloudflare_access"] as const;

const shared = {
  ...baseConfigShape,
  dbUrl: secret(url(["postgres:", "postgresql:"])),
  /** KEK for PII at rest (names, IPs) and idempotent responses. */
  piiKek: secret(),
  /** Directory with `current.pem` and `next.pem` (Ed25519) — internal JWT signing keys. */
  jwtKeysDir: z.string().min(1).default("/run/secrets/jwt"),
  complianceUrl: url(["http:", "https:"]),
  /** Client IP source behind the gateway (default: cf-connecting-ip on the server stage, x-forwarded-for locally). */
  clientIpHeader: z.enum(CLIENT_IP_HEADERS).optional(),
  /** CIDRs of the proxies in front of identity whose forwarding headers count (default: loopback + private ranges). */
  trustedProxies: list(z.string().min(1)).optional(),
  /**
   * Cool-off of a new settlement destination, seconds (default 0: owner decision 2026-11-11, final — a
   * payout wallet is active the moment its ownership is attested and the last required approval lands).
   * An operator may still set up to 30 days; the gauge `nearpay_identity_destination_cooloff_seconds`
   * shows the value. Ownership attestation, screening, step-up, the two-approver rule and the audit stay.
   */
  cooloffSeconds: z.coerce
    .number()
    .int()
    .min(0)
    .max(30 * 86_400)
    .default(0),
};

export const apiShape = {
  ...shared,
  valkeyUrl: url(["redis:", "rediss:"]),
  /** Core NATS for the cross-replica cache purge (`ctl.identity.cache.purge`); optional. */
  natsUrl: url(["nats:", "tls:"]).optional(),
  /** `{"clients":[{"client_id","secret_sha256"}]}` (scopes come from the spec). */
  serviceClientsFile: z.string().min(1),
  turnstileSecret: secret(),
  webauthnRpId: z.string().min(1).default("nearpay.localhost"),
  webauthnOrigins: list(url(["https:", "http:"])),
  dashboardOrigin: url(["https:", "http:"]),
  recoveryLockSeconds: z.coerce.number().int().min(0).default(172_800),
  railsUrl: url(["http:", "https:"]),
  notifyUrl: url(["http:", "https:"]),
  nearRpcUrls: list(url(["https:", "http:"])),
  /** Console origin (`https://ops.nearpay.money`): WebAuthn origin (RP id = its host) of operator passkeys. */
  opsOrigin: url(["https:", "http:"]).optional(),
  /** One AAGUID per line (`#` comments): hardware security keys accepted for operator passkeys. */
  opsAaguidAllowlistFile: z.string().min(1).optional(),
  /** PEM bundle of attestation roots (vendor CAs) operator-key attestations must chain to; required on the server stage. */
  opsAttestationRootsFile: z.string().min(1).optional(),
  /**
   * BETA ONLY (remove before the VPS): operator passkeys may be platform / synced passkeys (Touch ID,
   * iCloud Keychain, Google Password Manager; attestation `none`). UV and resident keys stay required.
   */
  opsAllowPlatformPasskeys: flag(false),
  /** Console sign-in: `passkey` (hardware keys, default) or `cloudflare_access` (Google login through Access). */
  opsAuthMode: z.enum(OPS_AUTH_MODES).default("passkey"),
  /** Access application audience tag (`aud`); required in `cloudflare_access` mode. */
  cfAccessAud: z.string().min(1).max(256).optional(),
  /** Access team domain (`<team>.cloudflareaccess.com`); required in `cloudflare_access` mode. */
  cfAccessTeamDomain: z.string().min(1).max(253).optional(),
  /** Access mode: the first operator (`ops_admin`), enrolled at boot while there is none. */
  opsBootstrapEmail: z.email().optional(),
  /**
   * Continue with Google (ADR-0026): the OAuth client id. Google sign-in is on only when this and the client
   * secret file are both non-empty; otherwise it is off (the dashboard hides the button) and identity starts.
   */
  googleClientId: z.string().max(256).default(""),
  /** `NP_GOOGLE_CLIENT_SECRET_FILE`; an absent variable or an empty file leaves Google sign-in off. */
  googleClientSecret: secret(z.string().max(512)).optional(),
  /** Tests and local mocks only (refused unless NP_ENV is local/test): Google's endpoints. */
  googleAuthorizationUrl: url(["https:", "http:"]).optional(),
  googleTokenUrl: url(["https:", "http:"]).optional(),
  googleJwksUrl: url(["https:", "http:"]).optional(),
  /** `{"<chain id>": ["https://…"]}` for ERC-1271 contract-wallet attestations (optional). */
  evmRpcUrls: z
    .string()
    .default("{}")
    .transform((s, ctx) => {
      try {
        const v = JSON.parse(s) as unknown;
        const r = z.record(z.string().regex(/^\d+$/), z.array(z.url())).safeParse(v);
        if (r.success) return r.data;
      } catch {}
      ctx.addIssue({ code: "custom", message: 'expected {"<chain id>": ["https://…"]}' });
      return z.NEVER;
    }),
};

export const workerShape = {
  ...shared,
  natsUrl: url(["nats:", "tls:"]),
  /** Revoked keys are purged from Valkey too (optional). */
  valkeyUrl: url(["redis:", "rediss:"]).optional(),
};

export const opsShape = {
  ...baseConfigShape,
  dbUrl: secret(url(["postgres:", "postgresql:"])),
  piiKek: secret(),
  jwtKeysDir: z.string().min(1).default("/run/secrets/jwt"),
  complianceUrl: url(["http:", "https:"]).default("http://compliance-api:8080"),
  railsUrl: url(["http:", "https:"]).default("http://rails-api:8080"),
  notifyUrl: url(["http:", "https:"]).default("http://notify-api:8080"),
  opsActor: z.string().min(1).max(100).optional(),
  /** Console origin for enrolment links (`<origin>/auth/enrol#token=…`). */
  opsOrigin: url(["https:", "http:"]).optional(),
  /** `cloudflare_access`: operators are enrolled by email only (no passkey enrolment link). */
  opsAuthMode: z.enum(OPS_AUTH_MODES).default("passkey"),
};

export const migrateShape = { ...baseConfigShape, dbUrl: secret(url(["postgres:", "postgresql:"])) };

export type ApiConfig = z.output<z.ZodObject<typeof apiShape>>;
export type WorkerConfig = z.output<z.ZodObject<typeof workerShape>>;
export type OpsConfig = z.output<z.ZodObject<typeof opsShape>>;

/**
 * The boot log line for the destination cool-off (owner decision 2026-11-11: none by default, an operator
 * may set up to 30 days). Informational either way — 0 is the intended setting, not a relaxation.
 */
export function cooloffNotice(c: { env: string; cooloffSeconds: number }): string {
  return c.cooloffSeconds === 0
    ? "destination cool-off: none — payout wallets activate as soon as they are attested and approved"
    : `destination cool-off: NP_COOLOFF_SECONDS=${c.cooloffSeconds} — payout wallets activate ${c.cooloffSeconds} s after attestation and approval`;
}

/** `cloudflare_access` needs the Access audience and team domain (the console would refuse everything otherwise). */
export function checkConsoleAuth(
  c: Pick<ApiConfig, "opsAuthMode" | "cfAccessAud" | "cfAccessTeamDomain" | "opsBootstrapEmail">,
): void {
  if (c.opsAuthMode !== "cloudflare_access") return;
  if (!c.cfAccessAud || !c.cfAccessTeamDomain)
    throw new Error("NP_OPS_AUTH_MODE=cloudflare_access needs NP_CF_ACCESS_AUD and NP_CF_ACCESS_TEAM_DOMAIN");
  normalizeTeamDomain(c.cfAccessTeamDomain);
}

/**
 * AAGUIDs of software/virtual authenticators (the Chrome DevTools virtual authenticator, the all-zero
 * AAGUID of self-attesting keys): accepted from the allow-list only when NP_ENV is `local` or `test`.
 */
export const VIRTUAL_AAGUIDS = new Set([
  "00000000-0000-0000-0000-000000000000",
  "01020304-0506-0708-0102-030405060708",
]);

/** Parses the AAGUID allow-list (one per line, `#` comments, case-insensitive). */
export function parseAaguids(text: string, env: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "").trim().toLowerCase();
    if (!line) continue;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(line))
      throw new Error(`NP_OPS_AAGUID_ALLOWLIST: not an AAGUID: ${line.slice(0, 40)}`);
    if (VIRTUAL_AAGUIDS.has(line) && !isDevEnv(env)) continue;
    out.add(line);
  }
  return out;
}

/** PEM certificates of a bundle. */
export function parsePemBundle(text: string): string[] {
  return [...text.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)].map((m) => `${m[0]}\n`);
}

export function consoleConfig(
  c: {
    env: string;
    piiKek?: string;
    opsOrigin?: string | undefined;
    opsAaguidAllowlistFile?: string | undefined;
    opsAttestationRootsFile?: string | undefined;
    opsAllowPlatformPasskeys?: boolean | undefined;
    opsAuthMode?: (typeof OPS_AUTH_MODES)[number] | undefined;
    cfAccessAud?: string | undefined;
    cfAccessTeamDomain?: string | undefined;
    opsBootstrapEmail?: string | undefined;
  },
  accessKeys?: JWTVerifyGetKey,
): ConsoleConfig {
  const origin = c.opsOrigin ? c.opsOrigin.replace(/\/$/, "") : null;
  const access = c.opsAuthMode === "cloudflare_access";
  return {
    origin,
    rpId: origin ? new URL(origin).hostname : null,
    aaguids: c.opsAaguidAllowlistFile ? parseAaguids(readFileSync(c.opsAaguidAllowlistFile, "utf8"), c.env) : new Set(),
    attestationRoots: c.opsAttestationRootsFile ? parsePemBundle(readFileSync(c.opsAttestationRootsFile, "utf8")) : [],
    allowPlatformPasskeys: c.opsAllowPlatformPasskeys === true,
    authMode: access ? "cloudflare_access" : "passkey",
    access:
      access && c.cfAccessAud && c.cfAccessTeamDomain && c.piiKek
        ? accessVerifier({
            teamDomain: c.cfAccessTeamDomain,
            audience: c.cfAccessAud,
            csrfKey: deriveCsrfKey(parseKek(c.piiKek)),
            ...(accessKeys ? { keys: accessKeys } : {}),
          })
        : null,
    bootstrapEmail: access && c.opsBootstrapEmail ? c.opsBootstrapEmail.toLowerCase() : null,
  };
}

/** Cloudflare's documented Turnstile test secrets (always pass / fail / spent): local and test stacks only. */
export const isTurnstileTestSecret = (s: string) => /^[123]x0+AA$/.test(s.trim());

function publicOrigin(name: string, value: string): URL {
  const u = new URL(value);
  if (u.protocol !== "https:" || u.hostname === "localhost" || u.hostname.endsWith(".localhost"))
    throw new Error(`${name} must be a public https origin on the server stage (got ${value})`);
  return u;
}

/**
 * Server-stage rules (every NP_ENV but local/test): a real Turnstile secret (a test secret passes every
 * token, even through siteverify), and WebAuthn origins that are public https origins under the RP id
 * (`nearpay.money` → `dashboard.nearpay.money`), the dashboard among them; the console origin likewise.
 */
export function checkServerConfig(
  c: Pick<ApiConfig, "env" | "turnstileSecret" | "webauthnRpId" | "webauthnOrigins" | "dashboardOrigin" | "opsOrigin">,
): void {
  if (isDevEnv(c.env)) return;
  if (isTurnstileTestSecret(c.turnstileSecret))
    throw new Error(
      "NP_TURNSTILE_SECRET_FILE holds a Cloudflare test secret: allowed only when NP_ENV is local or test",
    );
  const rp = c.webauthnRpId.toLowerCase();
  if (rp === "localhost" || rp.endsWith(".localhost") || !rp.includes("."))
    throw new Error(`NP_WEBAUTHN_RP_ID must be the public domain on the server stage (got ${c.webauthnRpId})`);
  for (const o of c.webauthnOrigins) {
    const h = publicOrigin("NP_WEBAUTHN_ORIGINS", o).hostname.toLowerCase();
    if (h !== rp && !h.endsWith(`.${rp}`))
      throw new Error(`NP_WEBAUTHN_ORIGINS: ${o} is not under the RP id ${c.webauthnRpId}`);
  }
  const dashboard = publicOrigin("NP_DASHBOARD_ORIGIN", c.dashboardOrigin).origin;
  if (!c.webauthnOrigins.some((o) => new URL(o).origin === dashboard))
    throw new Error("NP_WEBAUTHN_ORIGINS must include NP_DASHBOARD_ORIGIN");
  if (c.opsOrigin) publicOrigin("NP_OPS_ORIGIN", c.opsOrigin);
}

export interface GoogleSettings {
  readonly clientId: string;
  readonly clientSecret: string;
  /** `<NP_DASHBOARD_ORIGIN>/api/auth/google/callback` (spec GOOGLE_CALLBACK_DASHBOARD_PATH). */
  readonly redirectUri: string;
  readonly endpoints: { authorization: string; token: string; jwks: string } | null;
}

/**
 * Google sign-in settings, or null (off) with the reason. Off unless both the client id and the secret are
 * non-empty; the endpoint overrides are for local/test mocks only (a real deployment refuses to boot with them).
 */
export function googleSettings(
  c: Pick<
    ApiConfig,
    | "env"
    | "dashboardOrigin"
    | "googleClientId"
    | "googleClientSecret"
    | "googleAuthorizationUrl"
    | "googleTokenUrl"
    | "googleJwksUrl"
  >,
): { settings: GoogleSettings | null; reason: string } {
  const overrides = [c.googleAuthorizationUrl, c.googleTokenUrl, c.googleJwksUrl];
  const overridden = overrides.some((v) => v !== undefined);
  if (overridden && !isDevEnv(c.env))
    throw new Error(
      "NP_GOOGLE_AUTHORIZATION_URL / NP_GOOGLE_TOKEN_URL / NP_GOOGLE_JWKS_URL are for local/test mocks only",
    );
  if (overridden && overrides.some((v) => v === undefined))
    throw new Error("set all of NP_GOOGLE_AUTHORIZATION_URL, NP_GOOGLE_TOKEN_URL and NP_GOOGLE_JWKS_URL, or none");
  const clientId = c.googleClientId.trim();
  const clientSecret = (c.googleClientSecret ?? "").trim();
  if (!clientId && !clientSecret) return { settings: null, reason: "no Google client configured" };
  if (!clientId)
    return { settings: null, reason: "NP_GOOGLE_CLIENT_SECRET_FILE is set but NP_GOOGLE_CLIENT_ID is empty" };
  if (!clientSecret)
    return { settings: null, reason: "NP_GOOGLE_CLIENT_ID is set but the client secret file is absent or empty" };
  if (!/^[A-Za-z0-9._-]+$/.test(clientId)) throw new Error("NP_GOOGLE_CLIENT_ID is not an OAuth client id");
  return {
    settings: {
      clientId,
      clientSecret,
      redirectUri: `${new URL(c.dashboardOrigin).origin}${GOOGLE_CALLBACK_DASHBOARD_PATH}`,
      endpoints: overridden
        ? {
            authorization: c.googleAuthorizationUrl as string,
            token: c.googleTokenUrl as string,
            jwks: c.googleJwksUrl as string,
          }
        : null,
    },
    reason: "configured",
  };
}

export const readApiConfig = () => {
  const c = loadConfig(apiShape);
  checkServerConfig(c);
  googleSettings(c); // a bad client id or a server-stage endpoint override fails at boot
  checkConsoleAuth(c);
  clientIpRule(c.env, { header: c.clientIpHeader, trustedProxies: c.trustedProxies }); // a bad CIDR fails at boot
  return c;
};
export const readWorkerConfig = () => loadConfig(workerShape);
export const readOpsConfig = () => loadConfig(opsShape);

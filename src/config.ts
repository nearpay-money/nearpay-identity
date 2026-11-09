/** Configuration (lld/identity.md §11, foundations §13). */
import { readFileSync } from "node:fs";
import { baseConfigShape, list, loadConfig, secret, url } from "@nearpay-internal/service";
import { z } from "zod";
import type { ConsoleConfig } from "./app/context.js";
import { CLIENT_IP_HEADERS, clientIpRule } from "./domain/client-ip.js";
import { isDevEnv } from "./domain/env.js";

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
  /** 86 400 s; 0 is allowed only when NP_ENV=local (checked in readConfig). */
  cooloffSeconds: z.coerce
    .number()
    .int()
    .min(0)
    .max(30 * 86_400)
    .default(86_400),
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
};

export const migrateShape = { ...baseConfigShape, dbUrl: secret(url(["postgres:", "postgresql:"])) };

export type ApiConfig = z.output<z.ZodObject<typeof apiShape>>;
export type WorkerConfig = z.output<z.ZodObject<typeof workerShape>>;
export type OpsConfig = z.output<z.ZodObject<typeof opsShape>>;

/** A zero cool-off would let a stolen session redirect live funds at once: local stacks only. */
export function checkCooloff(c: { env: string; cooloffSeconds: number }): void {
  if (c.cooloffSeconds === 0 && !isDevEnv(c.env))
    throw new Error("NP_COOLOFF_SECONDS=0 is allowed only when NP_ENV=local");
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

export function consoleConfig(c: {
  env: string;
  opsOrigin?: string | undefined;
  opsAaguidAllowlistFile?: string | undefined;
  opsAttestationRootsFile?: string | undefined;
}): ConsoleConfig {
  const origin = c.opsOrigin ? c.opsOrigin.replace(/\/$/, "") : null;
  return {
    origin,
    rpId: origin ? new URL(origin).hostname : null,
    aaguids: c.opsAaguidAllowlistFile ? parseAaguids(readFileSync(c.opsAaguidAllowlistFile, "utf8"), c.env) : new Set(),
    attestationRoots: c.opsAttestationRootsFile ? parsePemBundle(readFileSync(c.opsAttestationRootsFile, "utf8")) : [],
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

export const readApiConfig = () => {
  const c = loadConfig(apiShape);
  checkCooloff(c);
  checkServerConfig(c);
  clientIpRule(c.env, { header: c.clientIpHeader, trustedProxies: c.trustedProxies }); // a bad CIDR fails at boot
  return c;
};
export const readWorkerConfig = () => {
  const c = loadConfig(workerShape);
  checkCooloff(c);
  return c;
};
export const readOpsConfig = () => loadConfig(opsShape);

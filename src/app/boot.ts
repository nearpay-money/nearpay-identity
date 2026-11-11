/**
 * Boot-time reporting of the console and destination settings that relax a default (lld/identity.md §6.1,
 * §11): one log line each, and metrics the monitoring stack reads (none of them affects `/readyz`).
 *
 * - `nearpay_ops_beta_flag{flag}` — 1 while a relaxation is on: `NP_OPS_ALLOW_PLATFORM_PASSKEYS` (beta
 *   only) and `NP_OPS_AUTH_MODE=cloudflare_access`; 0 otherwise. Unprefixed, the same name in every service.
 * - `nearpay_identity_destination_cooloff_seconds` — the configured destination cool-off (0 by default,
 *   owner decision 2026-11-11; logged at info either way).
 * - `nearpay_identity_ops_operators_active{role}` — active operators (a single `ops_admin` = the adaptive
 *   two-person rule lets that operator complete two-person actions alone).
 */
import type { Logger, ServiceMetrics } from "@nearpay-internal/service";
import { Gauge } from "prom-client";
import { cooloffNotice } from "../config.js";
import { accessMode, BETA_FLAGS, type Identity } from "./context.js";
import { activeOperatorsByRole } from "./operators.js";

export const BETA_FLAG_METRIC = "nearpay_ops_beta_flag";

export function betaFlagValues(id: Pick<Identity, "console">): Record<(typeof BETA_FLAGS)[number], 0 | 1> {
  return {
    NP_OPS_ALLOW_PLATFORM_PASSKEYS: id.console.allowPlatformPasskeys ? 1 : 0,
    "NP_OPS_AUTH_MODE=cloudflare_access": accessMode(id.console) ? 1 : 0,
  };
}

export function announceConsole(log: Logger, m: ServiceMetrics, id: Pick<Identity, "console" | "db">): void {
  const flags = betaFlagValues(id);
  const g = new Gauge({
    name: BETA_FLAG_METRIC,
    help: "1 while an ops relaxation is enabled (platform passkeys: beta only, remove before the VPS).",
    labelNames: ["flag"],
    registers: [m.registry],
  });
  for (const f of BETA_FLAGS) g.set({ flag: f }, flags[f]);
  if (flags.NP_OPS_ALLOW_PLATFORM_PASSKEYS)
    log.warn(
      { flag: "NP_OPS_ALLOW_PLATFORM_PASSKEYS", enabled: true, beta_only: true },
      "BETA relaxation ON: NP_OPS_ALLOW_PLATFORM_PASSKEYS=true — operator passkeys may be platform/synced passkeys (remove before the VPS)",
    );
  else log.info({ flag: "NP_OPS_ALLOW_PLATFORM_PASSKEYS", enabled: false }, "operator passkeys: hardware keys only");
  if (flags["NP_OPS_AUTH_MODE=cloudflare_access"])
    log.warn(
      { flag: "NP_OPS_AUTH_MODE", mode: "cloudflare_access", bootstrap: id.console.bootstrapEmail !== null },
      "console sign-in: Cloudflare Access (verified Cf-Access-Jwt-Assertion; re-authentication = Access login within 5 min)",
    );
  else log.info({ flag: "NP_OPS_AUTH_MODE", mode: "passkey" }, "console sign-in: operator passkeys");
  m.gauge("ops_operators_active", "Active console operators by role.", ["role"], async (gauge) => {
    const n = await activeOperatorsByRole(id.db);
    gauge.set({ role: "ops" }, n.ops);
    gauge.set({ role: "ops_admin" }, n.ops_admin);
  });
}

export function announceCooloff(log: Logger, m: ServiceMetrics, c: { env: string; cooloffSeconds: number }): void {
  m.gauge("destination_cooloff_seconds", "Configured cool-off of new settlement destinations (seconds).").set(
    c.cooloffSeconds,
  );
  log.info({ cooloff_seconds: c.cooloffSeconds }, cooloffNotice(c));
}

/**
 * Continue with Google (ADR-0026): one boot line (on: redirect URI and client id; off: why) and the gauge
 * `nearpay_identity_google_signin_enabled` (1/0). Off is a normal state (no client configured): identity starts.
 */
export function announceGoogle(log: Logger, m: ServiceMetrics, id: Pick<Identity, "google">, reason: string): void {
  m.gauge("google_signin_enabled", "1 while Continue with Google is configured (ADR-0026).").set(id.google ? 1 : 0);
  if (id.google)
    log.info(
      { google_signin: true, client_id: id.google.clientId, redirect_uri: id.google.redirectUri },
      "Continue with Google: on",
    );
  else log.info({ google_signin: false, reason }, "Continue with Google: off");
}

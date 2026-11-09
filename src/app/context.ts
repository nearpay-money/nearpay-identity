/** Dependencies shared by identity use cases. */

import type { EnvelopeCipher, Kysely, Transaction } from "@nearpay-internal/db";
import { emit, sql } from "@nearpay-internal/db";
import { uuidv7 } from "@nearpay-internal/ids";
import type { Logger, ServiceMetrics } from "@nearpay-internal/service";
import type { Subject } from "@nearpay-internal/spec";
import type { ClientIpRule } from "../domain/client-ip.js";
import type { AuthzCache } from "../infra/cache.js";
import type { Peers } from "../infra/clients/peers.js";
import type { TurnstileVerifier } from "../infra/clients/turnstile.js";
import type { OwnershipLookups } from "../infra/crypto/attestation.js";
import type { DB } from "../infra/db/schema.js";
import type { AccessVerifier } from "./console-access.js";
import type { Signer } from "./tokens.js";

export interface IdentityMetrics {
  authz(result: string, seconds: number): void;
  rateLimited(ptype: string): void;
  destinationTransition(to: string): void;
  attestationFailure(standard: string): void;
  loginFailure(): void;
}

/** Labels of `nearpay_ops_beta_flag{flag}`. */
export const BETA_FLAGS = ["NP_OPS_ALLOW_PLATFORM_PASSKEYS", "NP_OPS_AUTH_MODE=cloudflare_access"] as const;

export const noMetrics: IdentityMetrics = {
  authz() {},
  rateLimited() {},
  destinationTransition() {},
  attestationFailure() {},
  loginFailure() {},
};

export function identityMetrics(m: ServiceMetrics): IdentityMetrics {
  const authz = m.histogram(
    "authz_duration_seconds",
    "Gateway authorisation latency.",
    ["result"],
    [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25],
  );
  const limited = m.counter("rate_limited_total", "Requests refused by the rate limiter.", ["ptype"]);
  const transitions = m.counter("destination_transitions_total", "Settlement destination transitions.", ["to"]);
  const attest = m.counter("attestation_failures_total", "Rejected destination attestations.", ["standard"]);
  const login = m.counter("login_failures_total", "Failed passkey sign-ins and step-ups.");
  return {
    authz: (result, s) => authz.observe({ result }, s),
    rateLimited: (ptype) => limited.inc({ ptype }),
    destinationTransition: (to) => transitions.inc({ to }),
    attestationFailure: (standard) => attest.inc({ standard }),
    loginFailure: () => login.inc(),
  };
}

export interface WebAuthnConfig {
  readonly rpId: string;
  readonly rpName: string;
  readonly origins: readonly string[];
}

/**
 * Console (ops) sign-in (lld/identity.md §6.1, §11): the console origin (enrolment links, WebAuthn
 * origin; RP id = its host), the hardware-key AAGUID allow-list and the attestation trust anchors.
 * Missing origin or an empty allow-list refuses every console enrolment (fail closed).
 */
export interface ConsoleConfig {
  readonly origin: string | null;
  readonly rpId: string | null;
  /** Lower-case AAGUIDs of accepted hardware security keys. */
  readonly aaguids: ReadonlySet<string>;
  /** PEM root certificates attestation chains must lead to (required when NP_ENV=server). */
  readonly attestationRoots: readonly string[];
  /**
   * BETA ONLY (`NP_OPS_ALLOW_PLATFORM_PASSKEYS=true`, remove before the VPS): operator passkeys may be
   * platform / synced passkeys (Touch ID, iCloud Keychain, Google Password Manager; attestation `none`).
   * User verification and resident keys stay required. Default false.
   */
  readonly allowPlatformPasskeys?: boolean;
  /** `NP_OPS_AUTH_MODE`: `passkey` (default) or `cloudflare_access` (app/console-access.ts). */
  readonly authMode?: "passkey" | "cloudflare_access";
  /** Access verification (required in `cloudflare_access` mode). */
  readonly access?: AccessVerifier | null;
  /** `NP_OPS_BOOTSTRAP_EMAIL` (Access mode): the first operator, enrolled at boot while there is none. */
  readonly bootstrapEmail?: string | null;
}

export const NO_CONSOLE: ConsoleConfig = {
  origin: null,
  rpId: null,
  aaguids: new Set(),
  attestationRoots: [],
  allowPlatformPasskeys: false,
  authMode: "passkey",
  access: null,
  bootstrapEmail: null,
};

/** The console signs in through Cloudflare Access (and never with a cookie session or passkey). */
export const accessMode = (c: ConsoleConfig): boolean => c.authMode === "cloudflare_access";

/** Everything the use cases need; api and worker build it with the parts they run. */
export interface Identity {
  readonly env: string;
  /** Where the client IP comes from (NP_CLIENT_IP_HEADER, NP_TRUSTED_PROXIES); default: by NP_ENV. */
  readonly clientIp?: ClientIpRule;
  readonly db: Kysely<DB>;
  readonly cipher: EnvelopeCipher;
  readonly log: Logger;
  readonly metrics: IdentityMetrics;
  readonly signer: Signer;
  readonly peers: Peers;
  readonly cooloffMs: number;
  readonly recoveryLockMs: number;
  readonly dashboardOrigin: string;
  readonly webauthn: WebAuthnConfig;
  readonly console: ConsoleConfig;
  readonly lookups: OwnershipLookups;
  readonly turnstile: TurnstileVerifier;
  readonly cache: AuthzCache;
  readonly now: () => number;
}

export type Tx = Transaction<DB>;

export async function dbNow(db: Kysely<DB> | Tx): Promise<Date> {
  const r = await sql<{ now: Date }>`select now() as now`.execute(db);
  return (r.rows[0] as { now: Date }).now;
}

export function emitEvent(
  tx: Tx,
  e: {
    subject: Subject;
    aggregate: { type: string; id: string; version: number };
    accountUuid: string | null;
    livemode: boolean | null;
    object: unknown;
    previous?: Record<string, unknown>;
  },
) {
  return emit(tx, {
    subject: e.subject,
    aggregate: e.aggregate,
    accountId: e.accountUuid,
    livemode: e.livemode,
    data: { object: e.object, ...(e.previous ? { previous: e.previous } : {}) },
  });
}

export interface Actor {
  readonly type: "user" | "api_key" | "service" | "ops" | "operator" | "system";
  readonly id: string;
  readonly ip?: string | null;
}

/** Appends to the audit log (append-only table; security §12). */
export async function audit(
  id: Identity,
  tx: Tx | Kysely<DB>,
  a: {
    accountUuid: string | null;
    actor: Actor;
    action: string;
    target?: { type: string; id: string };
    details?: Record<string, unknown>;
    /** Where the action was requested from when that is not the actor (CLI login IP); encrypted. */
    originIp?: string | null;
    /** A deterministic event id: a repeat of the same event is then written once. */
    eventId?: string;
  },
): Promise<void> {
  const eid = a.eventId ?? uuidv7();
  const q = tx.insertInto("audit_events").values({
    id: eid,
    account_id: a.accountUuid,
    actor_type: a.actor.type,
    actor_id: a.actor.id,
    action: a.action,
    target_type: a.target?.type ?? null,
    target_id: a.target?.id ?? null,
    details: JSON.stringify(a.details ?? {}),
    ip_enc: a.actor.ip ? id.cipher.encrypt(a.actor.ip, `audit:${eid}:ip`) : null,
    ...(a.originIp ? { origin_ip_enc: id.cipher.encrypt(a.originIp, `audit:${eid}:origin_ip`) } : {}),
  });
  await (a.eventId ? q.onConflict((oc) => oc.column("id").doNothing()) : q).execute();
}

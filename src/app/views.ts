/** Rows → contract objects (`@nearpay/spec` Account, ApiKey, SettlementDestination…). */
import { createHash } from "node:crypto";
import type { Account, ApiKey as ApiKeySchema, SettlementDestination } from "@nearpay/spec";
import { destinationFingerprint } from "@nearpay-internal/chains";
import type { Selectable } from "@nearpay-internal/db";
import { fromUuid } from "@nearpay-internal/ids";
import type { InternalSettlementDestination } from "@nearpay-internal/spec";
import { usdMicrosToCents } from "../domain/settlement-destination/destination.js";
import type { AccountsTable, ApiKeysTable, SettlementDestinationsTable } from "../infra/db/schema.js";

const unix = (d: Date) => Math.floor(d.getTime() / 1000);
const unixOrNull = (d: Date | null) => (d ? unix(d) : null);

export type AccountRow = Selectable<AccountsTable>;
export type KeyRow = Selectable<ApiKeysTable>;
export type DestinationRow = Selectable<SettlementDestinationsTable>;

export function accountView(a: AccountRow): Account {
  return {
    id: fromUuid("acct", a.id),
    object: "account",
    created: unix(a.created_at),
    display_name: a.display_name,
    verified_legal_name: a.verified_legal_name,
    country: a.country ? a.country.trim() : null,
    status: a.status,
    kyb_status: a.kyb_status,
    live_enabled: a.live_enabled,
    fee_bearer: a.fee_bearer,
    api_version: a.api_version as Account["api_version"],
    settings: a.settings,
  };
}

type ApiKey = ReturnType<(typeof ApiKeySchema)["parse"]>;

export function apiKeyView(k: KeyRow, secret?: string): ApiKey {
  return {
    id: fromUuid("key", k.id),
    object: "api_key",
    created: unix(k.created_at),
    livemode: k.livemode,
    type: k.type,
    name: k.name,
    display_prefix: k.display_prefix,
    last4: k.last4.trim(),
    scopes: k.scopes,
    ip_allowlist: k.ip_allowlist,
    expires_at: unixOrNull(k.expires_at),
    last_used_at: unixOrNull(k.last_used_at),
    ...(secret ? { secret } : {}),
  };
}

export const fingerprintOf = (d: Pick<DestinationRow, "chain" | "address_norm" | "asset_id">) =>
  destinationFingerprint(d.chain, d.address_norm, d.asset_id);

export interface DestinationExtras {
  readonly isDefault: boolean;
  /** USD micros from rails, or null when unknown. */
  readonly minUsdMicros: number | null;
  readonly challenge?: SettlementDestination["attestation_challenge"];
}

export function destinationView(d: DestinationRow, x: DestinationExtras): SettlementDestination {
  const cap = d.per_payment_cap_usd_micros === null ? null : Number(d.per_payment_cap_usd_micros);
  return {
    id: fromUuid("sd", d.id),
    object: "settlement_destination",
    created: unix(d.created_at),
    livemode: d.livemode,
    asset_id: d.asset_id,
    type: d.type,
    chain: d.chain,
    address: d.address,
    label: d.label,
    status: d.status,
    verification: d.verification,
    fingerprint: fingerprintOf(d),
    is_default: x.isDefault,
    active_at: unixOrNull(d.active_at),
    min_payment_amount: x.minUsdMicros === null ? null : { amount: usdMicrosToCents(x.minUsdMicros), currency: "usd" },
    per_payment_cap: cap === null ? null : { amount: usdMicrosToCents(cap), currency: "usd" },
    disabled_reason: d.disabled_reason,
    ...(x.challenge ? { attestation_challenge: x.challenge } : {}),
  };
}

/** sha256 of the stored attestation (sentinel and payments compare it, never the attestation itself). */
export function attestationHash(d: Pick<DestinationRow, "attestation">): string | null {
  return d.attestation ? createHash("sha256").update(JSON.stringify(d.attestation)).digest("hex") : null;
}

export function internalDestinationView(d: DestinationRow, x: DestinationExtras): InternalSettlementDestination {
  const { attestation_challenge: _c, ...pub } = destinationView(d, x);
  return {
    ...pub,
    account: fromUuid("acct", d.account_id),
    address_norm: d.address_norm,
    attestation_hash: attestationHash(d),
    per_payment_cap_usd_micros: d.per_payment_cap_usd_micros === null ? null : Number(d.per_payment_cap_usd_micros),
  };
}

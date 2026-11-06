/** Kysely table types (migrations/0001_identity.sql). */
import type { ColumnType, Generated, KitTables } from "@nearpay-internal/db";

type Timestamp = ColumnType<Date, Date | string | undefined, Date | string>;
type NullableTimestamp = ColumnType<Date | null, Date | string | null | undefined, Date | string | null>;
type Json<T> = ColumnType<T, string, string>;
type NullableJson<T> = ColumnType<T | null, string | null | undefined, string | null>;
type TextArray = ColumnType<string[], string[] | undefined, string[]>;

export type FeeRule = {
  total_bps: number;
  min_fee_usd_micros: number;
};
export type FeeRules = {
  same_asset: FeeRule;
  stable_pair: FeeRule;
  volatile: FeeRule;
  intents_transfer: FeeRule;
};
export type ProviderSplit = {
  oneclick: { share_bps: number; floor_bps: number; stable_floor_bps: number };
};

export interface FeeSchedulesTable {
  id: string;
  name: string;
  rules: Json<FeeRules>;
  provider_split: Json<ProviderSplit>;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export type AccountSettingsRow = {
  late_payments: boolean;
  underpay_tolerance_bps: number;
  session_ttl_default: number;
  email_receipts: boolean;
  branding: { accent_color: string | null; logo_url: string | null };
};

export type AccountStatus = "active" | "suspended" | "closed";
export type KybStatus = "not_started" | "pending" | "needs_info" | "approved" | "rejected";

export interface AccountsTable {
  id: string;
  display_name: string;
  verified_legal_name: string | null;
  country: string | null;
  status: Generated<AccountStatus>;
  kyb_status: Generated<KybStatus>;
  live_enabled: Generated<boolean>;
  fee_schedule_id: string;
  fee_bearer: Generated<"payer" | "merchant">;
  api_version: string;
  settings: Json<AccountSettingsRow>;
  recovered_at: NullableTimestamp;
  kyb_source_version: Generated<number>;
  status_source_version: Generated<number>;
  created_at: Timestamp;
  updated_at: Timestamp;
  version: Generated<number>;
}

export interface UsersTable {
  id: string;
  email: string;
  email_verified_at: NullableTimestamp;
  name_enc: Buffer | null;
  status: Generated<"active" | "disabled">;
  created_at: Timestamp;
  last_login_at: NullableTimestamp;
}

export type Role = "owner" | "admin" | "developer" | "finance" | "support" | "viewer";

export interface MembershipsTable {
  account_id: string;
  user_id: string;
  role: Role;
  created_at: Timestamp;
}

export interface PasskeysTable {
  id: string;
  user_id: string;
  credential_id: Buffer;
  public_key: Buffer;
  sign_count: ColumnType<string, number | bigint | string, number | bigint | string>;
  transports: TextArray;
  aaguid: string | null;
  backed_up: Generated<boolean>;
  name: string;
  created_at: Timestamp;
  last_used_at: NullableTimestamp;
}

export interface SessionsTable {
  id: string;
  kind: Generated<"dashboard" | "ops">;
  user_id: string;
  account_id: string | null;
  token_hash: Buffer;
  csrf_hash: Buffer;
  csrf_enc: Buffer;
  step_up_at: NullableTimestamp;
  created_at: Timestamp;
  expires_at: Timestamp;
  last_seen_at: Timestamp;
  revoked_at: NullableTimestamp;
  ip_enc: Buffer | null;
  user_agent: string | null;
}

export interface MagicLinksTable {
  token_hash: Buffer;
  email: string;
  purpose: "signup" | "recovery" | "invite";
  account_id: string | null;
  role: string | null;
  expires_at: Timestamp;
  used_at: NullableTimestamp;
  created_at: Timestamp;
}

export interface RegistrationTokensTable {
  token_hash: Buffer;
  email: string;
  user_handle: Buffer;
  expires_at: Timestamp;
  used_at: NullableTimestamp;
  created_at: Timestamp;
}

export interface WebauthnChallengesTable {
  challenge: string;
  purpose: "registration" | "authentication" | "step_up";
  registration_token_hash: Buffer | null;
  user_id: string | null;
  session_id: string | null;
  host: string | null;
  expires_at: Timestamp;
  used_at: NullableTimestamp;
  created_at: Timestamp;
}

export type KeyType = "secret" | "publishable" | "restricted";

export interface ApiKeysTable {
  id: string;
  account_id: string;
  livemode: boolean;
  type: KeyType;
  key_hash: Buffer;
  display_prefix: string;
  last4: string;
  scopes: TextArray;
  name: string;
  ip_allowlist: TextArray;
  created_by: string;
  created_at: Timestamp;
  expires_at: NullableTimestamp;
  revoked_at: NullableTimestamp;
  last_used_at: NullableTimestamp;
  rolled_to: string | null;
}

export type DestinationStatus = "pending_verification" | "pending_approval" | "cooling_off" | "active" | "disabled";

export type Attestation = {
  standard: "nep413" | "eip191";
  message: string;
  signature: string;
  public_key: string | null;
  verified_at: string;
  method: "ed25519" | "implicit" | "full_access_key" | "ecrecover" | "erc1271";
};

export interface SettlementDestinationsTable {
  id: string;
  account_id: string;
  livemode: boolean;
  asset_id: string;
  type: "chain_address" | "intents_account";
  chain: string;
  address: string;
  address_norm: string;
  label: string;
  status: DestinationStatus;
  verification: "signature" | "unverified" | "test";
  attestation: NullableJson<Attestation>;
  per_payment_cap_usd_micros: ColumnType<string | null, number | bigint | null | undefined, number | bigint | null>;
  approvals_required: Generated<number>;
  active_at: NullableTimestamp;
  screening_id: string | null;
  created_by: string;
  disabled_at: NullableTimestamp;
  disabled_reason: "merchant" | "compliance" | "replaced" | null;
  created_at: Timestamp;
  updated_at: Timestamp;
  version: Generated<number>;
}

export interface DestinationTransitionsTable {
  id: string;
  destination_id: string;
  from_state: string | null;
  to_state: string;
  cause: string;
  actor: string;
  evidence: NullableJson<Record<string, unknown>>;
  created_at: Timestamp;
}

export interface DefaultDestinationsTable {
  account_id: string;
  livemode: boolean;
  asset_id: string | null;
  coalesce_asset: ColumnType<string, never, never>;
  destination_id: string;
  updated_at: Timestamp;
}

export interface AttestationChallengesTable {
  id: string;
  destination_id: string;
  standard: "nep413" | "eip191" | "solana" | "bip322";
  message: string;
  nonce: Buffer;
  expires_at: Timestamp;
  used_at: NullableTimestamp;
  /** Set when a newer challenge was issued for the destination (migration 0003); no longer accepted. */
  superseded_at: NullableTimestamp;
  created_at: Timestamp;
}

export interface OpsOperatorsTable {
  user_id: string;
  role: "ops" | "ops_admin";
  created_at: Timestamp;
  revoked_at: NullableTimestamp;
}

export interface AuditEventsTable {
  id: string;
  account_id: string | null;
  actor_type: "user" | "api_key" | "service" | "ops" | "system";
  actor_id: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: Json<Record<string, unknown>>;
  ip_enc: Buffer | null;
  created_at: Timestamp;
}

export interface IdentityTables {
  fee_schedules: FeeSchedulesTable;
  accounts: AccountsTable;
  users: UsersTable;
  memberships: MembershipsTable;
  passkeys: PasskeysTable;
  sessions: SessionsTable;
  magic_links: MagicLinksTable;
  registration_tokens: RegistrationTokensTable;
  webauthn_challenges: WebauthnChallengesTable;
  api_keys: ApiKeysTable;
  settlement_destinations: SettlementDestinationsTable;
  settlement_destination_transitions: DestinationTransitionsTable;
  account_default_destinations: DefaultDestinationsTable;
  attestation_challenges: AttestationChallengesTable;
  ops_operators: OpsOperatorsTable;
  audit_events: AuditEventsTable;
}

export type DB = IdentityTables & KitTables;

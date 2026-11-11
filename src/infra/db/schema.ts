/** Kysely table types (migrations/0001…0010). */
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
  /** `theme` / `corner_radius` from spec 0.2.1; absent on older rows (views fill the defaults). */
  branding: {
    accent_color: string | null;
    logo_url: string | null;
    theme?: "auto" | "light" | "dark";
    corner_radius?: number;
  };
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
  /** Migration 0006 (spec 0.2.1 `Account.website`). */
  website: Generated<string | null>;
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
  /** Migration 0006: last email recovery (`Member.security.recovered_at`). */
  recovered_at: Generated<Date | null>;
  /** Migration 0006: recoveries so far (`evt.identity.user.recovered` aggregate version). */
  recovery_count: Generated<number>;
  /** Migration 0010: Google links/unlinks so far (`user_sign_in_methods` aggregate version). */
  sign_in_methods_version: Generated<number>;
}

export type Role = "owner" | "admin" | "developer" | "finance" | "support" | "viewer";

export interface MembershipsTable {
  account_id: string;
  user_id: string;
  role: Role;
  created_at: Timestamp;
  /** Migration 0004: sign-in picks the most recently used account; switchSessionAccount sets it. */
  last_used_at: NullableTimestamp;
}

export type InvitationStatus = "pending" | "accepted" | "revoked" | "expired";

export interface InvitationsTable {
  id: string;
  account_id: string;
  email: string;
  role: Role;
  status: InvitationStatus;
  invited_by: string;
  expires_at: Timestamp;
  accepted_at: NullableTimestamp;
  accepted_by: string | null;
  revoked_at: NullableTimestamp;
  created_at: Timestamp;
}

export interface DestinationApprovalsTable {
  destination_id: string;
  user_id: string;
  decision: "approve" | "reject";
  created_at: Timestamp;
}

/** Owner/admin role grants (migration 0005), written by the trigger on `memberships`. */
export interface ManagerGrantsTable {
  id: Generated<string>;
  account_id: string;
  user_id: string;
  granted_at: Timestamp;
  qualifies_at: Timestamp;
  revoked_at: NullableTimestamp;
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
  /** Migration 0004: `ops` = hardware key registered through operator enrolment (console only). */
  kind: Generated<"dashboard" | "ops">;
  created_at: Timestamp;
  last_used_at: NullableTimestamp;
  /** Migration 0009: how an `ops` passkey was admitted (`platform_beta`: NP_OPS_ALLOW_PLATFORM_PASSKEYS). */
  ops_policy: ColumnType<"hardware" | "platform_beta" | null, "hardware" | "platform_beta" | null | undefined, never>;
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
  /** Migration 0010: how the session was created (ADR-0026). */
  auth_method: Generated<SessionAuthMethod>;
}

export type SessionAuthMethod = "passkey" | "google" | "recovery";

/** Migration 0010: external sign-in identities (ADR-0026); keyed on the provider subject. */
export interface LinkedIdentitiesTable {
  provider: "google";
  subject: string;
  user_id: string;
  email_at_link: string;
  created_at: Timestamp;
}

/** Migration 0010: a started Google flow (10 minutes, single use; hashes and the encrypted PKCE verifier only). */
export interface OauthFlowsTable {
  id: string;
  provider: "google";
  purpose: "signin" | "link";
  intent: Generated<"signin" | "signup">;
  state_hash: Buffer;
  binding_hash: Buffer;
  nonce_hash: Buffer;
  code_verifier_enc: Buffer;
  next_path: string | null;
  user_id: string | null;
  session_id: string | null;
  created_at: Timestamp;
  expires_at: Timestamp;
  used_at: NullableTimestamp;
}

export type LinkPurpose = "signup" | "recovery" | "invite" | "ops_enrol";

export interface MagicLinksTable {
  token_hash: Buffer;
  email: string;
  purpose: LinkPurpose;
  account_id: string | null;
  role: string | null;
  invitation_id: string | null;
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
  purpose: Generated<LinkPurpose>;
  user_id: string | null;
  invitation_id: string | null;
}

export type CeremonyPurpose =
  | "registration"
  | "authentication"
  | "step_up"
  | "ops_registration"
  | "ops_authentication"
  | "ops_step_up";

export interface WebauthnChallengesTable {
  challenge: string;
  purpose: CeremonyPurpose;
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
  standard: "nep413" | "eip191" | "solana" | "bip322";
  message: string;
  signature: string;
  public_key: string | null;
  verified_at: string;
  method:
    | "ed25519"
    | "implicit"
    | "full_access_key"
    | "ecrecover"
    | "erc1271"
    | "solana_ed25519"
    | "bip322_p2wpkh"
    | "bip322_p2tr";
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
  disabled_reason: "merchant" | "compliance" | "replaced" | "expired" | null;
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
  /** Migration 0009: the operator's latest console passkey — policy, attachment, synced, when. */
  passkey_policy: ColumnType<"hardware" | "platform_beta" | null, "hardware" | "platform_beta" | null | undefined>;
  passkey_attachment: ColumnType<
    "platform" | "cross-platform" | null,
    "platform" | "cross-platform" | null | undefined
  >;
  passkey_synced: ColumnType<boolean | null, boolean | null | undefined>;
  passkey_registered_at: NullableTimestamp;
}

export type AuditActorType = "user" | "api_key" | "service" | "ops" | "operator" | "system";

export interface AuditEventsTable {
  id: string;
  account_id: string | null;
  actor_type: AuditActorType;
  actor_id: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: Json<Record<string, unknown>>;
  ip_enc: Buffer | null;
  /** Migration 0007: where the action was requested from when that differs from the actor (CLI login IP). */
  origin_ip_enc: ColumnType<Buffer | null, Buffer | null | undefined, Buffer | null>;
  created_at: Timestamp;
}

export type CliLoginStatus = "pending" | "approved" | "denied" | "expired" | "redeemed";

/** Migration 0007 (lld/identity.md §6.2). */
export interface CliLoginsTable {
  id: string;
  device_code_sha256: Buffer;
  user_code: string;
  device_name: string;
  client_version: string | null;
  ip_enc: Buffer | null;
  country: string | null;
  user_agent: string | null;
  status: ColumnType<CliLoginStatus, CliLoginStatus | undefined, CliLoginStatus>;
  account_id: string | null;
  key_id: string | null;
  key_secret_enc: Buffer | null;
  approved_by: string | null;
  decided_at: NullableTimestamp;
  created_at: Timestamp;
  expires_at: Timestamp;
  last_polled_at: NullableTimestamp;
  updated_at: Timestamp;
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
  invitations: InvitationsTable;
  destination_approvals: DestinationApprovalsTable;
  manager_grants: ManagerGrantsTable;
  cli_logins: CliLoginsTable;
  linked_identities: LinkedIdentitiesTable;
  oauth_flows: OauthFlowsTable;
}

export type DB = IdentityTables & KitTables;

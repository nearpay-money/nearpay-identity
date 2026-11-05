-- nearpay-identity (lld/identity.md §4). Accounts, users, passkeys and sessions, API keys,
-- settlement destinations (attestation, cool-off, defaults), fee schedules, ops operators, audit.

create extension if not exists citext;

create table fee_schedules (
  id uuid primary key,
  name text not null unique,
  rules jsonb not null,                -- {same_asset|stable_pair|volatile|intents_transfer: {total_bps, min_fee_usd_micros}}
  provider_split jsonb not null,       -- {oneclick: {share_bps, floor_bps, stable_floor_bps}}
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now());

-- Q-BIZ-02 defaults (all-in bps; 1Click keeps half of appFees on its routes).
insert into fee_schedules (id, name, rules, provider_split) values (
  '01900000-0000-7000-8000-000000000001', 'standard',
  '{"same_asset":{"total_bps":20,"min_fee_usd_micros":0},"stable_pair":{"total_bps":50,"min_fee_usd_micros":0},"volatile":{"total_bps":100,"min_fee_usd_micros":0},"intents_transfer":{"total_bps":30,"min_fee_usd_micros":1000}}',
  '{"oneclick":{"share_bps":5000,"floor_bps":20,"stable_floor_bps":1}}');

create table accounts (
  id uuid primary key,
  display_name text not null,
  verified_legal_name text,
  country char(2),
  status text not null default 'active' check (status in ('active','suspended','closed')),
  kyb_status text not null default 'not_started'
    check (kyb_status in ('not_started','pending','needs_info','approved','rejected')),
  live_enabled boolean not null default false,
  fee_schedule_id uuid not null references fee_schedules(id),
  fee_bearer text not null default 'payer' check (fee_bearer in ('payer','merchant')),
  api_version text not null,
  settings jsonb not null,
  recovered_at timestamptz,
  -- last applied compliance aggregate versions (consumers ignore stale events, foundations §8)
  kyb_source_version integer not null default 0,
  status_source_version integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  version integer not null default 1);

create table users (
  id uuid primary key,
  email citext not null unique,
  email_verified_at timestamptz,
  name_enc bytea,
  status text not null default 'active' check (status in ('active','disabled')),
  created_at timestamptz not null default now(),
  last_login_at timestamptz);

create table memberships (
  account_id uuid not null references accounts(id),
  user_id uuid not null references users(id),
  role text not null check (role in ('owner','admin','developer','finance','support','viewer')),
  created_at timestamptz not null default now(),
  primary key (account_id, user_id));
create index memberships_user on memberships (user_id);

create table passkeys (
  id uuid primary key,
  user_id uuid not null references users(id),
  credential_id bytea not null unique,
  public_key bytea not null,
  sign_count bigint not null,
  transports text[] not null default '{}',
  aaguid uuid,
  backed_up boolean not null default false,
  name text not null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz);
create index passkeys_user on passkeys (user_id);

create table sessions (
  id uuid primary key,
  kind text not null default 'dashboard' check (kind in ('dashboard','ops')),
  user_id uuid not null references users(id),
  account_id uuid references accounts(id),             -- null for ops sessions
  token_hash bytea not null unique,
  csrf_hash bytea not null,
  csrf_enc bytea not null,                             -- encrypted copy: re-issued with the session object
  step_up_at timestamptz,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,                     -- absolute (7 days)
  last_seen_at timestamptz not null,                   -- sliding (12 h)
  revoked_at timestamptz,
  ip_enc bytea,
  user_agent text,
  check ((kind = 'dashboard') = (account_id is not null)));
create index sessions_user on sessions (user_id) where revoked_at is null;
create index sessions_expiry on sessions (expires_at);

create table magic_links (
  token_hash bytea primary key,
  email citext not null,
  purpose text not null check (purpose in ('signup','recovery','invite')),
  account_id uuid,
  role text,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now());
create index magic_links_email on magic_links (email, created_at desc);

-- verified email → passkey registration (5 minutes, single use)
create table registration_tokens (
  token_hash bytea primary key,
  email citext not null,
  user_handle bytea not null,                          -- WebAuthn user.id for the future user
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now());

create table webauthn_challenges (
  challenge text primary key,                          -- base64url, as echoed in clientDataJSON
  purpose text not null check (purpose in ('registration','authentication','step_up')),
  registration_token_hash bytea,
  user_id uuid,
  session_id uuid,
  host text,                                           -- dashboard or ops host the ceremony started on
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now());
create index webauthn_challenges_expiry on webauthn_challenges (expires_at);

create table api_keys (
  id uuid primary key,
  account_id uuid not null references accounts(id),
  livemode boolean not null,
  type text not null check (type in ('secret','publishable','restricted')),
  key_hash bytea not null unique,                      -- sha256(full key)
  display_prefix text not null,
  last4 char(4) not null,
  scopes text[] not null default '{}',
  name text not null,
  ip_allowlist cidr[] not null default '{}',
  created_by uuid not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  rolled_to uuid);
create index api_keys_account on api_keys (account_id, livemode, created_at desc) where revoked_at is null;

create table settlement_destinations (
  id uuid primary key,
  account_id uuid not null references accounts(id),
  livemode boolean not null,
  asset_id text not null,
  type text not null check (type in ('chain_address','intents_account')),
  chain text not null,
  address text not null,
  address_norm text not null,
  label text not null,
  status text not null check (status in ('pending_verification','pending_approval','cooling_off','active','disabled')),
  verification text not null check (verification in ('signature','unverified','test')),
  attestation jsonb,                                   -- {standard, message, signature, public_key, verified_at}
  per_payment_cap_usd_micros bigint,
  approvals_required smallint not null default 1,
  active_at timestamptz,
  screening_id text,
  created_by uuid not null,
  disabled_at timestamptz,
  disabled_reason text check (disabled_reason in ('merchant','compliance','replaced')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  version integer not null default 1);
-- one live signature-verified destination per (chain, address, asset) across all accounts (L-ID-06)
create unique index destinations_unique_live on settlement_destinations (chain, address_norm, asset_id)
  where status in ('pending_approval','cooling_off','active') and livemode and verification = 'signature';
create index destinations_account on settlement_destinations (account_id, livemode, status, created_at desc);

create table settlement_destination_transitions (
  id uuid primary key,
  destination_id uuid not null references settlement_destinations(id),
  from_state text,
  to_state text not null,
  cause text not null,
  actor text not null,
  evidence jsonb,
  created_at timestamptz not null default now());
create index destination_transitions_dest on settlement_destination_transitions (destination_id, created_at);

create table account_default_destinations (
  account_id uuid not null references accounts(id),
  livemode boolean not null,
  asset_id text,                                       -- null = account default
  coalesce_asset text generated always as (coalesce(asset_id, '*')) stored,
  destination_id uuid not null references settlement_destinations(id),
  updated_at timestamptz not null default now(),
  primary key (account_id, livemode, coalesce_asset));

create table destination_approvals (
  destination_id uuid not null references settlement_destinations(id),
  user_id uuid not null references users(id),
  decision text not null check (decision in ('approve','reject')),
  created_at timestamptz not null default now(),
  primary key (destination_id, user_id));

create table attestation_challenges (
  id uuid primary key,
  destination_id uuid not null references settlement_destinations(id),
  standard text not null check (standard in ('nep413','eip191','solana','bip322')),
  message text not null,
  nonce bytea not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now());
create index attestation_challenges_dest on attestation_challenges (destination_id);

create table ops_operators (
  user_id uuid primary key references users(id),
  role text not null check (role in ('ops','ops_admin')),
  created_at timestamptz not null default now(),
  revoked_at timestamptz);

create table audit_events (
  id uuid primary key,
  account_id uuid,
  actor_type text not null check (actor_type in ('user','api_key','service','ops','system')),
  actor_id text not null,
  action text not null,
  target_type text,
  target_id text,
  details jsonb not null default '{}',
  ip_enc bytea,
  created_at timestamptz not null default now());
create index audit_account on audit_events (account_id, created_at desc);

-- the audit log is append-only (security §12): no updates or deletes, even by the app role
create function audit_events_append_only() returns trigger language plpgsql as $$
begin
  raise exception 'audit_events is append-only';
end $$;
create trigger audit_events_no_update before update or delete on audit_events
  for each statement execute function audit_events_append_only();

-- sentinel's independent view of active destinations (sentinel LLD §5); SELECT only for sentinel_ro
create view sentinel_destination_registry as
  select d.id, d.account_id, d.livemode, d.asset_id, d.type, d.chain, d.address_norm, d.status, d.active_at,
         coalesce(a.verified_legal_name, a.display_name) as merchant_name, a.verified_legal_name is not null as kyb_verified
  from settlement_destinations d join accounts a on a.id = d.account_id where d.status = 'active';
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'sentinel_ro') then
    execute 'grant select on sentinel_destination_registry to sentinel_ro';
  end if;
end $$;

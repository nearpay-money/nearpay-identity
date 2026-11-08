-- CLI login (lld/identity.md §6.2, spec 0.3.0 `src/public/cli.ts`): device authorization minting an
-- ordinary restricted test key. Additive and forward-only. (The LLD named it 0006; 0006 was taken by
-- the spec 0.2.1 migration.)

create table cli_logins (
  id uuid primary key,
  device_code_sha256 bytea not null unique,          -- the device code itself is never stored
  user_code text not null check (user_code ~ '^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$'),
  device_name text not null check (char_length(device_name) between 1 and 64),
  client_version text check (char_length(client_version) <= 32),
  ip_enc bytea,                                      -- envelope-encrypted client IP (PII at rest)
  country text check (country ~ '^[A-Z0-9]{2}$'),
  user_agent text check (char_length(user_agent) <= 256),
  status text not null default 'pending'
    check (status in ('pending','approved','denied','expired','redeemed')),
  account_id uuid references accounts(id),           -- account that decided it (approve: the key's account)
  key_id uuid references api_keys(id),
  key_secret_enc bytea,                              -- only between approval and the redeeming poll
  approved_by uuid,                                  -- deciding user (approve or deny)
  decided_at timestamptz,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  last_polled_at timestamptz,
  updated_at timestamptz not null default now(),
  -- the secret exists only on an approved row with a key; a decided row names its account and user
  check (key_secret_enc is null or (status = 'approved' and key_id is not null)),
  check ((status in ('approved','redeemed') and key_id is not null)
         or (status in ('pending','denied') and key_id is null)
         or status = 'expired'),
  check (status not in ('approved','denied','redeemed')
         or (account_id is not null and approved_by is not null and decided_at is not null))
);
-- one live login per user code (a code may be reused once its login left `pending`)
create unique index cli_logins_user_code_pending on cli_logins (user_code) where status = 'pending';
create index cli_logins_user_code on cli_logins (user_code, created_at desc);
-- the expiry job's scans
create index cli_logins_open on cli_logins (status, expires_at) where status in ('pending','approved');

-- the login IP of a CLI-minted key stays provable after the login row is purged (7 days): kept
-- envelope-encrypted on the audit row (`details` holds no personal data, spec AuditEvent)
alter table audit_events add column origin_ip_enc bytea;

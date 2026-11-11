-- Continue with Google (ADR-0026, lld/identity.md §22). Additive and forward-only.
--
-- linked_identities: a user's external sign-in identity. The key is the provider's subject (Google `sub`),
-- never the email; at most one identity per provider and user. `email_at_link` is shown only.
create table linked_identities (
  provider text not null check (provider in ('google')),
  subject text not null check (length(subject) between 1 and 255),
  user_id uuid not null references users(id),
  email_at_link citext not null,
  created_at timestamptz not null default now(),
  primary key (provider, subject));
create unique index linked_identities_user_provider on linked_identities (user_id, provider);

-- oauth_flows: one row per started Google flow (10 minutes, single use). Secrets are never stored in clear:
-- the `state`, the cookie binding and the `nonce` as SHA-256, the PKCE verifier envelope-encrypted (the token
-- request needs it in clear). A `link` flow remembers the stepped-up session that started it.
create table oauth_flows (
  id uuid primary key,
  provider text not null check (provider in ('google')),
  purpose text not null check (purpose in ('signin', 'link')),
  intent text not null default 'signin' check (intent in ('signin', 'signup')),
  state_hash bytea not null unique,
  binding_hash bytea not null,
  nonce_hash bytea not null,
  code_verifier_enc bytea not null,
  next_path text check (next_path is null or length(next_path) <= 512),
  user_id uuid references users(id),
  session_id uuid references sessions(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz,
  check ((purpose = 'link') = (user_id is not null and session_id is not null)));
create index oauth_flows_expires on oauth_flows (expires_at);

-- How each dashboard session was created: a Google session carries no step-up, and a Google-only user may
-- add a first passkey only within 10 minutes of the Google sign-in.
alter table sessions add column auth_method text not null default 'passkey'
  check (auth_method in ('passkey', 'google', 'recovery'));

-- Aggregate version of evt.identity.user.google_linked / google_unlinked (`user_sign_in_methods`).
alter table users add column sign_in_methods_version integer not null default 0;

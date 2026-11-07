-- Stage 2 (lld/identity.md v1.7 §4–§7): team members and invitations, multi-account sessions,
-- recovery, the two-approver rule, restricted keys, console (ops) enrolment and sessions, the unified
-- audit trail. Additive and forward-only: new tables and columns, widened check constraints.

-- ---- multi-account sessions: sign-in picks the most recently used account -------------------------
alter table memberships add column last_used_at timestamptz;
-- `evt.identity.member.*` aggregate versions: memberships are deleted on removal, so a per-row
-- version would restart on re-join; one sequence keeps every member's events ordered
create sequence membership_event_version;
create index memberships_account_role on memberships (account_id, role);

-- ---- console passkeys: only `ops` passkeys (hardware keys registered through operator enrolment)
-- sign in to the console; dashboard passkeys never do, and ops passkeys never sign in to the dashboard
alter table passkeys add column kind text not null default 'dashboard' check (kind in ('dashboard','ops'));

-- ---- magic links: invitations (7 days) and operator enrolment (24 h) -----------------------------
alter table magic_links drop constraint magic_links_purpose_check;
alter table magic_links add constraint magic_links_purpose_check
  check (purpose in ('signup','recovery','invite','ops_enrol'));
alter table magic_links add column invitation_id uuid;

-- registration tokens remember why the email was verified: `signup` creates a user and an account,
-- `recovery` adds a passkey to `user_id`, `invite` joins `invitation_id`, `ops_enrol` registers the
-- operator `user_id`'s hardware key
alter table registration_tokens add column purpose text not null default 'signup'
  check (purpose in ('signup','recovery','invite','ops_enrol'));
alter table registration_tokens add column user_id uuid references users(id);
alter table registration_tokens add column invitation_id uuid;

-- ---- WebAuthn ceremonies on the console host (RP id = console host) -------------------------------
alter table webauthn_challenges drop constraint webauthn_challenges_purpose_check;
alter table webauthn_challenges add constraint webauthn_challenges_purpose_check
  check (purpose in ('registration','authentication','step_up','ops_registration','ops_authentication','ops_step_up'));

-- ---- invitations (inv_) ----------------------------------------------------------------------------
create table invitations (
  id uuid primary key,
  account_id uuid not null references accounts(id),
  email citext not null,
  role text not null check (role in ('owner','admin','developer','finance','support','viewer')),
  status text not null check (status in ('pending','accepted','revoked','expired')),
  invited_by uuid not null references users(id),
  expires_at timestamptz not null,
  accepted_at timestamptz,
  accepted_by uuid references users(id),
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  check ((status = 'accepted') = (accepted_at is not null and accepted_by is not null)));
-- one pending invitation per (account, email): `409 member_exists`
create unique index invitations_one_pending on invitations (account_id, email) where status = 'pending';
create index invitations_account on invitations (account_id, created_at desc);

-- ---- two-approver rule (identity §5) ---------------------------------------------------------------
-- The creator's own creation is an approval row, so the primary key (destination_id, user_id) itself
-- refuses a second approval by the creator, and the trigger below refuses to move a live destination
-- past approval with fewer distinct approving users than `approvals_required`: no single principal can
-- complete a destination change on a multi-admin account, whatever the application does.
insert into destination_approvals (destination_id, user_id, decision, created_at)
  select d.id, d.created_by, 'approve', d.created_at
  from settlement_destinations d join users u on u.id = d.created_by
  where d.verification <> 'test'
  on conflict do nothing;

alter table settlement_destinations add constraint settlement_destinations_approvals_range
  check (approvals_required between 1 and 2) not valid;
alter table settlement_destinations validate constraint settlement_destinations_approvals_range;

create function destination_approvals_complete() returns trigger language plpgsql as $$
declare
  approvals integer;
begin
  if new.livemode and new.verification <> 'test'
     and old.status in ('pending_verification','pending_approval')
     and new.status in ('cooling_off','active') then
    select count(distinct user_id) into approvals
      from destination_approvals where destination_id = new.id and decision = 'approve';
    if approvals < new.approvals_required then
      raise exception 'destination % needs % distinct approvals, has %', new.id, new.approvals_required, approvals
        using errcode = 'check_violation', constraint = 'destination_approvals_complete';
    end if;
  end if;
  return new;
end $$;
create trigger destination_approvals_complete before update of status on settlement_destinations
  for each row execute function destination_approvals_complete();

-- approvals and rejections are append-only facts (who approved stays provable, INV-9)
create function destination_approvals_append_only() returns trigger language plpgsql as $$
begin
  raise exception 'destination_approvals is append-only';
end $$;
create trigger destination_approvals_no_update before update or delete on destination_approvals
  for each statement execute function destination_approvals_append_only();

-- ---- audit trail: operator actions from every service (T-12) --------------------------------------
alter table audit_events drop constraint audit_events_actor_type_check;
alter table audit_events add constraint audit_events_actor_type_check
  check (actor_type in ('user','api_key','service','ops','operator','system'));
create index audit_created on audit_events (created_at desc, id desc);
create index audit_actor on audit_events (actor_id, created_at desc);

-- Stage 2 audit fix (lld/identity.md v1.8 §5 "Two-approver rule", §18): one person must not be able to
-- satisfy the two-approver rule with a puppet admin, by removing the other managers before creating a
-- destination, or by approving a destination that waited indefinitely. Additive and forward-only.
--
-- manager_grants is the history of owner/admin role grants per (account, user), written only by the
-- trigger on memberships below (so every path — sign-up, invitations, role changes, removals, ops CLI —
-- records it). A grant starts counting for approvals at `qualifies_at`: 7 days after the grant, or
-- 30 days when two or more other users held owner/admin in the 30 days before it (a contested team:
-- a new manager added next to existing ones cannot vote for a month, so one person cannot outvote the
-- other managers with users they invited). Owner <-> admin changes keep the grant; leaving the
-- owner/admin roles (demotion or removal) closes it; coming back opens a new one.

create table manager_grants (
  id bigint generated always as identity primary key,
  account_id uuid not null references accounts(id),
  user_id uuid not null references users(id),
  granted_at timestamptz not null,
  qualifies_at timestamptz not null,
  revoked_at timestamptz,
  check (qualifies_at >= granted_at),
  check (revoked_at is null or revoked_at >= granted_at));
create unique index manager_grants_open on manager_grants (account_id, user_id) where revoked_at is null;
create index manager_grants_account on manager_grants (account_id, granted_at);

-- When a grant of owner/admin to `p_user` at `p_at` starts counting (mirrored by grantQualifiesAt in
-- src/domain/approval/approval.ts): distinct other managers whose grant overlaps [p_at - 30 d, p_at].
create function manager_qualifies_at(p_account uuid, p_user uuid, p_at timestamptz) returns timestamptz
language sql stable as $$
  select p_at + case
    when (select count(distinct g.user_id) from manager_grants g
           where g.account_id = p_account and g.user_id <> p_user and g.granted_at <= p_at
             and (g.revoked_at is null or g.revoked_at >= p_at - interval '30 days')) >= 2
    then interval '30 days' else interval '7 days' end
$$;

create function memberships_manager_grants() returns trigger language plpgsql as $$
declare
  was_manager boolean := tg_op in ('UPDATE','DELETE') and old.role in ('owner','admin');
  is_manager boolean := tg_op in ('INSERT','UPDATE') and new.role in ('owner','admin');
begin
  if was_manager and not is_manager then
    update manager_grants set revoked_at = now()
      where account_id = old.account_id and user_id = old.user_id and revoked_at is null;
  elsif is_manager and not was_manager then
    insert into manager_grants (account_id, user_id, granted_at, qualifies_at)
      values (new.account_id, new.user_id, now(), manager_qualifies_at(new.account_id, new.user_id, now()));
  end if;
  return null;
end $$;
create trigger memberships_manager_grants after insert or update of role or delete on memberships
  for each row execute function memberships_manager_grants();

-- ---- backfill ----------------------------------------------------------------------------------------
-- TypeID (`usr_…`) → uuid, to read user ids out of the audit log (Crockford base32, 26 characters).
create function typeid_uuid(p_id text) returns uuid language plpgsql immutable as $$
declare
  s text := substring(p_id from '_([0-7][0-9a-hjkmnp-tv-z]{25})$');
  bits text := '';
  hex text := '';
  i integer;
begin
  if s is null then return null; end if;
  for i in 1..26 loop
    bits := bits || (strpos('0123456789abcdefghjkmnpqrstvwxyz', substr(s, i, 1)) - 1)::bit(5)::text;
  end loop;
  bits := substr(bits, 3); -- 130 bits, the top two are zero
  for i in 0..31 loop
    hex := hex || to_hex(substr(bits, i * 4 + 1, 4)::bit(4)::integer);
  end loop;
  return hex::uuid;
end $$;

-- Current managers: granted when the membership was created or, if later, when the audit log last saw
-- their role change (conservative: a later grant time only delays when they count).
insert into manager_grants (account_id, user_id, granted_at, qualifies_at)
select m.account_id, m.user_id, g.at, g.at
from memberships m
cross join lateral (
  select greatest(m.created_at, coalesce(max(a.created_at), m.created_at)) as at
  from audit_events a
  where a.account_id = m.account_id and a.action = 'member.role_changed' and typeid_uuid(a.target_id) = m.user_id
) g
where m.role in ('owner','admin');

-- Managers who left the owner/admin roles in the last 30 days (removed or demoted): closed grants, so
-- the 30-day high-water mark of managers still sees them.
insert into manager_grants (account_id, user_id, granted_at, qualifies_at, revoked_at)
select distinct on (a.account_id, typeid_uuid(a.target_id))
  a.account_id, typeid_uuid(a.target_id), a.created_at, a.created_at, a.created_at
from audit_events a
join users u on u.id = typeid_uuid(a.target_id)
where a.account_id is not null and a.created_at >= now() - interval '30 days'
  and ((a.action = 'member.removed' and a.details->>'role' in ('owner','admin'))
    or (a.action = 'member.role_changed' and a.details->>'previous_role' in ('owner','admin')
        and a.details->>'role' not in ('owner','admin')))
  and not exists (select 1 from manager_grants g
                  where g.account_id = a.account_id and g.user_id = typeid_uuid(a.target_id) and g.revoked_at is null)
order by a.account_id, typeid_uuid(a.target_id), a.created_at desc;

update manager_grants set qualifies_at = manager_qualifies_at(account_id, user_id, granted_at) where revoked_at is null;

-- ---- the two-approver rule in the database ---------------------------------------------------------
-- Repeats the application rule (src/domain/approval/approval.ts): a live, non-test destination moves
-- to cooling_off or active (also at activation) only with no rejection and enough distinct approving
-- users who hold owner/admin now. Required = the greatest of the stored `approvals_required`, 2 when
-- the account has ≥ 2 managers now, and 2 when ≥ 2 users held owner/admin in the last 30 days. With 2
-- required an approval counts only when the approver's grant predates the destination and has reached
-- `qualifies_at`.
create or replace function destination_approvals_complete() returns trigger language plpgsql as $$
declare
  current_n integer;
  recent_n integer;
  required integer;
  approvals integer;
begin
  if new.livemode and new.verification <> 'test'
     and old.status in ('pending_verification','pending_approval','cooling_off')
     and new.status in ('cooling_off','active') and new.status <> old.status then
    select count(distinct user_id) into current_n
      from manager_grants where account_id = new.account_id and revoked_at is null;
    select count(distinct user_id) into recent_n
      from manager_grants where account_id = new.account_id and granted_at <= now()
        and (revoked_at is null or revoked_at >= now() - interval '30 days');
    required := greatest(new.approvals_required,
                         case when current_n >= 2 then 2 else 1 end,
                         case when recent_n >= 2 then 2 else 1 end);
    select count(distinct a.user_id) into approvals
      from destination_approvals a
      join manager_grants g on g.account_id = new.account_id and g.user_id = a.user_id and g.revoked_at is null
      where a.destination_id = new.id and a.decision = 'approve'
        and (required < 2 or (g.granted_at < new.created_at and g.qualifies_at <= now()))
        and not exists (select 1 from destination_approvals r where r.destination_id = new.id and r.decision = 'reject');
    if approvals < required then
      raise exception 'destination % needs % distinct approvals by qualified owners/admins, has %',
        new.id, required, approvals
        using errcode = 'check_violation', constraint = 'destination_approvals_complete';
    end if;
  end if;
  return new;
end $$;

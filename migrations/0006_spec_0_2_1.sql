-- Spec 0.2.1 (lld/identity.md §"Spec 0.2.1 contract changes"). Additive and forward-only.

-- `Account.website` (settable via updateAccount; null clears it)
alter table accounts add column website text;

-- `Member.security.recovered_at` and the `evt.identity.user.recovered` aggregate version (the user's
-- recovery count): the account-level `recovered_at` drives the lock, the user-level one the summary
alter table users add column recovered_at timestamptz;
alter table users add column recovery_count integer not null default 0 check (recovery_count >= 0);

-- pending live destinations that waited 7 days are disabled with their own reason (was `merchant`)
alter table settlement_destinations drop constraint settlement_destinations_disabled_reason_check;
alter table settlement_destinations add constraint settlement_destinations_disabled_reason_check
  check (disabled_reason in ('merchant','compliance','replaced','expired'));

-- `getNotificationRecipients?user=` also finds a member removed in the last 7 days (audit trail)
create index audit_account_action_target on audit_events (account_id, action, target_id, created_at desc);

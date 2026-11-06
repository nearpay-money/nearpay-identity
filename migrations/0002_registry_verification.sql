-- Sentinel registry view, version 2 (lld/sentinel.md §5, §7):
--  * R5: when several active rows match a quote's recipient, sentinel prefers the single
--    signature-verified one, so the view carries `verification`;
--  * audit: sentinel checks that a settlement reached a destination that was active for the account
--    when the execution was created, so the view also lists destinations that were active once and are
--    now disabled, with `disabled_at`. The co-signer filters `status = 'active'` itself.
-- Columns are appended (replacing a view may only add columns at the end); the sentinel_ro grant is kept.
create or replace view sentinel_destination_registry as
  select d.id, d.account_id, d.livemode, d.asset_id, d.type, d.chain, d.address_norm, d.status, d.active_at,
         coalesce(a.verified_legal_name, a.display_name) as merchant_name, a.verified_legal_name is not null as kyb_verified,
         d.verification, d.disabled_at
  from settlement_destinations d join accounts a on a.id = d.account_id
  where d.status = 'active' or (d.status = 'disabled' and d.active_at is not null);

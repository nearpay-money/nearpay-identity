-- Console operator passkeys: how each was admitted, recorded on the passkey and on the operator
-- (lld/identity.md §6.1). Additive and forward-only.
--
-- `hardware`: the hardware-key policy (attested, allow-listed, device-bound). `platform_beta`: BETA ONLY
-- (NP_OPS_ALLOW_PLATFORM_PASSKEYS=true, remove before the VPS) — a platform / synced passkey (Touch ID,
-- iCloud Keychain, Google Password Manager); such a passkey signs in only while the flag is on.
alter table passkeys add column ops_policy text check (ops_policy in ('hardware','platform_beta'));
alter table passkeys add constraint passkeys_ops_policy_kind check (ops_policy is null or kind = 'ops');

alter table ops_operators
  add column passkey_policy text check (passkey_policy in ('hardware','platform_beta')),
  add column passkey_attachment text check (passkey_attachment in ('platform','cross-platform')),
  add column passkey_synced boolean,
  add column passkey_registered_at timestamptz;

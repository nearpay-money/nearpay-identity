-- Stage 4 (lld/identity.md §20): live Bitcoin settlement destinations are P2WPKH (bc1q…, 20-byte program)
-- or P2TR (bc1p…, 32-byte program) only — the address types BIP-322 "simple" can prove ownership of. The
-- service refuses other types with `address_invalid` in both modes; this constraint repeats the rule for
-- live rows. Live Bitcoin rows could not exist before Stage 4 (Stage 1 refused them), so the constraint
-- validates at once; test-mode rows created before Stage 4 are untouched. Additive and forward-only.

alter table settlement_destinations add constraint settlement_destinations_bitcoin_live_type
  check (
    not livemode
    or chain <> 'bip122:000000000019d6689c085ae165831e93'
    or address_norm ~ '^bc1(q[02-9ac-hj-np-z]{38}|p[02-9ac-hj-np-z]{58})$'
  ) not valid;
alter table settlement_destinations validate constraint settlement_destinations_bitcoin_live_type;

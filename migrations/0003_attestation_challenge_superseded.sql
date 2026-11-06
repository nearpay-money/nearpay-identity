-- Re-issued attestation challenges (spec 0.1.5, `POST /v1/settlement_destinations/{id}/challenge`):
-- issuing a fresh challenge supersedes the destination's earlier unused ones, which then stop being
-- accepted by `…/attest` (`challenge_expired`). Kept apart from `used_at` so a superseded challenge is
-- never mistaken for a used one; the hourly purge still removes unused challenges 30 days after expiry.
alter table attestation_challenges add column superseded_at timestamptz;

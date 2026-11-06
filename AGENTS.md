# AGENTS.md — nearpay-identity

You are working in **nearpay-identity**, one of 27 NearPay repositories (`nearpay-brain/architecture/repositories.md`).
Scope: Accounts, users, roles, passkey sessions, API keys, settlement destinations with attestation and cool-off, gateway authorisation.

## Before changing anything

1. Read `../nearpay-brain/AGENTS.md`, then this repo's LLD (`../nearpay-brain/lld/identity.md`) — it is the implementation spec; do not make design decisions it already makes.
2. Contracts (requests, responses, events, errors) come from `@nearpay/spec`. If one must change, open a PR in `nearpay-spec` first; never hand-write contract types here.
3. Check your change against invariants INV-1…INV-9 in `nearpay-brain/product/requirements.md`.

## Rules for this repo

- Hexagonal layout: `src/domain` is pure; `src/app` holds use cases; `src/infra` adapts Postgres, Valkey, NATS, peers, RPC and crypto; `src/api` maps spec routes to use cases.
- Every state change writes the aggregate row, its transition/audit row and the outbox event in ONE transaction; consumers run in the inbox transaction and apply compliance events in aggregate-version order.
- Destinations can never be changed by API keys (INV-1 practical); every destination change needs a stepped-up owner/admin session.
- Fail closed: screening unavailable → no new destination; RPC unavailable → no attestation; a missing JWT key file → no start.
- Never log or store secrets in clear: keys, session/registration/magic-link tokens are SHA-256 only; CSRF copies and IPs are envelope-encrypted; emails are never logged.
- Authz is hot (p99 ≤ 5 ms cached): no network call on the cached path except Valkey; anything new there needs a cache and a fallback.
- The audit log is append-only (a trigger enforces it); sensitive actions write it.
- Keep ≥ 90% branch coverage on `src/domain`; attestation changes need vectors.

## Never

- Import source code from another NearPay repo (depend on published packages/images only).
- Read or write another service's database.
- Add design documents here — update `nearpay-brain` and link to it.
- Commit secrets, private keys or real customer data.
- Merge changes to paths listed in `.github/CODEOWNERS` without the required human review.

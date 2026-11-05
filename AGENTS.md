# AGENTS.md — nearpay-identity

You are working in **nearpay-identity**, one of 27 NearPay repositories (`nearpay-brain/architecture/repositories.md`).
Scope: Accounts, users, roles, passkey sessions, API keys, settlement destinations with attestation and cool-off, gateway authorisation.

## Before changing anything

1. Read `../nearpay-brain/AGENTS.md`, then this repo's LLD (`../nearpay-brain/lld/identity.md`) — it is the implementation spec; do not make design decisions it already makes.
2. Contracts (requests, responses, events, errors) come from `@nearpay/spec`. If one must change, open a PR in `nearpay-spec` first; never hand-write contract types here.
3. Check your change against invariants INV-1…INV-9 in `nearpay-brain/product/requirements.md`.

## Rules for this repo

- Hexagonal layout: `src/domain` is pure (no I/O); `src/app` holds use cases; `src/infra` adapts DB, HTTP clients and NATS; `src/api` maps spec-generated routes to use cases.
- Every state change writes the aggregate row, a transition row and an outbox row in ONE transaction.
- Every public POST honours `Idempotency-Key` inside the same transaction as the side effect.
- Every query filters by `account_id` AND `livemode` (INV-8).
- Money is bigint base units + asset/currency (`@nearpay-internal/money`). No floats.
- Consumers dedupe by event ID (inbox table) and ignore stale `aggregate_version`.

## Never

- Import source code from another NearPay repo (depend on published packages/images only).
- Read or write another service's database.
- Add design documents here — update `nearpay-brain` and link to it.
- Commit secrets, private keys or real customer data.
- Merge changes to paths listed in `.github/CODEOWNERS` without the required human review.

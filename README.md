# nearpay-identity

> Accounts, users, roles, passkey sessions, API keys, settlement destinations with attestation and cool-off, gateway authorisation.

|                                       |                                                                                                               |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Group                                 | Services                                                                                                      |
| Kind                                  | service                                                                                                       |
| Ships as                              | image: ghcr.io/nearpay-money/identity · routes /v1/account, /v1/settlement_destinations, /v1/api_keys, /authz |
| Owns                                  | Account, User, Membership, Session, Passkey, ApiKey, SettlementDestination, Approval                          |
| Depends on (published artifacts only) | spec, kit, compliance, notify                                                                                 |
| First built in                        | Stage 1 (step 1.2)                                                                                            |

## Documentation

This repo stays surgical: design docs live in [`nearpay-brain`](../nearpay-brain/README.md), not here.

- `nearpay-brain/lld/identity.md` — **low-level design (dev-ready; implement from this)**
- `nearpay-brain/lld/audits/identity.md` — audit findings already folded into the LLD
- `nearpay-brain/roadmap/development-plan.md` — stage and step this repo is built in
- `nearpay-brain/architecture/hld.md` — system design
- `nearpay-brain/architecture/repositories.md` — repo topology and dependency rules
- `nearpay-brain/decisions/ADR-0005-settlement-destinations.md`
- `nearpay-brain/decisions/ADR-0014-auth-gateway.md`
- `nearpay-brain/architecture/security.md`

## Layout

```
nearpay-identity/
├── src/
│   ├── main.ts               process entry: `api` | `worker` | `migrate` | `healthcheck`
│   ├── ops.ts                Stage 1 ops CLI entry (`node dist/ops.js <command>`, run inside identity-api)
│   ├── config.ts             NP_* configuration (secrets from files)
│   ├── api/                  spec route bindings (auth, account, API keys, destinations, internal)
│   ├── app/                  use cases: sign-up/passkeys/sessions, accounts, keys, destinations, authz, tokens, internal reads, wiring
│   ├── consumers/            compliance KYB/suspension/blocks, key cache purges
│   ├── domain/               pure: key format, sessions, destination lifecycle, account settings, gateway rules
│   ├── infra/                Kysely schema, authz caches + rate limiter (Valkey), peer/RPC/Turnstile clients, attestation crypto
│   ├── ops/                  ops CLI commands
│   └── workers/              jobs: destination activation, auth purges
├── migrations/               plain SQL (kit tables first, then 0001_identity.sql)
├── test/
│   ├── unit/ property/       domain, attestation vectors (NEP-413, EIP-191, ERC-1271), tokens, Turnstile
│   ├── integration/          through a simulated gateway (authz → route) with a software passkey; worker on NATS
│   ├── contract/             route/subject coverage, sentinel registry view, append-only audit log
│   └── support/              stack, software WebAuthn authenticator, wallet signers
└── Dockerfile                distroless Node 22 image, `node dist/main.js <process>`
```

## Commands

| Command                                                                                                     | What it does                                                                                                                                        |
| ----------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm install`                                                                                              | Install (Node 22, pnpm 9); `@nearpay/*` and `@nearpay-internal/*` come from the local registry (`.npmrc`, `nearpay-deploy/scripts/up.sh` starts it) |
| `pnpm test`                                                                                                 | Unit and property tests                                                                                                                             |
| `pnpm test:integration`                                                                                     | Integration and contract tests on real Postgres, Valkey and NATS (Testcontainers; needs Docker)                                                     |
| `pnpm verify`                                                                                               | typecheck + lint + unit tests with the coverage gate + integration tests + build                                                                    |
| `docker build --network host --build-arg NP_REGISTRY_URL=http://127.0.0.1:4873 -t nearpay/identity:local .` | Image (what `up.sh` runs)                                                                                                                           |

## Configuration

| Variable                                             | Process     | Meaning                                                                                             |
| ---------------------------------------------------- | ----------- | --------------------------------------------------------------------------------------------------- |
| `NP_DB_URL_FILE`                                     | all         | Database URL (app role; migrator role for `migrate`)                                                |
| `NP_PII_KEK_FILE`                                    | all         | 32-byte KEK: IPs, CSRF copies, idempotent responses at rest                                         |
| `NP_JWT_KEYS_DIR`                                    | all         | `current.pem` + `next.pem` (Ed25519); both published in the JWKS, `current` signs; missing → exit 1 |
| `NP_VALKEY_URL`                                      | api, worker | Key cache and rate limits (down → per-pod limits at half rate)                                      |
| `NP_NATS_URL`                                        | api, worker | Worker: events; api (optional): cross-replica cache purge                                           |
| `NP_SERVICE_CLIENTS_FILE`                            | api         | `{"clients":[{"client_id","secret_sha256"}]}`; scopes from the spec                                 |
| `NP_TURNSTILE_SECRET_FILE`                           | api         | Cloudflare secret; Cloudflare's test secrets are answered locally outside the server stage          |
| `NP_WEBAUTHN_RP_ID`, `NP_WEBAUTHN_ORIGINS`           | api         | Relying party (`nearpay.localhost` locally) and allowed origins                                     |
| `NP_DASHBOARD_ORIGIN`                                | api         | Magic links: `<origin>/auth/verify#token=…` (fragment: never in a server log)                       |
| `NP_COOLOFF_SECONDS`                                 | api, worker | Destination cool-off (86 400; 0 only when `NP_ENV=local`)                                           |
| `NP_RECOVERY_LOCK_SECONDS`                           | api         | Destination changes after an account recovery (172 800)                                             |
| `NP_COMPLIANCE_URL`, `NP_RAILS_URL`, `NP_NOTIFY_URL` | api         | Screening, assets/chain profiles/minimums, magic-link mail                                          |
| `NP_NEAR_RPC_URLS`, `NP_EVM_RPC_URLS`                | api         | Attestation lookups: NEAR `view_access_key` pool; `{"<chain id>": [urls]}` for ERC-1271             |

## Behaviour

- **Sign-up and sessions:** sign-up (Turnstile) emails a single-use magic link (15 min; up to 5 per address per hour; an existing address gets the same 202 and no mail). The link yields a 5-minute registration token; registering a discoverable passkey (user verification required, ES256/EdDSA/RS256) creates the user, the account (owner) and a session, and emits `account.created`. Sign-in is a passkey assertion without an email (no enumeration). Sessions: `__Host-np_session`, 12 h sliding / 7 days absolute, CSRF token for unsafe requests; signing in counts as a step-up; step-up (`/v1/auth/step_up/*`) is fresh for 10 minutes. `GET /v1/auth/session` (any role, sets no cookie) returns the current `DashboardSession` so a reload or a new tab recovers it: the CSRF token is the session's own, re-issued from its encrypted copy, never rotated; a cookie that is not a valid dashboard session of the request's user and account is `401`.
- **Gateway (`/internal/authz`):** API key (SHA-256 lookup through LRU 30 s → Valkey 60 s → Postgres; revoked/expired → 401; IP allowlist; publishable keys only on publishable routes) or session (CSRF on unsafe methods; `NearPay-Mode` picks test/live; console sessions on `ops.` hosts mint `ptype ops`) or anonymous on open routes. Suspended accounts cannot write in live mode; live writes on the routes that declare `account_not_live` need `live_enabled`. Token buckets: live 100/s (burst 200), test 25/50, anonymous 10/20 per IP. Mints the 60 s request token with `role` and `step_up_until`.
- **API keys:** created and rolled from a stepped-up session, shown once; revocation purges Valkey and every replica's LRU (`ctl.identity.cache.purge`).
- **Destinations:** test mode is active at once (`verification: test`). Live: address/chain/asset/memo checks against rails, screening (fail closed), one live signature-verified row per (chain, address, asset) across accounts, then an attestation challenge (`nep413` with nonce/recipient, or `eip191`), the cool-off, and the activation job (re-screen; a block disables). The first active destination per asset becomes the default. Every change writes the row, a transition and the outbox event in one transaction.
- **Live mode:** `live_enabled = KYB approved ∧ active live destination ∧ account active`, recomputed on every change (`account.updated`); compliance events are applied in aggregate-version order.
- **Internal:** JWKS, client-credentials service tokens, settlement context (account, fee schedule, active destinations, defaults, `context_version`), any destination, notification recipients.

## Ops CLI (Stage 1)

```sh
docker compose exec identity-api /nodejs/bin/node dist/ops.js seed-demo
```

`account-show <acct|email>` · `operator-add <email> ops|ops_admin` · `operator-revoke <email>` · `destination-cooloff-skip <sd_…>` (local) · `seed-demo [--email] [--name] [--destination]` (local: demo merchant with test keys and an active test destination).

## Status

Stage 1 (step 1.2) implemented: every Stage-1 identity route and consumed subject of `@nearpay-internal/spec` 0.1.2. Team members and invitations, the two-approver rule, restricted keys, recovery, console sign-in and Solana/Bitcoin attestations arrive in Stages 2 and 4 (LLD §16).

## Built with

TypeScript 5, Node 22, `@nearpay-internal/*` kit (service, db, bus, http, auth, chains, intents, ids), `@simplewebauthn/server` (WebAuthn), `@noble/curves` + `@noble/hashes` (NEP-413 / EIP-191), `bs58`, `ioredis` (Valkey), `lru-cache`, Kysely + pg, NATS JetStream; tests with Vitest, fast-check, jose and Testcontainers. Code and documentation are written with AI assistance (Claude) under human direction and review.

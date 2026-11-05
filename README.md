# nearpay-identity

> Accounts, users, roles, passkey sessions, API keys, settlement destinations with attestation and cool-off, gateway authorisation.

| | |
|---|---|
| Group | Services |
| Kind | service |
| Ships as | image: ghcr.io/nearpay-money/identity · routes /v1/account, /v1/settlement_destinations, /v1/api_keys, /authz |
| Owns | Account, User, Membership, Session, Passkey, ApiKey, SettlementDestination, Approval |
| Depends on (published artifacts only) | spec, kit, compliance, notify |
| First built in | Stage 1 (step 1.2) |

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
├── migrations/
├── src/
│   ├── api/
│   ├── app/
│   ├── consumers/
│   ├── domain/
│   │   ├── account/
│   │   ├── api-key/
│   │   ├── approval/
│   │   ├── authz/
│   │   ├── passkey/
│   │   ├── session/
│   │   ├── settlement-destination/
│   │   └── user/
│   ├── infra/
│   │   ├── bus/
│   │   ├── clients/
│   │   └── db/
│   └── workers/
├── test/
│   ├── contract/
│   ├── integration/
│   ├── property/
│   └── unit/
└── .github/
    └── workflows/
```

## Status

Scaffold only. Implementation starts in **Stage 1 (step 1.2)** (`nearpay-brain/roadmap/development-plan.md`).

## Built with

Libraries are listed here as they are added (hackathon rule Q-005). Code and documentation are written with AI assistance (Claude) under human direction and review.

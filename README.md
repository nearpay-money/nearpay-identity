# nearpay-identity

> Accounts, users, roles, passkey sessions, API keys, settlement destinations with attestation and cool-off, gateway authorisation.

| | |
|---|---|
| Group | Services |
| Kind | service |
| Ships as | image: ghcr.io/nearpay-money/identity · routes /v1/account, /v1/settlement_destinations, /v1/api_keys, /authz |
| Owns | Account, User, Membership, Session, Passkey, ApiKey, SettlementDestination, Approval |
| Depends on (published artifacts only) | spec, kit, compliance, notify |
| Roadmap phase | P0 Foundations |

## Documentation

This repo stays surgical: design docs live in [`nearpay-brain`](../nearpay-brain/README.md), not here.

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

Scaffold only. Implementation starts in phase **P0 Foundations** (`nearpay-brain/roadmap/roadmap.md`).

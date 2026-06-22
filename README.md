# CaaS API — Crypto as a Service

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13334/badge)](https://www.bestpractices.dev/projects/13334)
[![CI](https://github.com/alexjavabraz/caas-api/actions/workflows/ci.yml/badge.svg)](https://github.com/alexjavabraz/caas-api/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Issuing a token on a blockchain normally requires managing cryptographic wallets, private keys, and low-level smart-contract interactions — a significant barrier for most development teams.

**CaaS API removes that barrier.** It exposes a simple REST API so that any application can deploy and operate tokens (fungible, NFT, or multi-token) on EVM-compatible blockchains with standard HTTP calls — no wallet management, no Solidity knowledge required. Blockchain operations are submitted asynchronously and executed by a secure custody backend (DFNS), while the API returns an `operation_id` immediately so your application stays responsive.

## What it does

- **Token deployment** — deploy ERC-20 (fungible), ERC-721 (NFT), and ERC-1155 (multi-token) contracts
- **Token operations** — mint, burn, pause, unpause, and transfer tokens
- **User management** — create user accounts and manage FIAT/token balances
- **Developer authentication** — OAuth2 `client_credentials` flow; all endpoints require a Bearer JWT
- **Async-first** — every blockchain operation returns an `operation_id` immediately; the result arrives via RabbitMQ when the chain confirms

## Stack

| Layer | Technology |
|-------|-----------|
| Web framework | [Axum](https://github.com/tokio-rs/axum) 0.7 + Tokio |
| Database | PostgreSQL via [SQLx](https://github.com/launchbadge/sqlx) |
| Message broker | RabbitMQ via [Lapin](https://github.com/amqp-rs/lapin) |
| Auth | JWT ([jsonwebtoken](https://github.com/Keats/jsonwebtoken)) — OAuth2 client_credentials |
| Observability | Sentry + `tracing` (structured JSON logs) |

## Quick start

```bash
cp .env.example .env
# Fill in DATABASE_URL, RABBITMQ_URL, JWT_SECRET

# Start dependencies
docker run -d --name caas-postgres \
  -e POSTGRES_USER=caas -e POSTGRES_PASSWORD=caas_secret -e POSTGRES_DB=caas_api \
  -p 5432:5432 postgres:16-alpine

docker run -d --name caas-rabbitmq \
  -p 5672:5672 -p 15672:15672 rabbitmq:3-management

cargo run
# API available at http://localhost:8080/v1/health
```

## API reference

### Authentication

```http
POST /v1/auth/token
Content-Type: application/json

{ "client_id": "cid_...", "client_secret": "sk_...", "grant_type": "client_credentials" }
```

Returns `{ "access_token": "...", "token_type": "Bearer", "expires_in": 3600 }`.
Use the token as `Authorization: Bearer <token>` on all protected endpoints.

### Health

```http
GET /v1/health
→ { "status": "ok" }
```

### Token operations (require Bearer token)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/tokens/deploy` | Deploy a new ERC-20/721/1155 contract |
| `POST` | `/v1/tokens/mint` | Mint tokens to an address |
| `POST` | `/v1/tokens/burn` | Burn tokens from an address |
| `POST` | `/v1/tokens/pause` | Pause all transfers on a contract |
| `POST` | `/v1/tokens/unpause` | Resume transfers on a paused contract |
| `POST` | `/v1/tokens/transfer` | Transfer tokens between addresses |

### User operations (require Bearer token)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/users` | Create a new user account |
| `POST` | `/v1/users/fiat-balance` | Add FIAT balance to a user |
| `POST` | `/v1/users/token-balance` | Add token balance to a user |

All write endpoints return `{ "operation_id": "<uuid>", "status": "queued" }`.

## Building with Docker

```bash
docker build -t caas-api:latest .
docker run -d --name caas-api --network host \
  -e DATABASE_URL=postgresql://caas:secret@localhost:5432/caas_api \
  -e RABBITMQ_URL=amqp://user:pass@localhost:5672 \
  -e JWT_SECRET=your-secret \
  caas-api:latest
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and requirements.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting process.

## License

[MIT](LICENSE)

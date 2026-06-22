# Contributing to CaaS API

Thank you for your interest in contributing! This document explains the process and requirements for acceptable contributions.

## How to contribute

1. **Fork** the repository and create a branch from `main`
2. **Make your changes** following the requirements below
3. **Open a Pull Request** against `main` with a clear description of the change

All contributions go through pull request review. Direct commits to `main` are not accepted.

## Requirements for acceptable contributions

### Code standards

- **Language**: Rust (edition 2021)
- **Formatting**: `cargo fmt` must pass with no changes (`cargo fmt --check`)
- **Linting**: `cargo clippy -- -D warnings` must pass with zero warnings
- **Build**: `cargo build --release` must succeed
- **Security**: No `unsafe` blocks without explicit justification in the PR description

### Input validation

All external inputs (HTTP request bodies, query params, AMQP messages) must be validated using the existing `validator` + `serde` pipeline. No raw string parsing of untrusted data.

### Authentication & secrets

- No hardcoded credentials or secrets — use environment variables via `AppConfig`
- JWT validation must go through the existing `require_auth` middleware
- Client secrets must be hashed (SHA-256) before storage — never stored in plaintext

### Tests

- New behaviour must include unit or integration tests
- Run `cargo test` and ensure all tests pass before opening a PR
- Coverage is measured automatically via CI

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add token pause/unpause endpoint
fix: return 409 when client_id already exists
docs: clarify JWT expiry in README
```

## Development setup

```bash
cp .env.example .env
# Fill in DATABASE_URL, RABBITMQ_URL, JWT_SECRET

docker run -d --name caas-postgres -e POSTGRES_USER=caas \
  -e POSTGRES_PASSWORD=caas_secret -e POSTGRES_DB=caas_api \
  -p 5432:5432 postgres:16-alpine

docker run -d --name caas-rabbitmq \
  -p 5672:5672 -p 15672:15672 rabbitmq:3-management

cargo run
```

## Security checklist for PRs

- [ ] No secrets or credentials in code or tests
- [ ] All new endpoints go through `require_auth` middleware (unless intentionally public)
- [ ] Database queries use SQLx parameterized statements — no string interpolation
- [ ] AMQP messages are validated with the existing schema pipeline
- [ ] `cargo audit` passes (run locally before submitting)

## Fuzzing

The project uses `cargo-fuzz` (libFuzzer) for dynamic analysis of the input validation functions. Fuzz targets live in `fuzz/fuzz_targets/` and require nightly Rust:

```bash
rustup install nightly
cargo install cargo-fuzz

# Fuzz the injection-pattern validator
cargo +nightly fuzz run fuzz_validate_safe_text

# Fuzz the password-strength validator
cargo +nightly fuzz run fuzz_validate_password_strength
```

Fuzzing runs automatically in CI for 30 seconds per target on every push to `main`. If you add new validation functions, add a corresponding fuzz target in `fuzz/fuzz_targets/`.

## Reporting bugs

Open a [GitHub Issue](https://github.com/alexjavabraz/caas-api/issues) with reproduction steps.
For security vulnerabilities, see [SECURITY.md](SECURITY.md).

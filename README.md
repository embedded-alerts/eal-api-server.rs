# eal-api-server

**Embedded Alerts — Rust REST and WebSocket API server**

Embedding-native monitoring and alerting that continuously matches user intents against newly ingested documents, feeds, pages, and streams.

This repository was bootstrapped on 2026-08-04. It is designed as an independently deployable component and as a member of the `eal-monorepo` workspace.

## GitHub target

`embedded-alerts/eal-api-server.rs`

## Baseline

- Rust 2024 edition for backend and native components.
- Axum HTTP/WebSocket transport.
- PostgreSQL persistence through SeaORM, with an in-memory development fallback
  only when `DATABASE_URL` is absent.
- Official protected Shared Auth introspection and product-local authorization.
- Exact-pinned ORES lifecycle logging plus bounded tracing.
- Docker, Nix, and GitHub Actions entry points.
- Zed 0.2.3 package metadata and immutable native dependency locks.

### Routes

- `/v1/alerts`
- `/v1/alerts/{id}`
- `/v1/web/alerts` — bounded web-server projection
- `/v1/ws`

Every alert and WebSocket route requires a Shared Auth access token. The
service calls protected `/auth/introspect` using a separate runtime-only service
credential and the strict `IntrospectionRequest` envelope. Authorization checks
active state, issuer, audience, authorized client, provider provenance, product
tenant, application, actor kind, subject, session, not-before, expiry, and the
route-specific read or write scope. Authentication never substitutes for the
product-owned tenant and alert ownership predicates.

## Four web/API interaction modes

1. **Direct database read:** the paired web server uses the dedicated
   `__eal_web_ro` identity, a SeaORM `AccessMode::ReadOnly` transaction, local
   tenant/subject settings for PostgreSQL RLS, and the fixed
   `DIRECT_ALERTS_SQL` query. It has no write grant.
2. **Stateless HTTPS:** the web server calls `/v1/web/alerts` with a
   redirect-free client, connect/request timeouts, and a streamed response cap.
   This API independently introspects and authorizes the user token.
3. **Stateful mTLS/TCP:** when the complete `EAL_API_MTLS_*` group is present,
   the API accepts hostname-verified client TLS connections with 64 KiB
   length-delimited frames. Every operation carries its own bounded deadline
   and user token and is re-introspected before database access.
4. **Durable JetStream request/reply:** when `NATS_URL`,
   `EAL_NATS_COMMAND_HMAC_KEY`, and `DATABASE_URL` are present, the API consumes
   from a file-backed command stream using a durable explicit-ack consumer. A
   transactional PostgreSQL inbox, dedupe constraints, status row, and outbox
   precede acknowledgement. Reply publication awaits the JetStream publish ack
   before marking the outbox row published. The web server introspects first and
   signs the actor/tenant/deadline command; user bearer tokens never enter NATS
   subjects, headers, payloads, logs, or status rows.

## Development

```bash
cp .env.example .env 2>/dev/null || true
nix develop  # optional
cargo fmt --all --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
zed validate
```

## Status

The runtime adapters are implemented and locally contract-tested. This is not
deployment evidence: operators must apply
`migrations/0001_four_mode_transport.sql`, provision the dedicated database
roles and runtime secrets, provide mTLS identities, and verify Shared Auth,
PostgreSQL, and JetStream in a disposable environment before rollout. The API
never runs DDL at startup.

## Environment secrets

Secrets live in this repo **encrypted** with [sops](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age):
`env/enc/<dev|prod>.env.enc` is committed; `just env-use <name>` decrypts it to
`env/dec/<name>.env` (gitignored, mode 0600) and symlinks `./.env` to it. The
Nix dev shell provides the tooling, `just env-audit` runs keyless in CI, and
containers decrypt at `docker run` — never at build. See [`env/README.md`](env/README.md).

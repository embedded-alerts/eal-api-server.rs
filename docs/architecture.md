# Architecture

Rust Axum, SeaORM, and WebSocket API for embedding-driven alert rules and delivery state.

## Fleet

- `eal-interfaces`
- `eal-api`
- `eal-mash-web`
- `eal-leptos-web`
- `eal-dioxus-web`
- `eal-sync`
- `eal-cli`
- `eal-infra`
- `embedded-alerts-clients`
- `embedded-alerts-libs`
- `embedded-alerts.github.io`
- `embedded-alerts-monorepo`

Interfaces own wire formats; libraries own reusable domain behavior; clients consume versioned contracts; runtimes own deployment behavior; monorepos coordinate pinned revisions. Edge code is allowlisted and never a generic proxy.

## Security boundary

The API consumes the official Shared Auth Rust client at immutable revision
`a814cf34eeef3429e5dee36f45965b6958d694bb`. Protected introspection sends the
user token only in the strict typed request body and sends the independent
service credential only as the request authorization. The product database,
not Shared Auth provider metadata, owns tenant and alert authorization.

All HTTP, WebSocket, TCP, and asynchronous alert reads bind the same verified
subject and product tenant. HTTP and TCP introspect at the API. The asynchronous
lane is accepted only after the paired web server has introspected and signed a
short-lived command envelope with an independent service key; the API verifies
that signature and deadline before opening its transaction.

## Delivery semantics

HTTP is stateless. TCP is persistent but each framed operation is independently
authorized. JetStream is durable request/reply: file storage, explicit consumer
acknowledgement, publisher acknowledgement, and database inbox/outbox/dedupe/
status records make redelivery safe. Core NATS alone is never treated as a
guaranteed-delivery mechanism.

The SQL migration is operator-applied. Source-level and mock-transport tests
prove the reviewed implementation contract; they do not prove that external
Shared Auth, PostgreSQL, certificates, or a JetStream cluster are deployed.

# Stack

Rust 1.95 with Axum, SeaORM/PostgreSQL, official Shared Auth protected
introspection, exact-pinned ORES logging, rustls mTLS/TCP, and durable
NATS JetStream. Zed 0.2.3 owns package intent; Cargo.lock and immutable Git
revisions own the reproducible native build.

The runtime implements four bounded web/API paths: least-privilege direct
database reads, redirect-free stateless HTTPS, per-operation re-authorized
persistent mTLS/TCP, and signed bearer-free JetStream request/reply backed by a
transactional inbox/outbox/status projection.

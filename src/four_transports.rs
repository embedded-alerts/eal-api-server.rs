#![forbid(unsafe_code)]
//! Serving the four avenues from `eal-api-server`.
//!
//! The web server may arrive over any of four wires. Three of them reach this
//! process, and all three land on one [`ores_transport::OperationHandler`] —
//! that single implementation is what makes the avenues interchangeable. An
//! operation cannot mean one thing over HTTP and another over JetStream if
//! there is only one place where it means anything.
//!
//! | # | Mode | This process's part |
//! |---|------|---------------------|
//! | 1 | `direct_read` | none: the web server reads Postgres itself through `eal-lib-core` |
//! | 2 | `http` | an axum route at [`ENVELOPE_PATH`] |
//! | 3 | `tcp` | [`serve_stateful`], one task per held-open connection |
//! | 4 | `jet_stream` | [`serve_asynchronous`], a durable pull consumer |
//!
//! # Finishing the wiring
//!
//! Implement [`ores_transport::OperationHandler`] for this service's
//! operations, then hand the same `Arc` to all three. See
//! `docs/four-transports.md`.

use ores_transport::{
    Envelope, NatsSubjects, OperationHandler, Reply, ServeError, serve_envelope,
};
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;

/// Service slug, which derives the NATS subjects and stream names.
///
/// It must match the slug the web server uses, or the two will be publishing
/// and consuming on different subjects while both look healthy.
pub const SERVICE_SLUG: &str = "eal";

/// Environment prefix for every variable this service reads.
pub const ENV_PREFIX: &str = "EAL";

/// The route that accepts an envelope on avenue 2.
pub const ENVELOPE_PATH: &str = "/v1/operations";

/// The NATS subjects, streams and durable consumer for this service.
#[must_use]
pub fn subjects() -> NatsSubjects {
    NatsSubjects::for_service(SERVICE_SLUG)
}

/// Run one envelope that arrived on avenue 2.
///
/// Deliberately the same call the stateful and asynchronous loops make, rather
/// than a parallel HTTP-only path. A second entry point is a second place for
/// the deadline check, the credential check and the error mapping to drift.
///
/// Returns the reply to serialize and the outcome to log.
pub async fn serve_http_envelope<O, T>(
    handler: &dyn OperationHandler<O, T>,
    envelope: &Envelope<O>,
) -> (Reply<T>, Result<(), ServeError>)
where
    O: Send + Sync,
    T: Send,
{
    serve_envelope(handler, envelope).await
}

/// Accept stateful connections forever (avenue 3).
///
/// Bind `EAL_API_MTLS_ADDR` and pass the listener. One task per
/// connection; a malformed frame is answered rather than closing the socket,
/// so one buggy caller cannot take out the requests multiplexed behind it.
pub async fn serve_stateful<O, T>(
    listener: tokio::net::TcpListener,
    handler: Arc<dyn OperationHandler<O, T>>,
) where
    O: DeserializeOwned + Send + Sync + 'static,
    T: Serialize + Send + 'static,
{
    ores_transport::serve_tcp(listener, handler).await;
}

/// Consume operations forever (avenue 4).
///
/// Declares both streams and the durable consumer idempotently, so every
/// replica may call this at startup. Each result is published *before* its
/// request is acknowledged: acknowledging first would lose the answer to any
/// crash in between, and the request would be gone from the work queue with
/// nothing to show for it.
///
/// # Errors
/// Any JetStream failure while establishing the streams or the consumer.
/// Once running, per-message failures are dispositioned rather than returned:
/// only a handler failure is redelivered, because a malformed, oversized,
/// expired or unauthorized message fails identically forever.
pub async fn serve_asynchronous<O, T>(
    context: ores_transport::async_nats::jetstream::Context,
    handler: Arc<dyn OperationHandler<O, T>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    O: DeserializeOwned + Send + Sync,
    T: Serialize + Send,
{
    ores_transport::serve_jetstream(context, subjects(), handler).await
}

/// Open the JetStream context for avenue 4 from `EAL_NATS_URL`.
///
/// # Errors
/// [`ores_transport::TransportError::Upstream`] if NATS is unreachable.
pub async fn jetstream_from_env()
-> Result<Option<ores_transport::async_nats::jetstream::Context>, Box<dyn std::error::Error + Send + Sync>>
{
    let config = ores_transport::TransportConfig::from_env(ENV_PREFIX)?;
    match config.nats_url.as_deref() {
        None => Ok(None),
        Some(url) => Ok(Some(ores_transport::connect_nats(url).await?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_slug_matches_the_environment_prefix() {
        // If these drift, this server consumes subjects the web server never
        // publishes to, and both processes report healthy.
        assert_eq!(SERVICE_SLUG.replace('-', "_").to_uppercase(), ENV_PREFIX);
    }

    #[test]
    fn the_subjects_are_namespaced_to_this_service() {
        let subjects = subjects();
        assert!(subjects.request_subject.starts_with(SERVICE_SLUG));
        assert!(subjects.result_subject.starts_with(SERVICE_SLUG));
        // JetStream stream names may not contain '.' or '-'.
        assert!(!subjects.request_stream.contains(['.', '-']));
        assert!(!subjects.result_stream.contains(['.', '-']));
    }
}

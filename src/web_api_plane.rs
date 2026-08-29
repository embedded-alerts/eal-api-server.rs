//! Four-avenue web ↔ API binding for `embedded-alerts`.
//!
//! 1. Direct read-only DB via `*-lib-core` named queries (no migrations).
//! 2. Stateless HTTP from `app.embedded-alerts.dev` to `api.embedded-alerts.dev`.
//! 3. Stateful TLS 1.3/mTLS TCP to `api.embedded-alerts.dev:7443`.
//! 4. JetStream: in-cluster producers publish directly to
//!    `nats://dd-nats.messaging.svc.cluster.local:4222`. External producers
//!    use named HTTPS routes on `dd-nats-bridge` (not raw subjects). The
//!    `dd-remote-queue-consumer` in k8s-cluster is the agent-task consumer,
//!    not the product-web producer path.

use k8s_web_api_data_plane::{
    DataPlaneCapabilities, DirectDatabasePolicy, InteractionMode, JetStreamPolicy,
    OrgIdentity, StatelessHttpPolicy, StatefulMtlsTcpPolicy,
};

pub const GITHUB_ORG: &str = "embedded-alerts";
pub const ORG_SLUG: &str = "eal";
pub const DNS_ZONE: &str = "embedded-alerts.dev";

pub fn identity() -> OrgIdentity {
    OrgIdentity::new(GITHUB_ORG, ORG_SLUG, DNS_ZONE).expect("catalog identity is valid")
}

pub fn capabilities() -> DataPlaneCapabilities {
    DataPlaneCapabilities::for_identity(&identity())
}

pub fn policies() -> (
    DirectDatabasePolicy,
    StatelessHttpPolicy,
    StatefulMtlsTcpPolicy,
    JetStreamPolicy,
) {
    let identity = identity();
    (
        DirectDatabasePolicy::for_identity(&identity),
        StatelessHttpPolicy::for_identity(&identity),
        StatefulMtlsTcpPolicy::for_identity(&identity, 7443),
        JetStreamPolicy::for_identity(&identity),
    )
}

pub fn validate_four_avenues() -> Result<(), k8s_web_api_data_plane::DataPlaneError> {
    let identity = identity();
    let (db, http, tcp, nats) = policies();
    db.validate(&identity)?;
    http.validate()?;
    tcp.validate()?;
    nats.validate()?;
    debug_assert_eq!(InteractionMode::ALL.len(), 4);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_avenues_are_named_and_fail_closed() {
        validate_four_avenues().expect("four-avenue policies");
        let caps = capabilities();
        assert_eq!(caps.app_host, format!("app.{DNS_ZONE}"));
        assert_eq!(caps.api_host, format!("api.{DNS_ZONE}"));
        assert_eq!(
            caps.nats_request_subject,
            format!("dd.remote.web_api.{ORG_SLUG}.request")
        );
        assert_eq!(caps.nats_url_in_cluster, "nats://dd-nats.messaging.svc.cluster.local:4222");
    }
}

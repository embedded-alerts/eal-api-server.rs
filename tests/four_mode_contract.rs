use eal_api_server::{
    auth::{AuthPolicy, authorize_introspection},
    transport::{
        AsyncCommand, DIRECT_ALERTS_SQL, MAX_FRAME_BYTES, MAX_OPERATION_DEADLINE_MS,
        OperationEnvelope, sign_command, verify_command_signature,
    },
};
use shared_auth_client::Introspection;
use uuid::Uuid;

fn claims() -> Introspection {
    serde_json::from_value(serde_json::json!({
        "active": true,
        "sub": "00000000-0000-4000-8000-000000000001",
        "sid": "00000000-0000-4000-8000-000000000002",
        "iss": "https://auth.oresoftware.dev/customer",
        "aud": "embedded-alerts-api",
        "azp": "embedded-alerts-web",
        "scope": "embedded-alerts:alerts:read",
        "nbf": 1,
        "exp": 4_000_000_000_u64,
        "provider_tenant": "embedded-alerts-provider",
        "tenant_id": "embedded-alerts",
        "application_id": "embedded-alerts-web",
        "actor_kind": "user"
    }))
    .unwrap()
}

fn policy() -> AuthPolicy {
    AuthPolicy {
        issuer: "https://auth.oresoftware.dev/customer".to_owned(),
        audience: "embedded-alerts-api".to_owned(),
        authorized_client: "embedded-alerts-web".to_owned(),
        provider_tenant: "embedded-alerts-provider".to_owned(),
        product_tenant: "embedded-alerts".to_owned(),
    }
}

#[test]
fn strict_introspection_binds_product_authorization() {
    let actor = authorize_introspection(
        &claims(),
        &policy(),
        "embedded-alerts:alerts:read",
        2_000_000_000,
    )
    .unwrap();
    assert_eq!(actor.product_tenant, "embedded-alerts");

    let mut wrong_tenant = claims();
    wrong_tenant.rest.insert(
        "tenant_id".to_owned(),
        serde_json::Value::String("other".to_owned()),
    );
    assert!(
        authorize_introspection(
            &wrong_tenant,
            &policy(),
            "embedded-alerts:alerts:read",
            2_000_000_000,
        )
        .is_err()
    );
}

#[test]
fn direct_database_contract_is_literal_select_only() {
    let sql = DIRECT_ALERTS_SQL.trim().to_ascii_uppercase();
    assert!(sql.starts_with("SELECT "));
    assert!(DIRECT_ALERTS_SQL.contains("product_tenant = $1"));
    assert!(DIRECT_ALERTS_SQL.contains("owner_subject = $2"));
    assert!(DIRECT_ALERTS_SQL.contains("LIMIT 100"));
    for forbidden in ["INSERT ", "UPDATE ", "DELETE ", "ALTER ", "DROP ", ";"] {
        assert!(!sql.contains(forbidden));
    }
}

#[test]
fn async_commands_are_bounded_signed_and_bearer_free() {
    let correlation_id = Uuid::new_v4();
    let operation = OperationEnvelope {
        version: 1,
        operation_id: correlation_id,
        operation: "list_alerts".to_owned(),
        actor_subject: "00000000-0000-4000-8000-000000000001".to_owned(),
        product_tenant: "embedded-alerts".to_owned(),
        deadline_unix_ms: 2_000_000_000_000 + MAX_OPERATION_DEADLINE_MS,
    };
    let mut command = AsyncCommand {
        event_id: Uuid::new_v4(),
        correlation_id,
        dedupe_key: format!("list-alerts:{correlation_id}"),
        product_tenant: "embedded-alerts".to_owned(),
        operation,
        signature: String::new(),
    };
    let key = b"test-only-command-key-at-least-32-bytes";
    command.signature = sign_command(&command, key).unwrap();
    assert!(verify_command_signature(&command, key));
    assert!(serde_json::to_vec(&command).unwrap().len() < MAX_FRAME_BYTES);
    let encoded = serde_json::to_string(&command).unwrap();
    assert!(!encoded.contains("Bearer "));
    assert!(!encoded.contains("access_token"));
    command.operation.actor_subject = Uuid::new_v4().to_string();
    assert!(!verify_command_signature(&command, key));
}

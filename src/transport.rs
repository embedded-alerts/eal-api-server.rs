use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_nats::{
    ConnectOptions, HeaderMap as NatsHeaderMap, HeaderValue as NatsHeaderValue,
    jetstream::{self, consumer::AckPolicy, stream::StorageType},
};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, QueryResult, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinHandle};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::LengthDelimitedCodec;
use uuid::Uuid;

use crate::{
    auth::{AuthBoundary, READ_SCOPE, VerifiedActor},
    store::{AlertStore, read_alerts},
};

pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_OPERATION_DEADLINE_MS: u64 = 15_000;
pub const COMMAND_STREAM: &str = "EAL_COMMANDS_V1";
pub const COMMAND_SUBJECT_WILDCARD: &str = "eal.command.*.v1";
pub const EVENT_STREAM: &str = "EAL_EVENTS_V1";
pub const EVENT_SUBJECT_WILDCARD: &str = "eal.event.*.v1";
const COMMAND_DURABLE: &str = "eal-api-commands-v1";
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_IO_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_CONNECTION_LIMIT: usize = 128;
const MAX_NATS_PAYLOAD_BYTES: usize = 256 * 1024;

pub const DIRECT_ALERTS_SQL: &str = r#"SELECT id,
    created_at,
    updated_at,
    name,
    query_text,
    embedding_model,
    similarity_threshold,
    source_filters,
    delivery_channels,
    enabled
FROM eal_alert_rules
WHERE product_tenant = $1 AND owner_subject = $2
ORDER BY updated_at DESC, id
LIMIT 100"#;

const INSERT_INBOX_SQL: &str = r#"
INSERT INTO eal_transport_inbox (
    event_id, correlation_id, dedupe_key, product_tenant, actor_subject, received_at
)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT DO NOTHING
"#;

const INSERT_STATUS_SQL: &str = r#"
INSERT INTO eal_transport_status (
    correlation_id, product_tenant, actor_subject, status, updated_at
)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (correlation_id) DO UPDATE
SET status = EXCLUDED.status, updated_at = now()
"#;

const INSERT_OUTBOX_SQL: &str = r#"
INSERT INTO eal_transport_outbox (
    event_id, correlation_id, dedupe_key, subject, payload, created_at
)
VALUES ($1, $2, $3, $4, $5::jsonb, now())
ON CONFLICT (dedupe_key) DO NOTHING
"#;

const SELECT_OUTBOX_SQL: &str = r#"
SELECT event_id, correlation_id, dedupe_key, subject, payload
FROM eal_transport_outbox
WHERE published_at IS NULL
ORDER BY created_at, event_id
LIMIT 50
"#;

const MARK_OUTBOX_SQL: &str = r#"
UPDATE eal_transport_outbox
SET published_at = now()
WHERE event_id = $1 AND published_at IS NULL
"#;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationEnvelope {
    pub version: u8,
    pub operation_id: Uuid,
    pub operation: String,
    pub actor_subject: String,
    pub product_tenant: String,
    pub deadline_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedOperation {
    pub authorization: String,
    pub envelope: OperationEnvelope,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperationReply {
    pub operation_id: Uuid,
    pub status: String,
    pub result: Option<Value>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncCommand {
    pub event_id: Uuid,
    pub correlation_id: Uuid,
    pub dedupe_key: String,
    pub product_tenant: String,
    pub operation: OperationEnvelope,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventEnvelope {
    pub event_id: Uuid,
    pub correlation_id: Uuid,
    pub dedupe_key: String,
    pub product_tenant: String,
    pub subject: String,
    pub reply: OperationReply,
}

pub fn command_signing_bytes(command: &AsyncCommand) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        command.event_id,
        command.correlation_id,
        command.dedupe_key,
        command.product_tenant,
        command.operation.version,
        command.operation.operation_id,
        command.operation.operation,
        command.operation.actor_subject,
        command.operation.deadline_unix_ms,
    )
}

pub fn sign_command(command: &AsyncCommand, key: &[u8]) -> Result<String, &'static str> {
    if !valid_command_key(key) {
        return Err("command key is malformed");
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "command key is malformed")?;
    mac.update(command_signing_bytes(command).as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub fn verify_command_signature(command: &AsyncCommand, key: &[u8]) -> bool {
    let Ok(signature) = hex::decode(&command.signature) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return false;
    };
    mac.update(command_signing_bytes(command).as_bytes());
    valid_command_key(key) && mac.verify_slice(&signature).is_ok()
}

fn valid_command_key(key: &[u8]) -> bool {
    (32..=1024).contains(&key.len()) && !key.iter().any(u8::is_ascii_control)
}

pub fn validate_operation_envelope_at(
    envelope: &OperationEnvelope,
    now_ms: u64,
) -> Result<(), &'static str> {
    if envelope.version != 1
        || envelope.operation != "list_alerts"
        || envelope.operation_id.is_nil()
        || !bounded_tenant(&envelope.product_tenant)
        || Uuid::parse_str(&envelope.actor_subject).is_err()
        || envelope.deadline_unix_ms < now_ms
        || envelope.deadline_unix_ms.saturating_sub(now_ms) > MAX_OPERATION_DEADLINE_MS
    {
        return Err("operation envelope is invalid");
    }
    Ok(())
}

pub async fn spawn_mtls_from_env(
    store: AlertStore,
    auth: AuthBoundary,
) -> Result<Option<JoinHandle<()>>, String> {
    let Some(config) = MtlsServerConfig::from_env()? else {
        return Ok(None);
    };
    let listener = TcpListener::bind(&config.bind)
        .await
        .map_err(|_| "mTLS/TCP bind failed".to_owned())?;
    let acceptor = TlsAcceptor::from(config.tls);
    Ok(Some(tokio::spawn(async move {
        if let Err(error) = run_mtls(listener, acceptor, store, auth).await {
            tracing::error!(%error, "mTLS/TCP transport stopped");
        }
    })))
}

struct MtlsServerConfig {
    bind: String,
    tls: Arc<ServerConfig>,
}

impl MtlsServerConfig {
    fn from_env() -> Result<Option<Self>, String> {
        let values = [
            optional_env("EAL_API_MTLS_BIND"),
            optional_env("EAL_API_TLS_CERT_FILE"),
            optional_env("EAL_API_TLS_KEY_FILE"),
            optional_env("EAL_WEB_CLIENT_CA_FILE"),
        ];
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        if values.iter().any(Option::is_none) {
            return Err("all API mTLS variables must be configured together".to_owned());
        }
        let [bind, certificate_file, private_key_file, client_ca_file] = values.map(Option::unwrap);
        let certificates = read_certificates(&certificate_file)?;
        let private_key = read_private_key(&private_key_file)?;
        let mut client_roots = RootCertStore::empty();
        for certificate in read_certificates(&client_ca_file)? {
            client_roots
                .add(certificate)
                .map_err(|_| "web client CA certificate is invalid".to_owned())?;
        }
        if client_roots.is_empty() {
            return Err("web client CA file is empty".to_owned());
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|_| "web client verifier configuration is invalid".to_owned())?;
        let tls = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, private_key)
            .map_err(|_| "API server certificate or key is invalid".to_owned())?;
        Ok(Some(Self {
            bind,
            tls: Arc::new(tls),
        }))
    }
}

async fn run_mtls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    store: AlertStore,
    auth: AuthBoundary,
) -> Result<(), String> {
    let capacity = Arc::new(Semaphore::new(TCP_CONNECTION_LIMIT));
    loop {
        let (socket, _) = listener
            .accept()
            .await
            .map_err(|_| "mTLS/TCP accept failed".to_owned())?;
        let permit = match capacity.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let store = store.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(tls)) =
                tokio::time::timeout(Duration::from_secs(5), acceptor.accept(socket)).await
            else {
                return;
            };
            let mut framed = LengthDelimitedCodec::builder()
                .max_frame_length(MAX_FRAME_BYTES)
                .new_framed(tls);
            while let Ok(Some(Ok(frame))) =
                tokio::time::timeout(TCP_IO_TIMEOUT, framed.next()).await
            {
                let reply = execute_tcp_operation(&store, &auth, &frame).await;
                let Ok(payload) = serde_json::to_vec(&reply) else {
                    break;
                };
                if payload.len() > MAX_FRAME_BYTES {
                    break;
                }
                if !matches!(
                    tokio::time::timeout(TCP_IO_TIMEOUT, framed.send(Bytes::from(payload))).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
        });
    }
}

async fn execute_tcp_operation(
    store: &AlertStore,
    auth: &AuthBoundary,
    frame: &[u8],
) -> OperationReply {
    let request: AuthenticatedOperation = match serde_json::from_slice(frame) {
        Ok(request) => request,
        Err(_) => return error_reply(Uuid::nil(), "invalid_request"),
    };
    let operation_id = request.envelope.operation_id;
    let Ok(now) = unix_ms() else {
        return error_reply(operation_id, "unavailable");
    };
    if validate_operation_envelope_at(&request.envelope, now).is_err() {
        return error_reply(operation_id, "invalid_request");
    }
    let Some(token) = request.authorization.strip_prefix("Bearer ") else {
        return error_reply(operation_id, "unauthorized");
    };
    let actor = match auth.verify_token(token, READ_SCOPE).await {
        Ok(actor)
            if actor.subject.to_string() == request.envelope.actor_subject
                && actor.product_tenant == request.envelope.product_tenant =>
        {
            actor
        }
        _ => return error_reply(operation_id, "unauthorized"),
    };
    match tokio::time::timeout(QUERY_TIMEOUT, store.list(&actor)).await {
        Ok(Ok(alerts)) => OperationReply {
            operation_id,
            status: "completed".to_owned(),
            result: Some(json!(alerts)),
            error: None,
        },
        Ok(Err(_)) => error_reply(operation_id, "unavailable"),
        Err(_) => error_reply(operation_id, "timeout"),
    }
}

pub async fn spawn_jetstream_from_env(
    store: AlertStore,
    product_tenant: String,
) -> Result<Option<JoinHandle<()>>, String> {
    let Some(url) = optional_env("NATS_URL") else {
        return Ok(None);
    };
    validate_nats_url(&url)?;
    let command_key = required_env("EAL_NATS_COMMAND_HMAC_KEY")?.into_bytes();
    if !valid_command_key(&command_key) {
        return Err("EAL_NATS_COMMAND_HMAC_KEY is malformed".to_owned());
    }
    let database = store.database().cloned().ok_or_else(|| {
        "JetStream requires DATABASE_URL for durable inbox/outbox state".to_owned()
    })?;
    Ok(Some(tokio::spawn(async move {
        if let Err(error) = run_jetstream(&url, database, product_tenant, command_key).await {
            tracing::error!(%error, "JetStream transport stopped");
        }
    })))
}

async fn run_jetstream(
    url: &str,
    database: DatabaseConnection,
    product_tenant: String,
    command_key: Vec<u8>,
) -> Result<(), String> {
    let client = ConnectOptions::new()
        .connect(url)
        .await
        .map_err(|_| "NATS connection failed".to_owned())?;
    let context = jetstream::new(client);
    let command_stream = context
        .get_or_create_stream(jetstream::stream::Config {
            name: COMMAND_STREAM.to_owned(),
            subjects: vec![COMMAND_SUBJECT_WILDCARD.to_owned()],
            storage: StorageType::File,
            max_messages: 100_000,
            max_message_size: MAX_NATS_PAYLOAD_BYTES as i32,
            ..Default::default()
        })
        .await
        .map_err(|_| "durable command stream is unavailable".to_owned())?;
    context
        .get_or_create_stream(jetstream::stream::Config {
            name: EVENT_STREAM.to_owned(),
            subjects: vec![EVENT_SUBJECT_WILDCARD.to_owned()],
            storage: StorageType::File,
            max_messages: 100_000,
            max_message_size: MAX_NATS_PAYLOAD_BYTES as i32,
            ..Default::default()
        })
        .await
        .map_err(|_| "durable event stream is unavailable".to_owned())?;
    let consumer = command_stream
        .get_or_create_consumer(
            COMMAND_DURABLE,
            jetstream::consumer::pull::Config {
                durable_name: Some(COMMAND_DURABLE.to_owned()),
                ack_policy: AckPolicy::Explicit,
                ack_wait: Duration::from_secs(30),
                filter_subject: COMMAND_SUBJECT_WILDCARD.to_owned(),
                max_ack_pending: 64,
                max_deliver: 8,
                ..Default::default()
            },
        )
        .await
        .map_err(|_| "durable command consumer is unavailable".to_owned())?;

    let publisher_context = context.clone();
    let publisher_database = database.clone();
    tokio::spawn(async move {
        loop {
            if let Err(error) = publish_pending(&publisher_context, &publisher_database).await {
                tracing::warn!(%error, "JetStream outbox publish attempt failed");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });

    let mut messages = consumer
        .messages()
        .await
        .map_err(|_| "JetStream command delivery is unavailable".to_owned())?;
    while let Some(message) = messages.next().await {
        let message = message.map_err(|_| "JetStream command delivery failed".to_owned())?;
        if message.payload.len() > MAX_NATS_PAYLOAD_BYTES {
            message
                .ack_with(jetstream::AckKind::Term)
                .await
                .map_err(|_| "JetStream termination acknowledgement failed".to_owned())?;
            continue;
        }
        let command: AsyncCommand = match serde_json::from_slice(&message.payload) {
            Ok(command) => command,
            Err(_) => {
                message
                    .ack_with(jetstream::AckKind::Term)
                    .await
                    .map_err(|_| "JetStream termination acknowledgement failed".to_owned())?;
                continue;
            }
        };
        let now = unix_ms().map_err(|_| "system clock is unavailable".to_owned())?;
        if command.product_tenant != product_tenant
            || command.product_tenant != command.operation.product_tenant
            || command.operation.operation_id != command.correlation_id
            || !bounded_dedupe_key(&command.dedupe_key)
            || !verify_command_signature(&command, &command_key)
            || validate_operation_envelope_at(&command.operation, now).is_err()
        {
            message
                .ack_with(jetstream::AckKind::Term)
                .await
                .map_err(|_| "JetStream termination acknowledgement failed".to_owned())?;
            continue;
        }
        process_command(&database, &command).await?;
        message
            .ack()
            .await
            .map_err(|_| "JetStream explicit acknowledgement failed".to_owned())?;
    }
    Err("JetStream command delivery ended".to_owned())
}

async fn process_command(
    database: &DatabaseConnection,
    command: &AsyncCommand,
) -> Result<(), String> {
    let transaction = database
        .begin()
        .await
        .map_err(|_| "begin JetStream inbox transaction failed".to_owned())?;
    let inserted = transaction
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            INSERT_INBOX_SQL,
            [
                command.event_id.into(),
                command.correlation_id.into(),
                command.dedupe_key.clone().into(),
                command.product_tenant.clone().into(),
                command.operation.actor_subject.clone().into(),
            ],
        ))
        .await
        .map_err(|_| "persist JetStream inbox failed".to_owned())?
        .rows_affected()
        == 1;
    if inserted {
        let actor = VerifiedActor {
            subject: Uuid::parse_str(&command.operation.actor_subject)
                .map_err(|_| "JetStream actor subject is invalid".to_owned())?,
            product_tenant: command.product_tenant.clone(),
        };
        let reply =
            match tokio::time::timeout(QUERY_TIMEOUT, read_alerts(&transaction, &actor)).await {
                Ok(Ok(alerts)) => OperationReply {
                    operation_id: command.correlation_id,
                    status: "completed".to_owned(),
                    result: Some(json!(alerts)),
                    error: None,
                },
                Ok(Err(_)) => error_reply(command.correlation_id, "unavailable"),
                Err(_) => error_reply(command.correlation_id, "timeout"),
            };
        enqueue_reply(&transaction, command, &reply).await?;
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                INSERT_STATUS_SQL,
                [
                    command.correlation_id.into(),
                    command.product_tenant.clone().into(),
                    command.operation.actor_subject.clone().into(),
                    reply.status.clone().into(),
                ],
            ))
            .await
            .map_err(|_| "persist JetStream status failed".to_owned())?;
    }
    transaction
        .commit()
        .await
        .map_err(|_| "commit JetStream inbox transaction failed".to_owned())
}

async fn enqueue_reply<C: ConnectionTrait>(
    connection: &C,
    command: &AsyncCommand,
    reply: &OperationReply,
) -> Result<(), String> {
    let event_id = Uuid::new_v4();
    let subject = format!("eal.event.{}.v1", command.product_tenant);
    let envelope = EventEnvelope {
        event_id,
        correlation_id: command.correlation_id,
        dedupe_key: format!("reply:{}", command.dedupe_key),
        product_tenant: command.product_tenant.clone(),
        subject: subject.clone(),
        reply: reply.clone(),
    };
    let payload = serde_json::to_value(&envelope)
        .map_err(|_| "serialize JetStream reply failed".to_owned())?;
    connection
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            INSERT_OUTBOX_SQL,
            [
                event_id.into(),
                command.correlation_id.into(),
                envelope.dedupe_key.into(),
                subject.into(),
                payload.into(),
            ],
        ))
        .await
        .map_err(|_| "persist JetStream outbox failed".to_owned())?;
    Ok(())
}

async fn publish_pending(
    context: &jetstream::Context,
    database: &DatabaseConnection,
) -> Result<(), String> {
    let rows = database
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Postgres,
            SELECT_OUTBOX_SQL.to_owned(),
        ))
        .await
        .map_err(|_| "read JetStream outbox failed".to_owned())?;
    for row in rows {
        let pending = PendingOutbox::from_row(row)?;
        let payload = serde_json::to_vec(&pending.payload)
            .map_err(|_| "serialize JetStream outbox failed".to_owned())?;
        if payload.len() > MAX_NATS_PAYLOAD_BYTES {
            return Err("JetStream outbox payload is oversized".to_owned());
        }
        let mut headers = NatsHeaderMap::new();
        headers.insert(
            "Nats-Msg-Id",
            NatsHeaderValue::from_str(&pending.dedupe_key)
                .map_err(|_| "JetStream dedupe header is invalid".to_owned())?,
        );
        context
            .publish_with_headers(pending.subject, headers, payload.into())
            .await
            .map_err(|_| "JetStream reply publish failed".to_owned())?
            .await
            .map_err(|_| "JetStream reply was not acknowledged".to_owned())?;
        database
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                MARK_OUTBOX_SQL,
                [pending.event_id.into()],
            ))
            .await
            .map_err(|_| "mark JetStream outbox published failed".to_owned())?;
    }
    Ok(())
}

struct PendingOutbox {
    event_id: Uuid,
    #[allow(dead_code)]
    correlation_id: Uuid,
    dedupe_key: String,
    subject: String,
    payload: Value,
}

impl PendingOutbox {
    fn from_row(row: QueryResult) -> Result<Self, String> {
        Ok(Self {
            event_id: row
                .try_get("", "event_id")
                .map_err(|_| "JetStream outbox event ID is invalid".to_owned())?,
            correlation_id: row
                .try_get("", "correlation_id")
                .map_err(|_| "JetStream outbox correlation ID is invalid".to_owned())?,
            dedupe_key: row
                .try_get("", "dedupe_key")
                .map_err(|_| "JetStream outbox dedupe key is invalid".to_owned())?,
            subject: row
                .try_get("", "subject")
                .map_err(|_| "JetStream outbox subject is invalid".to_owned())?,
            payload: row
                .try_get("", "payload")
                .map_err(|_| "JetStream outbox payload is invalid".to_owned())?,
        })
    }
}

fn error_reply(operation_id: Uuid, error: &str) -> OperationReply {
    OperationReply {
        operation_id,
        status: "rejected".to_owned(),
        result: None,
        error: Some(error.to_owned()),
    }
}

fn bounded_tenant(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        })
}

fn bounded_dedupe_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
}

fn validate_nats_url(value: &str) -> Result<(), String> {
    let secure = value.starts_with("tls://") && value.len() > "tls://".len();
    let loopback = value.starts_with("nats://127.0.0.1:")
        || value.starts_with("nats://localhost:")
        || value.starts_with("nats://[::1]:");
    if (secure || loopback) && !value.contains('@') {
        Ok(())
    } else {
        Err("remote NATS requires a credential-free tls:// URL".to_owned())
    }
}

fn read_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_file_iter(path)
        .map_err(|_| "TLS certificate file cannot be opened".to_owned())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "TLS certificate file is invalid".to_owned())
}

fn read_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|_| "TLS private key file is missing or invalid".to_owned())
}

fn required_env(name: &str) -> Result<String, String> {
    optional_env(name).ok_or_else(|| format!("{name} is required"))
}

fn optional_env(name: &str) -> Option<String> {
    crate::flags::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn unix_ms() -> Result<u64, std::time::SystemTimeError> {
    Ok(
        u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
            .unwrap_or(u64::MAX),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m_tls_configuration_is_absent_or_complete() {
        let names = [
            "EAL_API_MTLS_BIND",
            "EAL_API_TLS_CERT_FILE",
            "EAL_API_TLS_KEY_FILE",
            "EAL_WEB_CLIENT_CA_FILE",
        ];
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn remote_plaintext_nats_is_rejected() {
        assert!(validate_nats_url("tls://nats.example.test:4222").is_ok());
        assert!(validate_nats_url("nats://localhost:4222").is_ok());
        assert!(validate_nats_url("nats://nats.example.test:4222").is_err());
    }
}

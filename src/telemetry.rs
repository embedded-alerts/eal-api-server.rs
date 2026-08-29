use std::sync::Arc;

use next_loggers::{
    JsonObject, LogLevel, Logger, OpenTelemetryLogRecord, OpenTelemetryTransport, Options, json,
};
use tracing_subscriber::EnvFilter;

pub struct TelemetryGuard {
    logger: Logger,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        lifecycle(&self.logger, "shutdown", "complete");
        let _ = self.logger.close();
    }
}

pub fn init(service_name: &str) -> TelemetryGuard {
    let logger = application_logger(service_name);
    let subscriber = tracing_subscriber::fmt().json().with_env_filter(
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info,hyper=warn")),
    );
    match subscriber.try_init() {
        Ok(()) => lifecycle(&logger, "startup", "ready"),
        Err(_) => lifecycle(&logger, "startup", "subscriber_conflict"),
    }
    TelemetryGuard { logger }
}

fn application_logger(service_name: &str) -> Logger {
    let transport = Arc::new(OpenTelemetryTransport::new(emit_record));
    Logger::new(Options {
        app_name: service_name.to_owned(),
        name: Some("api.telemetry".into()),
        runtime: "rust".into(),
        max_level: LogLevel::Info,
        console: false,
        ..Options::default().with_transport(transport)
    })
}

fn emit_record(record: OpenTelemetryLogRecord) -> Result<(), next_loggers::LoggerError> {
    let operation = record
        .attributes
        .get("next_logger.field.operation")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let outcome = record
        .attributes
        .get("next_logger.field.outcome")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let schema = record
        .attributes
        .get("next_logger.schema")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    tracing::info!(
        next_logger.schema = schema,
        operation,
        outcome,
        message = %record.body,
        "next-loggers event"
    );
    Ok(())
}

fn lifecycle(logger: &Logger, operation: &'static str, outcome: &'static str) {
    let fields = JsonObject::from_iter([
        ("component".into(), json!("api.telemetry")),
        ("operation".into(), json!(operation)),
        ("outcome".into(), json!(outcome)),
    ]);
    let _ = logger
        .info(vec![json!("API telemetry lifecycle")])
        .add_fields(fields)
        .send();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ores_logger_accepts_only_bounded_lifecycle_fields() {
        let logger = application_logger("eal-api-server-test");
        lifecycle(&logger, "startup", "ready");
        let _ = logger.close();
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_ALERT_NAME_BYTES: usize = 160;
pub const MAX_QUERY_BYTES: usize = 8 * 1024;
pub const MAX_MODEL_BYTES: usize = 128;
pub const MAX_LIST_ITEMS: usize = 32;
pub const MAX_LIST_ITEM_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertRule {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub query_text: String,
    pub embedding_model: String,
    pub similarity_threshold: f32,
    pub source_filters: Vec<String>,
    pub delivery_channels: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAlertRule {
    pub name: String,
    pub query_text: String,
    pub embedding_model: String,
    pub similarity_threshold: f32,
    #[serde(default)]
    pub source_filters: Vec<String>,
    #[serde(default)]
    pub delivery_channels: Vec<String>,
    pub enabled: bool,
}

impl CreateAlertRule {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_text(&self.name, MAX_ALERT_NAME_BYTES)?;
        validate_text(&self.query_text, MAX_QUERY_BYTES)?;
        validate_text(&self.embedding_model, MAX_MODEL_BYTES)?;
        if !self.similarity_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.similarity_threshold)
        {
            return Err("similarity_threshold must be between zero and one");
        }
        validate_list(&self.source_filters)?;
        validate_list(&self.delivery_channels)?;
        Ok(())
    }

    pub fn into_rule(self, id: Uuid, now: DateTime<Utc>) -> AlertRule {
        AlertRule {
            id,
            created_at: now,
            updated_at: now,
            name: self.name.trim().to_owned(),
            query_text: self.query_text.trim().to_owned(),
            embedding_model: self.embedding_model.trim().to_owned(),
            similarity_threshold: self.similarity_threshold,
            source_filters: normalize_list(self.source_filters),
            delivery_channels: normalize_list(self.delivery_channels),
            enabled: self.enabled,
        }
    }
}

fn validate_text(value: &str, max: usize) -> Result<(), &'static str> {
    if value.trim().is_empty()
        || value.len() > max
        || value.chars().any(|character| character.is_control())
    {
        return Err("text field is empty, oversized, or contains controls");
    }
    Ok(())
}

fn validate_list(values: &[String]) -> Result<(), &'static str> {
    if values.len() > MAX_LIST_ITEMS {
        return Err("list field contains too many entries");
    }
    for value in values {
        validate_text(value, MAX_LIST_ITEM_BYTES)?;
    }
    Ok(())
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .collect()
}

#[derive(Debug, Serialize)]
pub struct Health {
    pub service: &'static str,
    pub status: &'static str,
    pub database_configured: bool,
    pub shared_auth_configured: bool,
    pub mtls_configured: bool,
    pub jetstream_configured: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_input_is_bounded_before_storage() {
        let mut input = CreateAlertRule {
            name: "New source".to_owned(),
            query_text: "rust security releases".to_owned(),
            embedding_model: "text-embedding-3-small".to_owned(),
            similarity_threshold: 0.8,
            source_filters: vec!["docs".to_owned()],
            delivery_channels: vec!["email".to_owned()],
            enabled: true,
        };
        assert!(input.validate().is_ok());
        input.query_text = "x".repeat(MAX_QUERY_BYTES + 1);
        assert!(input.validate().is_err());
    }
}

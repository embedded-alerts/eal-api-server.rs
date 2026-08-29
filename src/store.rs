use std::{collections::HashMap, sync::Arc};

use chrono::Utc;
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, QueryResult, Statement,
};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    auth::VerifiedActor,
    model::{AlertRule, CreateAlertRule},
    transport::DIRECT_ALERTS_SQL,
};

const INSERT_ALERT_SQL: &str = r#"
INSERT INTO eal_alert_rules (
    id, product_tenant, owner_subject, created_at, updated_at, name, query_text,
    embedding_model, similarity_threshold, source_filters, delivery_channels, enabled
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12)
"#;

type AlertKey = (String, Uuid, Uuid);
type FallbackAlerts = Arc<RwLock<HashMap<AlertKey, AlertRule>>>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("alert persistence is unavailable")]
    Unavailable,
    #[error("stored alert violated the service contract")]
    InvalidRecord,
}

#[derive(Clone)]
pub struct AlertStore {
    database: Option<DatabaseConnection>,
    fallback: FallbackAlerts,
}

impl AlertStore {
    pub fn new(database: Option<DatabaseConnection>) -> Self {
        Self {
            database,
            fallback: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn database(&self) -> Option<&DatabaseConnection> {
        self.database.as_ref()
    }

    pub fn database_configured(&self) -> bool {
        self.database.is_some()
    }

    pub async fn list(&self, actor: &VerifiedActor) -> Result<Vec<AlertRule>, StoreError> {
        match &self.database {
            Some(database) => read_alerts(database, actor).await,
            None => Ok(self
                .fallback
                .read()
                .await
                .iter()
                .filter(|((tenant, owner, _), _)| {
                    tenant == &actor.product_tenant && owner == &actor.subject
                })
                .map(|(_, alert)| alert.clone())
                .collect()),
        }
    }

    pub async fn get(
        &self,
        actor: &VerifiedActor,
        id: Uuid,
    ) -> Result<Option<AlertRule>, StoreError> {
        if self.database.is_some() {
            return Ok(self
                .list(actor)
                .await?
                .into_iter()
                .find(|alert| alert.id == id));
        }
        Ok(self
            .fallback
            .read()
            .await
            .get(&(actor.product_tenant.clone(), actor.subject, id))
            .cloned())
    }

    pub async fn create(
        &self,
        actor: &VerifiedActor,
        input: CreateAlertRule,
    ) -> Result<AlertRule, StoreError> {
        input.validate().map_err(|_| StoreError::InvalidRecord)?;
        let now = Utc::now();
        let alert = input.into_rule(Uuid::new_v4(), now);
        match &self.database {
            Some(database) => {
                let source_filters = serde_json::to_string(&alert.source_filters)
                    .map_err(|_| StoreError::InvalidRecord)?;
                let delivery_channels = serde_json::to_string(&alert.delivery_channels)
                    .map_err(|_| StoreError::InvalidRecord)?;
                database
                    .execute_raw(Statement::from_sql_and_values(
                        DatabaseBackend::Postgres,
                        INSERT_ALERT_SQL,
                        [
                            alert.id.into(),
                            actor.product_tenant.clone().into(),
                            actor.subject.into(),
                            alert.created_at.into(),
                            alert.updated_at.into(),
                            alert.name.clone().into(),
                            alert.query_text.clone().into(),
                            alert.embedding_model.clone().into(),
                            f64::from(alert.similarity_threshold).into(),
                            source_filters.into(),
                            delivery_channels.into(),
                            alert.enabled.into(),
                        ],
                    ))
                    .await
                    .map_err(map_db)?;
            }
            None => {
                self.fallback.write().await.insert(
                    (actor.product_tenant.clone(), actor.subject, alert.id),
                    alert.clone(),
                );
            }
        }
        Ok(alert)
    }
}

pub async fn read_alerts<C: ConnectionTrait>(
    database: &C,
    actor: &VerifiedActor,
) -> Result<Vec<AlertRule>, StoreError> {
    let rows = database
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            DIRECT_ALERTS_SQL,
            [actor.product_tenant.clone().into(), actor.subject.into()],
        ))
        .await
        .map_err(map_db)?;
    rows.into_iter().map(decode_alert).collect()
}

fn decode_alert(row: QueryResult) -> Result<AlertRule, StoreError> {
    let id = row
        .try_get::<Uuid>("", "id")
        .map_err(|_| StoreError::InvalidRecord)?;
    let source_filters = row
        .try_get::<serde_json::Value>("", "source_filters")
        .map_err(|_| StoreError::InvalidRecord)?;
    let delivery_channels = row
        .try_get::<serde_json::Value>("", "delivery_channels")
        .map_err(|_| StoreError::InvalidRecord)?;
    Ok(AlertRule {
        id,
        created_at: row
            .try_get("", "created_at")
            .map_err(|_| StoreError::InvalidRecord)?,
        updated_at: row
            .try_get("", "updated_at")
            .map_err(|_| StoreError::InvalidRecord)?,
        name: row
            .try_get("", "name")
            .map_err(|_| StoreError::InvalidRecord)?,
        query_text: row
            .try_get("", "query_text")
            .map_err(|_| StoreError::InvalidRecord)?,
        embedding_model: row
            .try_get("", "embedding_model")
            .map_err(|_| StoreError::InvalidRecord)?,
        similarity_threshold: row
            .try_get::<f64>("", "similarity_threshold")
            .map_err(|_| StoreError::InvalidRecord)? as f32,
        source_filters: serde_json::from_value(source_filters)
            .map_err(|_| StoreError::InvalidRecord)?,
        delivery_channels: serde_json::from_value(delivery_channels)
            .map_err(|_| StoreError::InvalidRecord)?,
        enabled: row
            .try_get("", "enabled")
            .map_err(|_| StoreError::InvalidRecord)?,
    })
}

fn map_db(_error: DbErr) -> StoreError {
    StoreError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fallback_storage_is_scoped_by_tenant_and_subject() {
        let store = AlertStore::new(None);
        let actor = VerifiedActor {
            subject: Uuid::new_v4(),
            product_tenant: "embedded-alerts".to_owned(),
        };
        let input = CreateAlertRule {
            name: "Release monitor".to_owned(),
            query_text: "new Rust releases".to_owned(),
            embedding_model: "small".to_owned(),
            similarity_threshold: 0.7,
            source_filters: vec!["docs".to_owned()],
            delivery_channels: vec!["email".to_owned()],
            enabled: true,
        };
        store.create(&actor, input).await.unwrap();
        assert_eq!(store.list(&actor).await.unwrap().len(), 1);
        let other = VerifiedActor {
            subject: Uuid::new_v4(),
            product_tenant: actor.product_tenant,
        };
        assert!(store.list(&other).await.unwrap().is_empty());
    }
}

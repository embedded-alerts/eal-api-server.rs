-- Operator-applied PostgreSQL migration. The API never runs DDL at startup.
-- Infrastructure must create the LOGIN role __eal_web_ro before this migration
-- and must give it only CONNECT plus schema USAGE outside this file.

CREATE TABLE eal_alert_rules (
    id uuid PRIMARY KEY,
    product_tenant text NOT NULL CHECK (length(product_tenant) BETWEEN 1 AND 64),
    owner_subject uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
    query_text text NOT NULL CHECK (length(query_text) BETWEEN 1 AND 8192),
    embedding_model text NOT NULL CHECK (length(embedding_model) BETWEEN 1 AND 128),
    similarity_threshold double precision NOT NULL
        CHECK (similarity_threshold >= 0 AND similarity_threshold <= 1),
    source_filters jsonb NOT NULL CHECK (jsonb_typeof(source_filters) = 'array'),
    delivery_channels jsonb NOT NULL CHECK (jsonb_typeof(delivery_channels) = 'array'),
    enabled boolean NOT NULL
);

CREATE INDEX eal_alert_rules_owner_updated
    ON eal_alert_rules (product_tenant, owner_subject, updated_at DESC, id);

CREATE TABLE eal_transport_inbox (
    event_id uuid PRIMARY KEY,
    correlation_id uuid NOT NULL UNIQUE,
    dedupe_key text NOT NULL UNIQUE CHECK (length(dedupe_key) BETWEEN 1 AND 128),
    product_tenant text NOT NULL CHECK (length(product_tenant) BETWEEN 1 AND 64),
    actor_subject uuid NOT NULL,
    received_at timestamptz NOT NULL
);

CREATE TABLE eal_transport_outbox (
    event_id uuid PRIMARY KEY,
    correlation_id uuid NOT NULL,
    dedupe_key text NOT NULL UNIQUE CHECK (length(dedupe_key) BETWEEN 1 AND 134),
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    published_at timestamptz
);

CREATE INDEX eal_transport_outbox_pending
    ON eal_transport_outbox (created_at, event_id)
    WHERE published_at IS NULL;

CREATE TABLE eal_transport_status (
    correlation_id uuid PRIMARY KEY,
    product_tenant text NOT NULL CHECK (length(product_tenant) BETWEEN 1 AND 64),
    actor_subject uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('completed', 'rejected')),
    updated_at timestamptz NOT NULL
);

ALTER TABLE eal_alert_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY eal_web_owner_read ON eal_alert_rules
    FOR SELECT
    TO __eal_web_ro
    USING (
        product_tenant = current_setting('eal.product_tenant', true)
        AND owner_subject = current_setting('eal.owner_subject', true)::uuid
    );

REVOKE ALL ON eal_alert_rules FROM __eal_web_ro;
GRANT SELECT ON eal_alert_rules TO __eal_web_ro;

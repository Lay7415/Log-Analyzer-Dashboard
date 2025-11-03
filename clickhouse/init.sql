CREATE TABLE IF NOT EXISTS dim_ip (
    ip_id UInt64,
    ip String,
    country LowCardinality(String)
) ENGINE = ReplacingMergeTree(ip_id)
ORDER BY ip_id;

CREATE TABLE IF NOT EXISTS dim_request (
    request_id UInt64,
    request Nullable(String),
    method LowCardinality(Nullable(String)),
    page Nullable(String),
    referrer Nullable(String)
) ENGINE = ReplacingMergeTree(request_id)
ORDER BY request_id;

CREATE TABLE IF NOT EXISTS dim_user_agent (
    agent_id UInt64,
    agent Nullable(String)
) ENGINE = ReplacingMergeTree(agent_id)
ORDER BY agent_id;

CREATE TABLE IF NOT EXISTS dim_anomaly_type (
    anomaly_type_id UInt64,
    anomaly_type String
) ENGINE = ReplacingMergeTree(anomaly_type_id)
ORDER BY anomaly_type_id;

CREATE TABLE IF NOT EXISTS dim_error_details (
    error_details_id UInt64,
    log_level LowCardinality(Nullable(String)),
    error_message Nullable(String)
) ENGINE = ReplacingMergeTree(error_details_id)
ORDER BY error_details_id;


-- Fact Table
CREATE TABLE IF NOT EXISTS fact_nginx_events (
    timestamp DateTime,
    log_type LowCardinality(String),

    ip_id UInt64,
    request_id Nullable(UInt64),
    agent_id Nullable(UInt64),
    error_details_id Nullable(UInt64),
    anomaly_type_id Nullable(UInt64),

    status Nullable(UInt16),
    bytes Nullable(UInt32),
    is_anomaly UInt8
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, ip_id);

CREATE TABLE IF NOT EXISTS nginx_predictions (
    timestamp DateTime,
    predicted_requests Float64,
    predicted_lower Float64,
    predicted_upper Float64
) ENGINE = MergeTree()
ORDER BY timestamp;
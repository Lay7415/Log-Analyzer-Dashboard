CREATE TABLE IF NOT EXISTS nginx_logs (
    timestamp DateTime,
    ip String,
    country LowCardinality(String),
    log_type LowCardinality(String),

    request Nullable(String),
    method Nullable(String),
    page Nullable(String),
    status Nullable(UInt16),
    bytes Nullable(UInt32),
    referrer Nullable(String),
    agent Nullable(String),

    log_level LowCardinality(Nullable(String)),
    error_message Nullable(String),

    is_anomaly UInt8,
    anomaly_type String

) ENGINE = MergeTree()
ORDER BY timestamp;

CREATE TABLE IF NOT EXISTS nginx_predictions (
    timestamp DateTime,
    predicted_requests Float64,
    predicted_lower Float64,
    predicted_upper Float64
) ENGINE = MergeTree()
ORDER BY timestamp;
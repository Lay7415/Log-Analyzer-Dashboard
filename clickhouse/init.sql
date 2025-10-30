CREATE TABLE IF NOT EXISTS nginx_logs (
    ip String,
    time String,
    request String,
    status UInt16,
    bytes UInt32,
    referrer String,
    agent String,
    timestamp DateTime,
    country LowCardinality(String),
    is_anomaly UInt8
) ENGINE = MergeTree()
ORDER BY timestamp;
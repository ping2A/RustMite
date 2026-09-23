-- RustMite ClickHouse schema (mobipwn-inspired: daily partitions, 90-day TTL)

CREATE DATABASE IF NOT EXISTS rustmite;

CREATE TABLE IF NOT EXISTS rustmite.events
(
    `id` UUID DEFAULT generateUUIDv7(),
    `timestamp` DateTime64(6, 'UTC'),
    `message` String,
    `source_type` LowCardinality(String) DEFAULT 'rustmite_probe',
    `source` LowCardinality(String) DEFAULT '',
    `ingest_time` DateTime64(6, 'UTC') DEFAULT now64(6),
    `platform` LowCardinality(String) DEFAULT 'linux',
    `host_id` String DEFAULT '',
    `host_name` String DEFAULT '',
    `scan_id` String DEFAULT '',
    `collector` LowCardinality(String) DEFAULT '',
    `kind` LowCardinality(String) DEFAULT '',
    `check_id` LowCardinality(String) DEFAULT '',
    `data_type` LowCardinality(String) DEFAULT '',
    `process_name` LowCardinality(String) DEFAULT '',
    `process_id` UInt32 DEFAULT 0,
    `user` LowCardinality(String) DEFAULT '',
    `path` String DEFAULT '',
    `src_ip` String DEFAULT '',
    `dest_ip` String DEFAULT '',
    `file_hash` String DEFAULT '',
    `severity` LowCardinality(String) DEFAULT 'info',
    `exe_memfd` UInt8 DEFAULT 0,
    `ext` String DEFAULT '{}',
    INDEX idx_message_tokens message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_host host_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_kind kind TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (platform, host_id, timestamp, id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS rustmite.detection_signals
(
    `rule_id` UUID,
    `rule_name` String,
    `matched_at` DateTime64(6, 'UTC') DEFAULT now64(6),
    `event_id` UUID,
    `host_id` String,
    `dedup_key` String,
    `prevalence` Float64 DEFAULT 0,
    `payload` String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(matched_at)
ORDER BY (rule_id, matched_at)
TTL toDateTime(matched_at) + INTERVAL 90 DAY;

-- Control-plane durable state (hosts, scans, findings, …). ReplacingMergeTree so
-- ./dev.sh restart reloads the latest row per id via FINAL.
CREATE TABLE IF NOT EXISTS rustmite.cp_entities
(
    `entity` LowCardinality(String),
    `id` String,
    `updated_at` DateTime64(6, 'UTC') DEFAULT now64(6),
    `deleted` UInt8 DEFAULT 0,
    `payload` String
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (entity, id)
SETTINGS index_granularity = 8192;

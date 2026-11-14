-- Baseline schema for antiwire-store.
--
-- Every timestamp column holds the fixed-width UTC form the store writes,
-- `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`, so text order is chronological order.

-- One row per application, identified by `identity_key`: the path with its
-- version-shaped segments erased. A self-updating app that installs into a new
-- versioned directory keeps its row, while a copy under a different install
-- root, or another binary that adopts a known file name, gets its own.
-- `app_path` holds the most recently observed location.
CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_path TEXT NOT NULL,
    app_name TEXT NOT NULL DEFAULT '',
    signature_fingerprint TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    identity_key TEXT NOT NULL DEFAULT ''
);

-- The recent distinct locations an application has run from, newest last_seen
-- first, capped per application. A well-behaved app shows one stable path (or a
-- versioned series under its install root); a name that suddenly appears under
-- %TEMP% or a user profile is the signal this table exists to preserve.
CREATE TABLE IF NOT EXISTS application_path_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    app_path TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'BLOCK',
    direction TEXT NOT NULL DEFAULT 'OUTBOUND',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL
);

-- CIDR payload for rules whose target is a set of networks (e.g. a country
-- block). One firewall_rules row owns many entries; the cascade means deleting
-- the rule takes its networks with it.
CREATE TABLE IF NOT EXISTS firewall_rule_cidrs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES firewall_rules(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL,
    ordinal INTEGER NOT NULL DEFAULT 0
);

-- One row per connection, not per flow tuple, so two connections to the same
-- destination stay separate records.
--
-- A connection's identity is the (conn_id, conn_pid, timestamp) triple.
-- `conn_id` is the tracker's per-connection session id, which restarts at one
-- on every launch; the pid observed at flow open and the connection start in
-- `timestamp`, which updates never refresh, keep a later run's connection from
-- accumulating onto an earlier run's row. A `conn_id` of 0 never matches a live
-- session.
--
-- A non-empty `closed_at` is terminal: a later flush carrying the same triple
-- starts a fresh row, so a connection never absorbs traffic that arrived after
-- it ended. DNS blocks are completed events and are written closed.
--
-- `app_path` is the executable path observed when the row was written, not the
-- application's current path, so an update does not relabel history.
-- `blocklist_names` lists the hosts-blocklist sources that produced a block,
-- newline-separated; it is empty for allowed rows, user DNS rules, and the
-- fail-closed boot window.
CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    app_id INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT 'TCP',
    src_ip TEXT NOT NULL DEFAULT '',
    src_port INTEGER NOT NULL DEFAULT 0,
    dst_ip TEXT NOT NULL DEFAULT '',
    dst_port INTEGER NOT NULL DEFAULT 0,
    dst_domain TEXT NOT NULL DEFAULT '',
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    action_taken TEXT NOT NULL DEFAULT 'ALLOWED',
    last_seen TEXT NOT NULL,
    country_code TEXT NOT NULL DEFAULT '',
    isp TEXT NOT NULL DEFAULT '',
    blocklist_names TEXT NOT NULL DEFAULT '',
    conn_id INTEGER NOT NULL DEFAULT 0,
    conn_pid INTEGER NOT NULL DEFAULT 0,
    closed_at TEXT NOT NULL DEFAULT '',
    app_path TEXT NOT NULL DEFAULT ''
);

-- The single settings row (id 1).
--
-- AI classification: `ai_decision_mode` is `retroactive` (show the result for
-- the user to accept) or `proactive` (block when the score meets the
-- threshold). Each `ai_confidence_*` is a percent from 0 to 100. Each category
-- has an `_enabled` switch, which gates whether it is considered at all, and an
-- `_action` of `block` or `record`. The defaults keep every category enabled
-- and non-enforcing, so turning the feature on never starts blocking by
-- surprise.
--
-- `dns_answer_local_names_enabled` answers `.local` names locally with
-- NXDOMAIN (RFC 6762); turning it off forwards them upstream, for a network
-- whose Active Directory domain ends in `.local`.
--
-- `dns_new_domain_blocking_enabled` blocks domains whose registry creation
-- date is less than `dns_new_domain_max_age_days` old: 7, 14, 30 or 90. It is
-- off by default, since each new registered domain is looked up at its
-- registry.
--
-- `update_channel` is the channel the user chose: stable, beta, or nightly.
--
-- `private_relay_compatibility`: when set, the daemon loads no packet filter
-- rules, which is what macOS needs to leave iCloud Private Relay on.
CREATE TABLE IF NOT EXISTS daemon_settings (
    id INTEGER PRIMARY KEY,
    siem_enabled INTEGER NOT NULL DEFAULT 0,
    wazuh_transport TEXT NOT NULL DEFAULT 'file',
    wazuh_file_path TEXT NOT NULL DEFAULT '',
    wazuh_manager_host TEXT NOT NULL DEFAULT '',
    wazuh_manager_port INTEGER NOT NULL DEFAULT 514,
    wazuh_protocol TEXT NOT NULL DEFAULT 'udp',
    siem_file_enabled INTEGER NOT NULL DEFAULT 1,
    siem_syslog_enabled INTEGER NOT NULL DEFAULT 0,
    siem_webhook_enabled INTEGER NOT NULL DEFAULT 0,
    siem_url TEXT NOT NULL DEFAULT '',
    siem_auth_token TEXT NOT NULL DEFAULT '',
    siem_auth_header TEXT NOT NULL DEFAULT '',
    siem_send_allowed INTEGER NOT NULL DEFAULT 0,
    siem_send_blocked INTEGER NOT NULL DEFAULT 1,
    siem_send_new_app INTEGER NOT NULL DEFAULT 1,
    siem_send_new_domain INTEGER NOT NULL DEFAULT 1,
    siem_send_threats INTEGER NOT NULL DEFAULT 1,
    ai_enabled INTEGER NOT NULL DEFAULT 0,
    ai_api_key TEXT NOT NULL DEFAULT '',
    log_retention_enabled INTEGER NOT NULL DEFAULT 1,
    log_retention_days INTEGER NOT NULL DEFAULT 30,
    dns_resolver_enabled INTEGER NOT NULL DEFAULT 1,
    dns_protocol TEXT NOT NULL DEFAULT 'doh',
    doh_blocking_enabled INTEGER NOT NULL DEFAULT 1,
    doh_provider TEXT NOT NULL DEFAULT 'cloudflare',
    doh_custom_url TEXT NOT NULL DEFAULT '',
    hosts_blocklist_enabled INTEGER NOT NULL DEFAULT 0,
    hosts_blocklist_selected_lists TEXT NOT NULL DEFAULT 'hagezi_light',
    hosts_blocklist_update_frequency TEXT NOT NULL DEFAULT '24hours',
    hosts_blocklist_last_updated TEXT NOT NULL DEFAULT '0001-01-01T00:00:00Z',
    hosts_blocklist_custom_urls TEXT NOT NULL DEFAULT '',
    notify_every_connection INTEGER NOT NULL DEFAULT 0,
    notify_new_connection INTEGER NOT NULL DEFAULT 0,
    notify_new_app INTEGER NOT NULL DEFAULT 1,
    notify_threat_detected INTEGER NOT NULL DEFAULT 1,
    persist_rules_offline INTEGER NOT NULL DEFAULT 0,
    geoip_enabled INTEGER NOT NULL DEFAULT 0,
    log_daemon_connections INTEGER NOT NULL DEFAULT 0,
    power_user_settings_enabled INTEGER NOT NULL DEFAULT 0,
    dns_block_response_mode TEXT NOT NULL DEFAULT 'sinkhole',
    dns_block_custom_ip TEXT NOT NULL DEFAULT '',
    dns_rebinding_protection_enabled INTEGER NOT NULL DEFAULT 0,
    network_mapping_auto_enabled INTEGER NOT NULL DEFAULT 0,
    network_mapping_interval_minutes INTEGER NOT NULL DEFAULT 30,
    network_mapping_baseline_established INTEGER NOT NULL DEFAULT 0,
    oui_database_last_updated TEXT NOT NULL DEFAULT '0001-01-01T00:00:00Z',
    geoip_database_last_updated TEXT NOT NULL DEFAULT '0001-01-01T00:00:00Z',
    updated_at TEXT NOT NULL,
    ai_decision_mode TEXT NOT NULL DEFAULT 'retroactive',
    ai_confidence_advertising INTEGER NOT NULL DEFAULT 80,
    ai_confidence_tracking INTEGER NOT NULL DEFAULT 80,
    ai_confidence_telemetry INTEGER NOT NULL DEFAULT 80,
    ai_confidence_analytics INTEGER NOT NULL DEFAULT 80,
    ai_confidence_malicious INTEGER NOT NULL DEFAULT 80,
    ai_confidence_fraud INTEGER NOT NULL DEFAULT 80,
    ai_confidence_cryptomining INTEGER NOT NULL DEFAULT 80,
    ai_confidence_tunnel INTEGER NOT NULL DEFAULT 80,
    ai_advertising_enabled INTEGER NOT NULL DEFAULT 1,
    ai_advertising_action TEXT NOT NULL DEFAULT 'record',
    ai_tracking_enabled INTEGER NOT NULL DEFAULT 1,
    ai_tracking_action TEXT NOT NULL DEFAULT 'record',
    ai_telemetry_enabled INTEGER NOT NULL DEFAULT 1,
    ai_telemetry_action TEXT NOT NULL DEFAULT 'record',
    ai_analytics_enabled INTEGER NOT NULL DEFAULT 1,
    ai_analytics_action TEXT NOT NULL DEFAULT 'record',
    ai_malicious_enabled INTEGER NOT NULL DEFAULT 1,
    ai_malicious_action TEXT NOT NULL DEFAULT 'record',
    ai_fraud_enabled INTEGER NOT NULL DEFAULT 1,
    ai_fraud_action TEXT NOT NULL DEFAULT 'record',
    ai_cryptomining_enabled INTEGER NOT NULL DEFAULT 1,
    ai_cryptomining_action TEXT NOT NULL DEFAULT 'record',
    ai_tunnel_enabled INTEGER NOT NULL DEFAULT 1,
    ai_tunnel_action TEXT NOT NULL DEFAULT 'record',
    save_domain_lookups INTEGER NOT NULL DEFAULT 0,
    dns_answer_local_names_enabled INTEGER NOT NULL DEFAULT 1,
    dns_new_domain_blocking_enabled INTEGER NOT NULL DEFAULT 0,
    dns_new_domain_max_age_days INTEGER NOT NULL DEFAULT 30,
    update_channel TEXT NOT NULL DEFAULT 'stable',
    private_relay_compatibility INTEGER NOT NULL DEFAULT 0
);

-- `last_seen` is the throttled, persisted refresh; `latest_seen` keeps the
-- newest observation separately.
CREATE TABLE IF NOT EXISTS dns_cache_entries (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    latest_seen TEXT
);

-- Pre-aggregated 30-minute counters backing the dashboard heatmap.
CREATE TABLE IF NOT EXISTS activity_buckets (
    bucket_start TEXT NOT NULL PRIMARY KEY,
    event_count INTEGER NOT NULL DEFAULT 0,
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    blocked_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS seen_domains (
    domain TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_devices (
    mac_address TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL DEFAULT '',
    manufacturer TEXT NOT NULL DEFAULT '',
    mdns_name TEXT NOT NULL DEFAULT '',
    adapter_id TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    present INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS network_scan_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    adapter_id TEXT NOT NULL DEFAULT '',
    cidr TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS network_device_watches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL DEFAULT '',
    mac_address TEXT NOT NULL DEFAULT '',
    adapter_id TEXT NOT NULL DEFAULT '',
    cidr TEXT NOT NULL DEFAULT '',
    interval_minutes INTEGER NOT NULL DEFAULT 30,
    enabled INTEGER NOT NULL DEFAULT 1,
    present INTEGER NOT NULL DEFAULT 0,
    baseline_established INTEGER NOT NULL DEFAULT 0,
    last_checked TEXT NOT NULL DEFAULT '0001-01-01T00:00:00Z'
);

-- Ratings and the applied decision for every domain TypeSafe has classified.
--
-- One row per domain, upserted on each classification so `updated_at` tracks the
-- most recent decision while `first_seen` keeps the original sighting. The
-- `rating_*` columns are the raw Jev probabilities (0.0-1.0). The verdict and
-- top_* columns record what Antiwire did with those ratings, so a row is an
-- auditable decision rather than only a score cache: `verdict` is `block`,
-- `record`, or empty when no category met its threshold, and `top_category` /
-- `top_score` identify the category that drove it. `scan_tier` reserves the
-- basic/advanced distinction. The last four ratings are advanced signals and
-- stay 0 until an advanced check replaces the decision.
CREATE TABLE IF NOT EXISTS domain_decisions (
    domain TEXT PRIMARY KEY,
    model TEXT NOT NULL DEFAULT '',
    rating_advertising REAL NOT NULL DEFAULT 0,
    rating_tracking REAL NOT NULL DEFAULT 0,
    rating_telemetry REAL NOT NULL DEFAULT 0,
    rating_analytics REAL NOT NULL DEFAULT 0,
    rating_malicious REAL NOT NULL DEFAULT 0,
    rating_fraud REAL NOT NULL DEFAULT 0,
    rating_cryptomining REAL NOT NULL DEFAULT 0,
    rating_tunnel REAL NOT NULL DEFAULT 0,
    verdict TEXT NOT NULL DEFAULT '',
    top_category TEXT NOT NULL DEFAULT '',
    top_score REAL NOT NULL DEFAULT 0,
    scan_tier TEXT NOT NULL DEFAULT 'basic',
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    rating_newly_registered REAL NOT NULL DEFAULT 0,
    rating_registry_hold REAL NOT NULL DEFAULT 0,
    rating_hidden_registrant REAL NOT NULL DEFAULT 0,
    rating_abusive_registrar REAL NOT NULL DEFAULT 0
);

-- Optional local copy of an official registration record, written only when
-- the user has turned `save_domain_lookups` on.
CREATE TABLE IF NOT EXISTS domain_lookups (
    domain TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    registrar TEXT,
    registrar_id TEXT,
    statuses TEXT NOT NULL DEFAULT '',
    nameservers TEXT NOT NULL DEFAULT '',
    registered_at TEXT,
    expires_at TEXT,
    registry_updated_at TEXT,
    registrant_name TEXT,
    registrant_organization TEXT,
    redacted INTEGER NOT NULL DEFAULT 0,
    dnssec INTEGER,
    fetched_at TEXT NOT NULL
);

-- The system DNS redirect record, which only the DNS redirect writes. A row
-- here means a redirect is in place, and `snapshot` is what restores it. It is
-- kept out of the settings row so that a whole-row settings save cannot write
-- back a stale copy and lose the adapters' real DNS servers.
CREATE TABLE IF NOT EXISTS dns_redirect (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    snapshot TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

-- Unique per version family. Path lookups use the expression index; uniqueness
-- is not enforced on the path because synthetic placeholder paths are shared by
-- design.
CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_identity_key
    ON applications(identity_key);
CREATE INDEX IF NOT EXISTS idx_applications_app_path ON applications(app_path);
CREATE INDEX IF NOT EXISTS idx_applications_app_path_nocase
    ON applications(LOWER(app_path));
CREATE UNIQUE INDEX IF NOT EXISTS idx_application_path_history_path
    ON application_path_history(app_id, app_path);
CREATE INDEX IF NOT EXISTS idx_application_path_history_recent
    ON application_path_history(app_id, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_connection_logs_timestamp ON connection_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_connection_logs_last_seen ON connection_logs(last_seen);
CREATE INDEX IF NOT EXISTS idx_connection_logs_dst_ip ON connection_logs(dst_ip);
CREATE INDEX IF NOT EXISTS idx_connection_logs_dst_domain ON connection_logs(dst_domain);
CREATE INDEX IF NOT EXISTS idx_connection_logs_action_taken ON connection_logs(action_taken);
CREATE INDEX IF NOT EXISTS idx_connection_logs_action_taken_lower ON connection_logs(LOWER(action_taken));
CREATE INDEX IF NOT EXISTS idx_connection_logs_app_id ON connection_logs(app_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_dst_port ON connection_logs(dst_port);
CREATE INDEX IF NOT EXISTS idx_connection_logs_src_ip ON connection_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_connection_logs_protocol ON connection_logs(protocol);
CREATE INDEX IF NOT EXISTS idx_connection_logs_bytes_sent ON connection_logs(bytes_sent);
CREATE INDEX IF NOT EXISTS idx_connection_logs_bytes_received ON connection_logs(bytes_received);
-- The connection-log flush looks rows up by flow identity, comparing protocol
-- and both addresses case-insensitively. This indexes the exact expressions
-- that query uses.
CREATE INDEX IF NOT EXISTS idx_connection_logs_flow_key
    ON connection_logs(app_id, LOWER(protocol), LOWER(src_ip), LOWER(dst_ip), dst_port);
CREATE INDEX IF NOT EXISTS idx_connection_logs_conn_identity
    ON connection_logs(conn_id, conn_pid, timestamp);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_firewall_rule_cidrs_rule ON firewall_rule_cidrs(rule_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_activity_buckets_start ON activity_buckets(bucket_start);

CREATE INDEX IF NOT EXISTS idx_dns_cache_entries_last_seen ON dns_cache_entries(last_seen);
CREATE INDEX IF NOT EXISTS idx_dns_cache_entries_latest_seen
    ON dns_cache_entries(latest_seen);

CREATE INDEX IF NOT EXISTS idx_network_devices_last_seen ON network_devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_network_devices_present ON network_devices(present);
-- A watch with only an IPv4 address stores an empty MAC, so uniqueness applies
-- to real MACs only.
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_device_watches_mac
    ON network_device_watches(mac_address)
    WHERE mac_address <> '';
CREATE INDEX IF NOT EXISTS idx_network_device_watches_enabled ON network_device_watches(enabled);

CREATE INDEX IF NOT EXISTS idx_domain_decisions_updated_at ON domain_decisions(updated_at);
CREATE INDEX IF NOT EXISTS idx_domain_decisions_verdict ON domain_decisions(verdict);
CREATE INDEX IF NOT EXISTS idx_domain_lookups_fetched_at ON domain_lookups(fetched_at);

-- The settings row, with its timestamps in the fixed-width form. The column
-- defaults above stay in the short form they have in existing databases.
INSERT OR IGNORE INTO daemon_settings (
    id,
    hosts_blocklist_last_updated,
    oui_database_last_updated,
    geoip_database_last_updated,
    updated_at
)
VALUES (
    1,
    '0001-01-01T00:00:00.000000000Z',
    '0001-01-01T00:00:00.000000000Z',
    '0001-01-01T00:00:00.000000000Z',
    strftime('%Y-%m-%dT%H:%M:%f', 'now') || '000000Z'
);

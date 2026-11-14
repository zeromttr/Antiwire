//! Converts between store models and protobuf IPC types.

mod activity;
mod ai_decisions;
mod ai_settings;
mod capture;
mod domain_lookup;
mod logs;
mod network_mapping;
mod notifications;
mod rules;
mod scalars;
mod settings;
#[cfg(test)]
mod tests;
mod timestamps;
mod traffic;
mod updates;

pub(crate) use activity::{
    activity_bucket_to_proto, activity_bucket_window, history_deletion_start,
};
pub(crate) use ai_decisions::{
    ai_decision_page_to_response, ai_decisions_query_from_proto, domain_decision_to_proto,
};
pub(crate) use capture::{
    capture_device_to_proto, capture_frame_to_proto, capture_status_to_proto, CaptureId,
};
pub(crate) use domain_lookup::{
    certificate_lookup_to_proto, records_to_proto, registration_lookup_to_proto,
    seen_subdomains_to_proto,
};
pub(crate) use logs::{
    app_summary_request_to_query, app_summary_to_proto, log_page_to_response, log_request_to_query,
};
pub(crate) use network_mapping::{
    device_watch_request, netmap_overview_to_proto, scan_range_to_store,
};
pub(crate) use notifications::{alert_to_proto, notification_to_proto};
pub(crate) use rules::{
    country_selector_from_proto, country_summary_to_proto, new_country_block_from_proto,
    new_rule_from_proto, rule_selector_from_proto, rule_to_proto,
};
pub(crate) use settings::{settings_merge_request, settings_to_proto};
pub(crate) use traffic::traffic_event_to_proto;
pub(crate) use updates::update_status_to_proto;

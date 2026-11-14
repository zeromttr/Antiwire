//! Connection log, application summary, and log request conversions.

use super::scalars::{i32_to_u32, i64_to_u64};
use super::timestamps::{datetime_to_unix_secs, time_window_from_proto};
use std::collections::HashMap;
use std::hash::BuildHasher;

use antiwire_policy::UNKNOWN_APP_NAME;
use antiwire_proto::{
    ApplicationLogSummary as ProtoAppSummary, LogRequest, LogResponse, TrafficEvent,
};
use antiwire_store::{
    ApplicationLogSummary, ApplicationLogSummaryQuery, ConnectionLog, ConnectionLogPage,
    ConnectionLogQuery,
};

pub(crate) fn log_request_to_query(request: LogRequest) -> ConnectionLogQuery {
    let (time_window_start, time_window_end) =
        time_window_from_proto(request.time_window_start, request.time_window_end);
    ConnectionLogQuery {
        offset: request.offset,
        limit: request.limit,
        time_filter_seconds: request.time_filter_seconds,
        time_window_start,
        time_window_end,
        action_filter: if request.action_filter.is_empty() {
            None
        } else {
            Some(request.action_filter)
        },
        order_by: if request.order_by.is_empty() {
            None
        } else {
            Some(request.order_by)
        },
        sort_descending: request.sort_descending,
        app_name: if request.app_name.is_empty() {
            None
        } else {
            Some(request.app_name)
        },
        app_id: (request.app_id > 0).then_some(request.app_id),
        search_query: if request.search_query.is_empty() {
            None
        } else {
            Some(request.search_query)
        },
        protocol_filter: if request.protocol_filter.is_empty() {
            None
        } else {
            Some(request.protocol_filter)
        },
        country_code: if request.country_filter.is_empty() {
            None
        } else {
            Some(request.country_filter.trim().to_ascii_uppercase())
        },
        port: u16::try_from(request.port_filter)
            .ok()
            .filter(|port| *port > 0),
        host: Some(request.host_filter.trim().to_owned()).filter(|host| !host.is_empty()),
    }
}

pub(crate) fn app_summary_request_to_query(
    request: antiwire_proto::ApplicationLogSummaryRequest,
) -> ApplicationLogSummaryQuery {
    let (time_window_start, time_window_end) =
        time_window_from_proto(request.time_window_start, request.time_window_end);
    ApplicationLogSummaryQuery {
        time_filter_seconds: request.time_filter_seconds,
        time_window_start,
        time_window_end,
        action_filter: if request.action_filter.is_empty() {
            None
        } else {
            Some(request.action_filter)
        },
    }
}

pub(crate) fn log_page_to_response<S: BuildHasher>(
    page: &ConnectionLogPage,
    apps: &HashMap<i32, (String, String), S>,
) -> LogResponse {
    let logs: Vec<TrafficEvent> = page
        .logs
        .iter()
        .map(|log| connection_log_to_traffic_event(log, apps))
        .collect();

    LogResponse {
        logs,
        total_count: u32::try_from(page.total_count).unwrap_or(u32::MAX),
        blocked_count: u32::try_from(page.blocked_count).unwrap_or(u32::MAX),
        unique_domain_count: u32::try_from(page.unique_domain_count).unwrap_or(u32::MAX),
    }
}

pub(super) fn connection_log_to_traffic_event<S: BuildHasher>(
    log: &ConnectionLog,
    apps: &HashMap<i32, (String, String), S>,
) -> TrafficEvent {
    let (app_name, current_path) = apps
        .get(&log.app_id)
        .cloned()
        .unwrap_or_else(|| (UNKNOWN_APP_NAME.to_owned(), String::new()));
    // The record's own path is the version it actually ran from; the joined
    // application path is only a fallback for legacy or unplaced rows.
    let app_path = if log.app_path.is_empty() {
        current_path
    } else {
        log.app_path.clone()
    };
    TrafficEvent {
        // A saved row carries the flow's totals.
        kind: antiwire_proto::TrafficEventKind::FlowRecord.into(),
        timestamp: datetime_to_unix_secs(log.timestamp),
        app_name,
        app_path,
        protocol: log.protocol.clone(),
        src_ip: log.src_ip.clone(),
        src_port: i32_to_u32(log.src_port),
        dst_ip: log.dst_ip.clone(),
        dst_port: i32_to_u32(log.dst_port),
        dst_domain: log.dst_domain.clone(),
        bytes_sent: i64_to_u64(log.bytes_sent),
        bytes_received: i64_to_u64(log.bytes_received),
        action: log.action_taken.clone(),
        last_seen: datetime_to_unix_secs(log.last_seen),
        country_code: log.country_code.clone(),
        isp: log.isp.clone(),
        blocklist_names: antiwire_store::decode_blocklist_names(&log.blocklist_names),
        id: log.id,
        closed_at: log.closed_at.map_or(0, datetime_to_unix_secs),
        // A closed row is never active, even if its triple is still tracked
        // for a reopened successor. Legacy rows stay inactive.
        is_active: log.is_active && log.closed_at.is_none(),
    }
}

pub(crate) fn app_summary_to_proto(summary: &ApplicationLogSummary) -> ProtoAppSummary {
    ProtoAppSummary {
        app_id: summary.app_id,
        app_name: summary.app_name.clone(),
        app_path: summary.app_path.clone(),
        total_count: u32::try_from(summary.connection_count).unwrap_or(u32::MAX),
        blocked_count: u32::try_from(summary.blocked_count).unwrap_or(u32::MAX),
        total_bytes: summary.bytes_sent.saturating_add(summary.bytes_received),
        bytes_sent: summary.bytes_sent,
        bytes_received: summary.bytes_received,
    }
}

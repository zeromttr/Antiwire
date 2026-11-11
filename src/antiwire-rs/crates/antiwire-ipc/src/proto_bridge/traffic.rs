//! Live traffic events to their wire form.

use antiwire_events::{TrafficEvent, TrafficEventKind};
use antiwire_proto::TrafficEventKind as ProtoKind;

pub(crate) fn traffic_event_to_proto(event: TrafficEvent) -> antiwire_proto::TrafficEvent {
    let kind = match event.kind {
        TrafficEventKind::FlowRecord => ProtoKind::FlowRecord,
        TrafficEventKind::ByteDelta => ProtoKind::ByteDelta,
        TrafficEventKind::Lagged => ProtoKind::Lagged,
    };
    antiwire_proto::TrafficEvent {
        kind: kind.into(),
        timestamp: event.timestamp,
        app_name: event.app_name,
        app_path: event.app_path,
        protocol: event.protocol,
        src_ip: event.src_ip,
        src_port: event.src_port,
        dst_ip: event.dst_ip,
        dst_port: event.dst_port,
        dst_domain: event.dst_domain,
        bytes_sent: event.bytes_sent,
        bytes_received: event.bytes_received,
        action: event.action,
        last_seen: event.last_seen,
        country_code: event.country_code,
        isp: event.isp,
        blocklist_names: event.blocklist_names,
        id: event.id,
        closed_at: event.closed_at,
        is_active: event.is_active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kind_survives_so_clients_can_tell_totals_from_deltas() {
        for (kind, expected) in [
            (TrafficEventKind::FlowRecord, ProtoKind::FlowRecord),
            (TrafficEventKind::ByteDelta, ProtoKind::ByteDelta),
            (TrafficEventKind::Lagged, ProtoKind::Lagged),
        ] {
            let proto = traffic_event_to_proto(TrafficEvent {
                kind,
                bytes_sent: 7,
                ..TrafficEvent::default()
            });
            assert_eq!(proto.kind(), expected);
            assert_eq!(proto.bytes_sent, 7);
        }
    }
}

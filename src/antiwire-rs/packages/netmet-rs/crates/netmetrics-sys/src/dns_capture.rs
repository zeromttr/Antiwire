//! DNS as a backend that reads packets sees it.

use crate::{BackendEvent, EventSink};
use netmetrics_core::{
    DnsCallerIdentity, DnsPacket, DnsStreamReassembler, DnsTransactionTracker, parse_dns_packet,
};

/// Turns captured port-53 packets, over UDP or TCP, into DNS events.
///
/// The Linux packet socket and the macOS PKTAP reader both feed one of these, so both
/// report a lookup the same way.
#[derive(Debug)]
pub struct DnsCapture {
    streams: DnsStreamReassembler,
    transactions: DnsTransactionTracker,
}

impl DnsCapture {
    /// A capture that follows at most `max_flows` unanswered queries, up to a fixed cap.
    #[must_use]
    pub fn new(max_flows: usize) -> Self {
        Self {
            streams: DnsStreamReassembler::default(),
            transactions: DnsTransactionTracker::new(max_flows),
        }
    }

    /// Reads one packet, starting at its IP header, and emits what it completes: every
    /// lookup as a [`BackendEvent::DnsQuery`], when it is sent and again when it is
    /// answered with whatever response code, and the addresses of a successful answer as
    /// a [`BackendEvent::DnsResolved`]. A packet that is not DNS emits nothing.
    ///
    /// `caller` is asked who sent a query, which the packet alone does not say. It must
    /// return the default identity for a query this host did not send.
    pub fn observe(
        &mut self,
        packet: &[u8],
        now: u64,
        sink: &EventSink,
        mut caller: impl FnMut(&DnsPacket) -> DnsCallerIdentity,
    ) {
        if let Some(message) = parse_dns_packet(packet) {
            self.publish(message, now, sink, &mut caller);
            return;
        }
        for message in self.streams.observe(packet, now) {
            self.publish(message, now, sink, &mut caller);
        }
    }

    fn publish(
        &mut self,
        message: DnsPacket,
        now: u64,
        sink: &EventSink,
        caller: &mut impl FnMut(&DnsPacket) -> DnsCallerIdentity,
    ) {
        let caller = if message.is_response {
            DnsCallerIdentity::default()
        } else {
            caller(&message)
        };
        let Some(observation) = self.transactions.observe(message, caller, now) else {
            return;
        };
        sink.emit(BackendEvent::DnsQuery(observation.query));
        // An answer that may not be cached names no address worth remembering.
        if let Some(resolution) = observation
            .resolution
            .filter(|resolution| resolution.ttl_ms > 0)
        {
            sink.emit(BackendEvent::DnsResolved {
                pid: resolution.pid,
                query: resolution.query,
                answers: resolution.answers,
                ttl_ms: resolution.ttl_ms,
                timestamp: now,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmetrics_core::test_support::{
        dns_message, dns_over_tcp, ipv4_tcp, ipv4_udp, push_a_record,
    };
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc::{Receiver, sync_channel};

    const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 50_000);
    const RESOLVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53);

    fn sink() -> (EventSink, Receiver<BackendEvent>) {
        let (sender, receiver) = sync_channel(16);
        (
            EventSink::new(sender, Arc::new(AtomicU64::new(0))),
            receiver,
        )
    }

    fn sent_by(pid: u32) -> impl FnMut(&DnsPacket) -> DnsCallerIdentity {
        move |_| DnsCallerIdentity {
            requesting_pid: Some(pid),
            ..DnsCallerIdentity::default()
        }
    }

    /// The lookups in `events`, as (name, status, requesting PID).
    fn lookups(events: &[BackendEvent]) -> Vec<(&str, u32, Option<u32>)> {
        events
            .iter()
            .filter_map(|event| match event {
                BackendEvent::DnsQuery(query) => Some((
                    query.name.as_str(),
                    query.status,
                    query.caller.requesting_pid,
                )),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_failed_lookup_is_reported_when_sent_and_when_refused() {
        let (sink, events) = sink();
        let mut capture = DnsCapture::new(8);
        let query = ipv4_udp(CLIENT, RESOLVER, &dns_message(7, "missing.test", None, 0));
        let refusal = ipv4_udp(
            RESOLVER,
            CLIENT,
            &dns_message(7, "missing.test", Some(3), 0),
        );
        capture.observe(&query, 1, &sink, sent_by(42));
        capture.observe(&refusal, 2, &sink, |_| {
            unreachable!("a response does not say who asked")
        });

        let events: Vec<_> = events.try_iter().collect();
        assert_eq!(
            lookups(&events),
            [("missing.test", 0, Some(42)), ("missing.test", 3, Some(42))]
        );
        assert_eq!(events.len(), 2, "a failure resolves to no address");
    }

    #[test]
    fn an_answered_lookup_also_publishes_its_addresses() {
        let (sink, events) = sink();
        let mut capture = DnsCapture::new(8);
        let mut answer = dns_message(7, "example.test", Some(0), 1);
        push_a_record(&mut answer, [192, 0, 2, 1], 30);
        capture.observe(
            &ipv4_udp(CLIENT, RESOLVER, &dns_message(7, "example.test", None, 0)),
            1,
            &sink,
            sent_by(42),
        );
        capture.observe(&ipv4_udp(RESOLVER, CLIENT, &answer), 2, &sink, sent_by(0));

        let events: Vec<_> = events.try_iter().collect();
        assert_eq!(
            lookups(&events),
            [("example.test", 0, Some(42)), ("example.test", 0, Some(42))]
        );
        assert!(matches!(
            events.last(),
            Some(BackendEvent::DnsResolved { pid: 42, query, answers, ttl_ms: 30_000, timestamp: 2 })
                if query == "example.test" && answers.len() == 1
        ));
    }

    #[test]
    fn a_lookup_over_tcp_is_reported_like_one_over_udp() {
        let (sink, events) = sink();
        let mut capture = DnsCapture::new(8);
        let query = dns_over_tcp(&dns_message(9, "stream.test", None, 0));
        let mut answer = dns_message(9, "stream.test", Some(0), 1);
        push_a_record(&mut answer, [192, 0, 2, 9], 60);
        let answer = dns_over_tcp(&answer);
        // The answer arrives in two segments.
        let (head, tail) = answer.split_at(10);
        capture.observe(
            &ipv4_tcp(CLIENT, RESOLVER, 100, 0, &query),
            1,
            &sink,
            sent_by(7),
        );
        capture.observe(
            &ipv4_tcp(RESOLVER, CLIENT, 500, 0, head),
            2,
            &sink,
            sent_by(0),
        );
        capture.observe(
            &ipv4_tcp(RESOLVER, CLIENT, 510, 0, tail),
            3,
            &sink,
            sent_by(0),
        );

        let events: Vec<_> = events.try_iter().collect();
        assert_eq!(
            lookups(&events),
            [("stream.test", 0, Some(7)), ("stream.test", 0, Some(7))]
        );
        assert!(matches!(
            events.last(),
            Some(BackendEvent::DnsResolved { pid: 7, .. })
        ));
    }
}

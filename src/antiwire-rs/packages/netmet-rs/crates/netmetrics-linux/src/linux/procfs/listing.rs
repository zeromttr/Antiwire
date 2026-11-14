//! What the backend last listed from `/proc`, which the procfs fallback polls against and
//! the eBPF source takes over.

use super::{inode_pid_map, read_proc_flows, snapshot_row_is_news};
use crate::linux::interface::{best_interface_index, emit_interface_samples};
use crate::linux::io_error;
use crate::linux::process::{ProcessReading, read_process};
use netmetrics_core::{CookieSource, FlowKey, ProcessInfo, SocketCookie, unix_now_ms};
use netmetrics_sys::{BackendError, BackendEvent, EventSink};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// The connections the backend last listed from `/proc/net` and the processes it last
/// reported holding a socket.
///
/// The procfs fallback announces a connection when it first lists it and closes it when it
/// stops listing it, and reports processes the same way. When the eBPF source starts it
/// reconciles against the same listing, so a connection the fallback announced is neither
/// announced again nor left open, and it keeps the processes current from then on.
#[derive(Debug, Default)]
pub(in crate::linux) struct ProcfsListing {
    /// Each listed connection's owner, zero when unknown, and socket inode.
    flows: HashMap<FlowKey, (u32, u64)>,
    /// The processes reported holding a socket, as `/proc` described them then.
    processes: HashMap<u32, ProcessReading>,
}

impl ProcfsListing {
    /// One poll of the fallback: reports the connections that appeared or went and the
    /// processes that started or stopped holding a socket since the last poll, and samples
    /// the interfaces.
    ///
    /// # Errors
    ///
    /// Returns why `/proc/net` could not be read.
    pub(in crate::linux) fn poll(&mut self, sink: &EventSink) -> Result<(), BackendError> {
        let timestamp = unix_now_ms();
        let inode_pids = inode_pid_map(Path::new("/proc"));
        let flows = read_proc_flows(Path::new("/proc/net"), &inode_pids)
            .map_err(|error| io_error("procfs sockets", &error))?;
        self.list_flows(flows, timestamp, sink);
        self.list_processes(inode_pids.values().copied().collect(), timestamp, sink);
        emit_interface_samples(sink, timestamp);
        Ok(())
    }

    /// Reports the connections that appeared or went since the last listing, for the eBPF
    /// source: when it starts, and on a kernel without the lifecycle tracepoint at every
    /// poll interval.
    ///
    /// # Errors
    ///
    /// Returns why `/proc/net` could not be read.
    #[cfg(feature = "ebpf")]
    pub(in crate::linux) fn reconcile(&mut self, sink: &EventSink) -> Result<(), BackendError> {
        let timestamp = unix_now_ms();
        let inode_pids = inode_pid_map(Path::new("/proc"));
        let flows = read_proc_flows(Path::new("/proc/net"), &inode_pids)
            .map_err(|error| io_error("procfs eBPF reconciliation", &error))?;
        self.list_flows(flows, timestamp, sink);
        Ok(())
    }

    /// Hands over the processes the fallback reported, for the eBPF source to keep current.
    #[cfg(feature = "ebpf")]
    pub(in crate::linux) fn take_processes(&mut self) -> HashMap<u32, ProcessReading> {
        std::mem::take(&mut self.processes)
    }

    /// Lists `current`: announces each connection in it that is news
    /// ([`snapshot_row_is_news`]), and closes each one listed before that it no longer has.
    fn list_flows(
        &mut self,
        current: HashMap<FlowKey, (u32, u64)>,
        timestamp: u64,
        sink: &EventSink,
    ) {
        for (key, (pid, inode)) in &current {
            if snapshot_row_is_news(self.flows.get(key), *pid, *inode) {
                sink.emit(BackendEvent::Opened {
                    key: *key,
                    pid: *pid,
                    cookie: Some(SocketCookie {
                        value: *inode,
                        source: CookieSource::LinuxInode,
                    }),
                    timestamp,
                    if_index: best_interface_index(key.remote_addr),
                });
            }
        }
        for key in self.flows.keys() {
            if !current.contains_key(key) {
                sink.emit(BackendEvent::Closed {
                    pid: 0,
                    key: *key,
                    timestamp,
                });
            }
        }
        self.flows = current;
    }

    /// Reports each of `pids` that `/proc` describes as started when it is new or now another
    /// process, and each process reported before that no longer holds a socket as stopped.
    fn list_processes(&mut self, pids: HashSet<u32>, timestamp: u64, sink: &EventSink) {
        let mut current = HashMap::new();
        for pid in pids {
            if let Some(reading) = read_process(Path::new("/proc"), pid) {
                if self.processes.get(&pid).map(|known| &known.identity) != Some(&reading.identity)
                {
                    sink.emit(BackendEvent::ProcessStarted(ProcessInfo {
                        pid,
                        identity: reading.identity.clone(),
                    }));
                }
                current.insert(pid, reading);
            }
        }
        for (pid, known) in &self.processes {
            if !current.contains_key(pid) {
                sink.emit(BackendEvent::ProcessStopped {
                    pid: *pid,
                    timestamp,
                    identity: Some(known.identity.clone()),
                });
            }
        }
        self.processes = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmetrics_core::Protocol;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc::{Receiver, sync_channel};

    const PID: u32 = 7;
    const TIMESTAMP: u64 = 1_000_000;

    fn sink() -> (EventSink, Receiver<BackendEvent>) {
        let (sender, receiver) = sync_channel(64);
        (
            EventSink::new(sender, Arc::new(AtomicU64::new(0))),
            receiver,
        )
    }

    /// A connection from one fixed local address, told apart by `local_port`.
    fn key(local_port: u16) -> FlowKey {
        FlowKey {
            protocol: Protocol::Tcp,
            local_addr: Ipv4Addr::new(192, 0, 2, 10).into(),
            local_port,
            remote_addr: Ipv4Addr::new(198, 51, 100, 20).into(),
            remote_port: 443,
        }
    }

    /// `ports`' connections as `/proc/net` lists them, each with its port as its inode.
    fn listed(ports: &[u16]) -> HashMap<FlowKey, (u32, u64)> {
        ports
            .iter()
            .map(|port| (key(*port), (PID, u64::from(*port))))
            .collect()
    }

    /// The ports of the connections `events` announce and close, in that order.
    fn announced_and_closed(events: &Receiver<BackendEvent>) -> (Vec<u16>, Vec<u16>) {
        let (mut opened, mut closed) = (Vec::new(), Vec::new());
        for event in events.try_iter() {
            match event {
                BackendEvent::Opened { key, .. } => opened.push(key.local_port),
                BackendEvent::Closed { key, .. } => closed.push(key.local_port),
                other => panic!("unexpected event {other:?}"),
            }
        }
        opened.sort_unstable();
        closed.sort_unstable();
        (opened, closed)
    }

    /// The fallback's polls and the eBPF source's reconciliation list into the same table. So
    /// when the eBPF source takes over, a connection the fallback announced and that is still
    /// there is not announced again, and one that went while the sources switched is closed.
    #[test]
    fn a_listing_announces_each_connection_once_and_closes_it_when_it_goes() {
        let (sink, events) = sink();
        let mut listing = ProcfsListing::default();
        listing.list_flows(listed(&[1, 2]), TIMESTAMP, &sink);
        assert_eq!(announced_and_closed(&events), (vec![1, 2], vec![]));

        listing.list_flows(listed(&[1, 3]), TIMESTAMP + 1, &sink);
        assert_eq!(announced_and_closed(&events), (vec![3], vec![2]));
    }

    /// A socket the kernel recycled onto the same tuple is a new connection, and the cookie
    /// lets the collector tell it from the one before.
    #[test]
    fn a_tuple_on_a_new_socket_is_announced_again() {
        let (sink, events) = sink();
        let mut listing = ProcfsListing::default();
        listing.list_flows(listed(&[1]), TIMESTAMP, &sink);
        let _ = events.try_iter().count();

        listing.list_flows(HashMap::from([(key(1), (PID, 99))]), TIMESTAMP + 1, &sink);
        assert_eq!(announced_and_closed(&events), (vec![1], vec![]));
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn handing_over_the_processes_leaves_none_to_report_stopped() {
        let (sink, events) = sink();
        let mut listing = ProcfsListing::default();
        listing.processes.insert(
            PID,
            ProcessReading {
                identity: netmetrics_core::ProcessIdentity {
                    executable: "/usr/bin/curl".to_owned(),
                    name: "curl".to_owned(),
                    start_ts: TIMESTAMP,
                },
                start_ticks: Some(1),
            },
        );
        let handed = listing.take_processes();
        assert_eq!(handed.keys().copied().collect::<Vec<_>>(), [PID]);
        listing.list_processes(HashSet::new(), TIMESTAMP, &sink);
        assert!(
            events.try_iter().next().is_none(),
            "the eBPF source reports their exits now"
        );
    }
}

//! Point-in-time active socket counts from the host OS.

pub use netmetrics_core::SocketCount;

/// Returns the number of established TCP connections on this host, IPv4 and IPv6.
///
/// On every platform a connection counts when its state is `ESTABLISHED` or `CLOSE-WAIT`
/// ([`TcpState::is_established`](netmetrics_core::TcpState::is_established)), which is
/// what the TCP MIB counts as currently established (`tcpCurrEstab`, RFC 4022).
/// Listeners, handshakes, connections this end has sent its FIN on, and UDP sockets never
/// count. The same rule decides which TCP flows are open and not finishing
/// ([`FlowEvent::Finishing`](netmetrics_core::FlowEvent::Finishing)): a socket-table row
/// opens a flow only when it is established, and Linux eBPF and macOS packet capture open
/// a flow when its connection becomes established and report it finishing when it stops.
///
/// The platforms' tables differ in one thing the rule cannot settle, a connection that a
/// listener has not accepted yet:
///
/// - Linux lists it, so it counts.
/// - Windows counts every established row that names an owning process. Its documentation
///   does not say whether such a connection is listed.
/// - macOS lists sockets by the descriptors processes hold, so it does not count. A socket
///   that several descriptors refer to counts once.
///
/// Prefers a fresh count published by the collector's last successful TCP
/// owner-table poll. Stale or missing samples walk the platform table.
/// Acquisition failure keeps last-known and marks it stale when one exists,
/// and is unavailable rather than a valid zero when nothing has been sampled.
#[must_use]
pub fn active_connection_count() -> SocketCount {
    platform_active_socket_count()
}

#[cfg(all(windows, feature = "windows"))]
fn platform_active_socket_count() -> SocketCount {
    netmetrics_windows::active_socket_count()
}

#[cfg(all(target_os = "linux", feature = "linux"))]
fn platform_active_socket_count() -> SocketCount {
    LAST_KNOWN.observe(netmetrics_linux::active_socket_count().ok())
}

#[cfg(all(target_os = "macos", feature = "macos"))]
fn platform_active_socket_count() -> SocketCount {
    LAST_KNOWN.observe(netmetrics_macos::active_socket_count().ok())
}

#[cfg(any(
    all(target_os = "linux", feature = "linux"),
    all(target_os = "macos", feature = "macos"),
))]
static LAST_KNOWN: LastKnown = LastKnown::new();

/// The last count a platform table walk returned, so a failed walk can be
/// reported as stale or unavailable instead of as a valid zero.
#[cfg(any(
    test,
    all(target_os = "linux", feature = "linux"),
    all(target_os = "macos", feature = "macos"),
))]
struct LastKnown(std::sync::atomic::AtomicU64);

#[cfg(any(
    test,
    all(target_os = "linux", feature = "linux"),
    all(target_os = "macos", feature = "macos"),
))]
impl LastKnown {
    const NONE: u64 = u64::MAX;

    const fn new() -> Self {
        Self(std::sync::atomic::AtomicU64::new(Self::NONE))
    }

    fn observe(&self, sample: Option<u32>) -> SocketCount {
        use std::sync::atomic::Ordering;
        match sample {
            Some(count) => {
                self.0.store(u64::from(count), Ordering::Relaxed);
                SocketCount::fresh(count)
            }
            None => u32::try_from(self.0.load(Ordering::Relaxed))
                .map_or(SocketCount::UNAVAILABLE, SocketCount::stale),
        }
    }
}

#[cfg(not(any(
    all(windows, feature = "windows"),
    all(target_os = "linux", feature = "linux"),
    all(target_os = "macos", feature = "macos"),
)))]
fn platform_active_socket_count() -> SocketCount {
    SocketCount::UNAVAILABLE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_walk_is_never_a_fresh_zero() {
        let last = LastKnown::new();
        assert_eq!(last.observe(None), SocketCount::UNAVAILABLE);
        assert_eq!(last.observe(Some(5)), SocketCount::fresh(5));
        assert_eq!(last.observe(None), SocketCount::stale(5));
        assert_eq!(last.observe(Some(0)), SocketCount::fresh(0));
    }
}

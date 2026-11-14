//! What the `st` column of a `/proc/net/tcp` or `tcp6` row says about the socket it lists.
//!
//! `proc_pid_net(5)` calls `st` "the internal status of the socket" and lists no values,
//! so this follows the kernel. `tcp4_seq_show` (`net/ipv4/tcp_ipv4.c`) and its twin
//! `tcp6_seq_show` (`net/ipv6/tcp_ipv6.c`) print three kinds of socket:
//!
//! - A full socket (`get_tcp4_sock`). `st` is its state, and `inode` is `sock_i_ino`: the
//!   inode of the socket file that refers to it, or zero when no file does. No file refers
//!   to a socket its application has closed, which the kernel then finishes alone
//!   (`sk_ino`, "zero if orphaned", in `include/net/sock.h`), nor to a connection still
//!   waiting in a listener's queue for `accept(2)`.
//! - A time-wait socket (`get_timewait4_sock`), which takes the place of a full socket once
//!   this end has closed the connection (`tcp_time_wait` in `net/ipv4/tcp_minisocks.c`).
//!   `st` is its sub-state: `FIN_WAIT2` until the peer's FIN arrives, then `TIME_WAIT`.
//!   Its `inode` is always zero.
//! - A request socket (`get_openreq4`): a handshake a listener has not completed. `st` is
//!   always `SYN_RECV` and `inode` always zero.
//!
//! A row is a flow, and is counted as an active connection, when its state is established
//! ([`TcpState::is_established`]): `ESTABLISHED` or `CLOSE_WAIT`. The kernel keeps its own
//! count of the same two states: `tcp_set_state` (`net/ipv4/tcp.c`) raises
//! `TCP_MIB_CURRESTAB`, the `CurrEstab` field of `/proc/net/snmp`, when a socket enters
//! one of them and lowers it when the socket leaves both. A connection waiting to be
//! accepted is established although its inode is still zero.
//!
//! Every established row is a full socket, and the kernel reports a full socket's end:
//! the eBPF lifecycle program sees it change to `TCP_CLOSE` (`tcp_done`), which also
//! happens when a time-wait socket takes its place. A time-wait or request socket has no
//! such change left to report, so a flow opened from one would never be closed.

use netmetrics_core::TcpState;

/// The state a full socket prints in `st`, numbered as in `include/net/tcp_states.h`.
///
/// `None` for a number that is no state of a connection. The kernel defines two beyond
/// those below, and prints neither here: `TCP_NEW_SYN_RECV` (`0C`), since a request
/// socket prints `SYN_RECV`, and `TCP_BOUND_INACTIVE` (`0D`), which the header calls a
/// pseudo-state for `inet_diag`.
pub(crate) fn from_procfs(st: u8) -> Option<TcpState> {
    Some(match st {
        0x01 => TcpState::Established,
        0x02 => TcpState::SynSent,
        0x03 => TcpState::SynReceived,
        0x04 => TcpState::FinWait1,
        0x05 => TcpState::FinWait2,
        0x06 => TcpState::TimeWait,
        0x07 => TcpState::Closed,
        0x08 => TcpState::CloseWait,
        0x09 => TcpState::LastAck,
        0x0a => TcpState::Listen,
        0x0b => TcpState::Closing,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every state in `include/net/tcp_states.h`, under the name the kernel gives it.
    #[test]
    fn each_kernel_state_number_is_its_state() {
        let states = [
            (0x01, "TCP_ESTABLISHED", Some(TcpState::Established)),
            (0x02, "TCP_SYN_SENT", Some(TcpState::SynSent)),
            (0x03, "TCP_SYN_RECV", Some(TcpState::SynReceived)),
            (0x04, "TCP_FIN_WAIT1", Some(TcpState::FinWait1)),
            (0x05, "TCP_FIN_WAIT2", Some(TcpState::FinWait2)),
            (0x06, "TCP_TIME_WAIT", Some(TcpState::TimeWait)),
            (0x07, "TCP_CLOSE", Some(TcpState::Closed)),
            (0x08, "TCP_CLOSE_WAIT", Some(TcpState::CloseWait)),
            (0x09, "TCP_LAST_ACK", Some(TcpState::LastAck)),
            (0x0a, "TCP_LISTEN", Some(TcpState::Listen)),
            (0x0b, "TCP_CLOSING", Some(TcpState::Closing)),
            (0x0c, "TCP_NEW_SYN_RECV", None),
            (0x0d, "TCP_BOUND_INACTIVE", None),
        ];
        for (st, name, state) in states {
            assert_eq!(from_procfs(st), state, "{name}");
        }
        assert_eq!(from_procfs(0), None, "the kernel numbers states from one");
        for st in 0x0e..=u8::MAX {
            assert_eq!(from_procfs(st), None, "unknown state {st:#04x}");
        }
    }
}

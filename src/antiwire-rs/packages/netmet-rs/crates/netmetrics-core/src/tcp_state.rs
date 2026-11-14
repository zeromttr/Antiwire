//! The states of a TCP connection, and which of them make it an established one.

/// A state of a TCP connection, named as in RFC 9293, section 3.3.2.
///
/// Each backend turns the numbers its socket table prints into these, so one rule
/// ([`TcpState::is_established`]) decides on every platform which connections are counted
/// as active and which socket-table rows open a flow.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TcpState {
    /// No connection.
    Closed,
    /// Waiting for a connection request.
    Listen,
    /// This end has sent its connection request and waits for the answer.
    SynSent,
    /// Both ends have sent a connection request, and this end waits for its own to be
    /// acknowledged.
    SynReceived,
    /// The handshake is complete and neither end has finished sending.
    Established,
    /// This end has sent its FIN, which the peer has not acknowledged yet.
    FinWait1,
    /// The peer has acknowledged this end's FIN and has not sent its own.
    FinWait2,
    /// The peer has sent its FIN. This end has not, and can still send.
    CloseWait,
    /// Both ends have sent a FIN, and this end's is not acknowledged yet.
    Closing,
    /// The peer sent its FIN first, and this end waits for its own to be acknowledged.
    LastAck,
    /// The connection is over, and its addresses are held back for a while.
    TimeWait,
}

impl TcpState {
    /// Whether a connection in this state is established: `ESTABLISHED` or `CLOSE-WAIT`.
    ///
    /// This is what the TCP MIB counts as currently established (`tcpCurrEstab`, RFC 4022:
    /// "the number of TCP connections for which the current state is either ESTABLISHED or
    /// CLOSE-WAIT"). In both states the handshake is complete and the application has not
    /// yet asked for the connection to end.
    ///
    /// Every other state is left out:
    ///
    /// - `SYN-SENT` and `SYN-RECEIVED` are handshakes, which may never complete.
    /// - In `FIN-WAIT-1` and `FIN-WAIT-2` this end has sent its FIN. The application may
    ///   only have shut down its sending side, and still be receiving, or it may have
    ///   closed the socket, leaving the system to finish alone. Linux tells the two apart
    ///   and Windows does not: its table lists both with the same state and owning
    ///   process. A rule every platform can apply therefore counts neither.
    /// - In `CLOSING`, `LAST-ACK` and `TIME-WAIT` both ends have sent their FIN.
    /// - `LISTEN` and `CLOSED` are not connections.
    #[must_use]
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established | Self::CloseWait)
    }
}

#[cfg(test)]
mod tests {
    use super::TcpState;

    #[test]
    fn only_established_and_close_wait_are_established() {
        let states = [
            (TcpState::Closed, false),
            (TcpState::Listen, false),
            (TcpState::SynSent, false),
            (TcpState::SynReceived, false),
            (TcpState::Established, true),
            (TcpState::FinWait1, false),
            (TcpState::FinWait2, false),
            (TcpState::CloseWait, true),
            (TcpState::Closing, false),
            (TcpState::LastAck, false),
            (TcpState::TimeWait, false),
        ];
        for (state, established) in states {
            assert_eq!(state.is_established(), established, "{state:?}");
        }
    }
}

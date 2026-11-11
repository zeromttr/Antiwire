// Each field is an independent probe result, not a state machine in disguise.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CapabilityMatrix {
    pub lifecycle: bool,
    pub tcp_send: bool,
    pub tcp_receive: bool,
    pub udp_send: bool,
    pub udp_receive: bool,
}

impl CapabilityMatrix {
    pub(crate) fn has_byte_accounting(self) -> bool {
        self.tcp_send || self.tcp_receive || self.udp_send || self.udp_receive
    }

    pub(crate) fn needs_reconciliation(self) -> bool {
        !self.lifecycle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_missing_byte_group_keeps_other_groups_viable() {
        let matrix = CapabilityMatrix {
            tcp_send: true,
            tcp_receive: true,
            udp_send: false,
            udp_receive: true,
            lifecycle: true,
        };
        assert!(matrix.has_byte_accounting());
        assert!(!matrix.needs_reconciliation());
    }

    #[test]
    fn missing_lifecycle_requires_reconciliation() {
        let matrix = CapabilityMatrix {
            tcp_send: true,
            lifecycle: false,
            ..CapabilityMatrix::default()
        };
        assert!(matrix.has_byte_accounting());
        assert!(matrix.needs_reconciliation());
    }

    #[test]
    fn no_byte_group_is_not_a_viable_ebpf_backend() {
        assert!(!CapabilityMatrix::default().has_byte_accounting());
    }
}

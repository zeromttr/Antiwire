use std::sync::Arc;

use ahash::AHashSet;
use arc_swap::ArcSwap;

/// Fail-closed gate while hosts blocklists are enabled but not yet loaded/synced.
pub(super) struct BlocklistBootGate {
    state: ArcSwap<BlocklistBootGateSnapshot>,
}

pub(super) struct BlocklistBootGateSnapshot {
    pub(super) active: bool,
    pub(super) allow_hosts: AHashSet<String>,
}

impl BlocklistBootGate {
    pub(super) fn new() -> Self {
        Self {
            state: ArcSwap::from_pointee(BlocklistBootGateSnapshot {
                active: false,
                allow_hosts: AHashSet::new(),
            }),
        }
    }

    pub(super) fn arm(&self, hosts: AHashSet<String>) {
        self.state.store(Arc::new(BlocklistBootGateSnapshot {
            active: true,
            allow_hosts: hosts,
        }));
    }

    pub(super) fn clear(&self) {
        self.state.store(Arc::new(BlocklistBootGateSnapshot {
            active: false,
            allow_hosts: AHashSet::new(),
        }));
    }

    pub(super) fn is_active(&self) -> bool {
        self.state.load().active
    }

    pub(super) fn blocks_normalized(&self, domain: &str) -> bool {
        let state = self.state.load();
        state.blocks_normalized(domain)
    }

    #[must_use]
    pub(super) fn load_full(&self) -> Arc<BlocklistBootGateSnapshot> {
        self.state.load_full()
    }
}

impl BlocklistBootGateSnapshot {
    pub(super) fn blocks_normalized(&self, domain: &str) -> bool {
        self.active && !self.allow_hosts.contains(domain)
    }
}

//! The `iptables` command surface, behind a trait so chain handling is testable.

use firew_core::Error;
#[cfg(not(target_os = "linux"))]
use firew_core::ErrorKind;

use super::IptablesBackend;

/// Abstracts `iptables` table/chain operations so chain attachment, jump repair,
/// and rule reconstruction can be unit-tested deterministically on every host.
pub(crate) trait IptablesOps {
    fn chain_exists(&self, table: &str, chain: &str) -> Result<bool, Error>;
    fn new_chain(&self, table: &str, chain: &str) -> Result<(), Error>;
    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, Error>;
    fn insert(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<(), Error>;
    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), Error>;
    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), Error>;
    fn delete_chain(&self, table: &str, chain: &str) -> Result<(), Error>;
}

#[cfg(target_os = "linux")]
pub(super) struct NativeIptables(iptables::IPTables);

#[cfg(target_os = "linux")]
impl IptablesOps for NativeIptables {
    fn chain_exists(&self, table: &str, chain: &str) -> Result<bool, Error> {
        self.0
            .chain_exists(table, chain)
            .map_err(|e| map_ipt(e.as_ref()))
    }

    fn new_chain(&self, table: &str, chain: &str) -> Result<(), Error> {
        self.0
            .new_chain(table, chain)
            .map_err(|e| map_ipt(e.as_ref()))
    }

    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, Error> {
        self.0.list(table, chain).map_err(|e| map_ipt(e.as_ref()))
    }

    fn insert(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<(), Error> {
        self.0
            .insert(table, chain, rule, position)
            .map_err(|e| map_ipt(e.as_ref()))
    }

    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), Error> {
        self.0
            .append(table, chain, rule)
            .map_err(|e| map_ipt(e.as_ref()))
    }

    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), Error> {
        self.0
            .delete(table, chain, rule)
            .map_err(|e| map_ipt(e.as_ref()))
    }

    fn delete_chain(&self, table: &str, chain: &str) -> Result<(), Error> {
        self.0
            .delete_chain(table, chain)
            .map_err(|e| map_ipt(e.as_ref()))
    }
}

impl IptablesBackend {
    #[cfg(target_os = "linux")]
    pub(super) fn ipt() -> Result<NativeIptables, Error> {
        iptables::new(false)
            .map(NativeIptables)
            .map_err(|e| map_ipt(e.as_ref()))
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn ipt() -> Result<StubIptables, Error> {
        Err(Error::new(
            ErrorKind::BackendUnavailable,
            "iptables unavailable on this target",
        ))
    }

    /// Ensures `chain_name` exists AND is jumped to exactly once from `parent`.
    pub(crate) fn ensure_chain_with(
        ipt: &dyn IptablesOps,
        chain_name: &str,
        parent: &str,
    ) -> Result<(), Error> {
        if !ipt.chain_exists("filter", chain_name)? {
            ipt.new_chain("filter", chain_name)?;
        }
        let jump_spec = format!("-j {chain_name}");
        let jump_line = format!("-A {parent} {jump_spec}");
        let lines = ipt.list("filter", parent)?;
        let count = lines.iter().filter(|line| line.trim() == jump_line).count();
        if count == 0 {
            ipt.insert("filter", parent, &jump_spec, 1)?;
        } else if count > 1 {
            for _ in 1..count {
                let _ = ipt.delete("filter", parent, &jump_spec);
            }
        }
        Ok(())
    }

    /// Removes `chain_name`, which the caller has just emptied, and the jump to it from
    /// `parent`, so a manager that holds no rules leaves nothing in the packet path.
    /// [`Self::ensure_chain_with`] puts both back before the next rule is installed.
    ///
    /// `iptables(8)`, `-X`: "There must be no references to the chain", so the jump goes
    /// first, and "The chain must be empty". A rule another process put into the chain
    /// since makes the delete fail; the chain then stays, with its jump put back, because a
    /// chain nothing jumps to would hide that rule from the packets it was written for.
    pub(crate) fn release_chain_with(ipt: &dyn IptablesOps, chain_name: &str, parent: &str) {
        let jump_spec = format!("-j {chain_name}");
        if ipt.delete("filter", parent, &jump_spec).is_ok()
            && ipt.delete_chain("filter", chain_name).is_err()
        {
            let _ = ipt.insert("filter", parent, &jump_spec, 1);
        }
    }

    /// Returns whether both managed chains exist and are attached to `INPUT`/`OUTPUT`.
    pub(crate) fn chains_attached_with(
        ipt: &dyn IptablesOps,
        in_chain: &str,
        out_chain: &str,
    ) -> Result<bool, Error> {
        for (chain, parent) in [(in_chain, "INPUT"), (out_chain, "OUTPUT")] {
            if !ipt.chain_exists("filter", chain)? {
                return Ok(false);
            }
            let expected = format!("-A {parent} -j {chain}");
            let lines = ipt.list("filter", parent)?;
            if !lines.iter().any(|line| line.trim() == expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
#[cfg(not(target_os = "linux"))]
pub(super) struct StubIptables;

#[cfg(not(target_os = "linux"))]
impl IptablesOps for StubIptables {
    fn chain_exists(&self, _table: &str, _chain: &str) -> Result<bool, Error> {
        Err(Error::new(ErrorKind::BackendUnavailable, "stub"))
    }
    fn new_chain(&self, _table: &str, _chain: &str) -> Result<(), Error> {
        Err(Error::new(ErrorKind::BackendUnavailable, "stub"))
    }
    fn list(&self, _table: &str, _chain: &str) -> Result<Vec<String>, Error> {
        Err(Error::new(ErrorKind::BackendUnavailable, "stub"))
    }
    fn insert(&self, _table: &str, _chain: &str, _rule: &str, _pos: i32) -> Result<(), Error> {
        Err(Error::new(ErrorKind::BackendUnavailable, "stub"))
    }
    fn append(&self, _table: &str, _chain: &str, _rule: &str) -> Result<(), Error> {
        Err(Error::new(ErrorKind::BackendUnavailable, "stub"))
    }
    fn delete(&self, _table: &str, _chain: &str, _rule: &str) -> Result<(), Error> {
        Err(Error::new(ErrorKind::BackendUnavailable, "stub"))
    }
    fn delete_chain(&self, _table: &str, _chain: &str) -> Result<(), Error> {
        Err(Error::new(ErrorKind::BackendUnavailable, "stub"))
    }
}

fn map_ipt(err: &dyn std::error::Error) -> Error {
    let text = err.to_string();
    let kind = crate::ipset::classify_cli_stderr(&text);
    Error::new(kind, format!("iptables: {text}"))
}

//! Rule validation and native-expansion accounting.

use crate::direction::Direction;
use crate::domain::normalize_domain;
use crate::error::{Error, ErrorKind};
use crate::protocol::Protocol;

use super::{
    AddressSetMode, Rule, MAX_ADDRESS_SET_ENTRIES, MAX_MATCHERS_PER_FIELD, MAX_NATIVE_EXPANSION,
    MAX_PACKAGE_SID_LEN, MAX_RULE_LABEL_LEN,
};

/// Whether a rule with these matcher counts would break the Cartesian caps
/// if each remote address took its own native row.
///
/// True when the remote addresses alone exceed [`MAX_MATCHERS_PER_FIELD`], or
/// when every direction × address × port combination together exceeds
/// [`MAX_NATIVE_EXPANSION`]. An empty field counts as one "any" alternative.
/// Callers use it to decide whether to fall back to [`AddressSetMode::Set`].
#[must_use]
pub fn cartesian_exceeds_limits(
    direction: Direction,
    remote_addresses: usize,
    local_addresses: usize,
    remote_ports: usize,
    local_ports: usize,
) -> bool {
    let directions: usize = if direction == Direction::Both { 2 } else { 1 };
    let rows = directions
        .saturating_mul(remote_addresses.max(1))
        .saturating_mul(local_addresses.max(1))
        .saturating_mul(remote_ports.max(1))
        .saturating_mul(local_ports.max(1));
    remote_addresses > MAX_MATCHERS_PER_FIELD || rows > MAX_NATIVE_EXPANSION
}

impl Rule {
    /// Validates that the rule has at least one matcher.
    ///
    /// # Errors
    /// Returns an error when the logical key or matchers are invalid.
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_matchers()?;
        self.validate_protocol()?;
        self.validate_address_families()?;
        self.validate_metadata()?;
        let expansion = self.native_expansion()?;
        if expansion > MAX_NATIVE_EXPANSION {
            return Err(self.error(
                ErrorKind::LimitExceeded,
                format!("rule requires {expansion} native rows; maximum is {MAX_NATIVE_EXPANSION}"),
            ));
        }
        Ok(())
    }

    /// An error about this rule, tagged with its key.
    fn error(&self, kind: ErrorKind, message: impl Into<String>) -> Error {
        Error::new(kind, message).with_logical_key(&self.inner.logical_key)
    }

    /// At least one matcher, each within its count limit, and normalized domains.
    fn validate_matchers(&self) -> Result<(), Error> {
        let inner = &self.inner;
        if inner.remote_addresses.is_empty()
            && inner.local_addresses.is_empty()
            && inner.remote_ports.is_empty()
            && inner.local_ports.is_empty()
            && inner.application_path.is_none()
            && inner.package_sid.is_none()
            && inner.remote_domains.is_empty()
        {
            return Err(self.error(ErrorKind::InvalidRule, "rule has no matchers"));
        }
        match inner.address_set_mode {
            AddressSetMode::Cartesian => {
                validate_matcher_count("remote addresses", inner.remote_addresses.len())?;
            }
            AddressSetMode::Set if inner.remote_addresses.is_empty() => {
                return Err(self.error(
                    ErrorKind::InvalidRule,
                    "address-set mode requires at least one remote address",
                ));
            }
            AddressSetMode::Set if inner.remote_addresses.len() > MAX_ADDRESS_SET_ENTRIES => {
                return Err(self.error(
                    ErrorKind::LimitExceeded,
                    format!(
                        "address set holds {} entries; maximum is {MAX_ADDRESS_SET_ENTRIES}",
                        inner.remote_addresses.len()
                    ),
                ));
            }
            AddressSetMode::Set => {}
        }
        validate_matcher_count("local addresses", inner.local_addresses.len())?;
        validate_matcher_count("remote ports", inner.remote_ports.len())?;
        validate_matcher_count("local ports", inner.local_ports.len())?;
        validate_matcher_count("remote domains", inner.remote_domains.len())?;
        for domain in &inner.remote_domains {
            if normalize_domain(domain)? != *domain {
                return Err(self.error(ErrorKind::InvalidRule, "domain matcher is not normalized"));
            }
        }
        Ok(())
    }

    /// A usable protocol number, and ports only with TCP or UDP.
    fn validate_protocol(&self) -> Result<(), Error> {
        let inner = &self.inner;
        if inner.protocol == Protocol::Other(0) {
            return Err(self.error(
                ErrorKind::InvalidRule,
                "protocol number 0 is reserved and cannot be used as a matcher",
            ));
        }
        if (!inner.remote_ports.is_empty() || !inner.local_ports.is_empty())
            && !matches!(inner.protocol, Protocol::Tcp | Protocol::Udp)
        {
            return Err(self.error(ErrorKind::InvalidRule, "port matchers require TCP or UDP"));
        }
        Ok(())
    }

    /// The application path, package SID, and label.
    fn validate_metadata(&self) -> Result<(), Error> {
        let inner = &self.inner;
        if let Some(path) = &inner.application_path {
            if path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
                || path.as_os_str().to_string_lossy().contains('\0')
            {
                return Err(self.error(
                    ErrorKind::InvalidRule,
                    "application path contains a NUL or parent component",
                ));
            }
        }
        if let Some(sid) = &inner.package_sid {
            validate_package_sid(sid)
                .map_err(|error| error.with_logical_key(&inner.logical_key))?;
        }
        if let Some(label) = &inner.label {
            if label.len() > MAX_RULE_LABEL_LEN {
                return Err(self.error(
                    ErrorKind::LimitExceeded,
                    format!("rule label exceeds {MAX_RULE_LABEL_LEN} bytes"),
                ));
            }
            if label.contains('\0') {
                return Err(self.error(ErrorKind::InvalidRule, "rule label contains a NUL"));
            }
        }
        Ok(())
    }

    fn validate_address_families(&self) -> Result<(), Error> {
        let has_any_v4 = self
            .inner
            .remote_addresses
            .iter()
            .chain(&self.inner.local_addresses)
            .any(|net| net.addr().is_ipv4());
        let has_any_v6 = self
            .inner
            .remote_addresses
            .iter()
            .chain(&self.inner.local_addresses)
            .any(|net| net.addr().is_ipv6());

        if self.inner.protocol == Protocol::IcmpV4 && has_any_v6 {
            return Err(Error::new(
                ErrorKind::InvalidRule,
                "ICMPv4 protocol cannot be combined with IPv6 address matchers",
            )
            .with_logical_key(&self.inner.logical_key));
        }
        if self.inner.protocol == Protocol::IcmpV6 && has_any_v4 {
            return Err(Error::new(
                ErrorKind::InvalidRule,
                "ICMPv6 protocol cannot be combined with IPv4 address matchers",
            )
            .with_logical_key(&self.inner.logical_key));
        }

        if !self.inner.remote_addresses.is_empty() && !self.inner.local_addresses.is_empty() {
            let remote_v4 = self
                .inner
                .remote_addresses
                .iter()
                .any(|net| net.addr().is_ipv4());
            let remote_v6 = self
                .inner
                .remote_addresses
                .iter()
                .any(|net| net.addr().is_ipv6());
            let local_v4 = self
                .inner
                .local_addresses
                .iter()
                .any(|net| net.addr().is_ipv4());
            let local_v6 = self
                .inner
                .local_addresses
                .iter()
                .any(|net| net.addr().is_ipv6());
            if !(remote_v4 && local_v4 || remote_v6 && local_v6) {
                return Err(Error::new(
                    ErrorKind::InvalidRule,
                    "remote and local address matchers have disjoint IP families",
                )
                .with_logical_key(&self.inner.logical_key));
            }
        }
        Ok(())
    }

    /// Returns the conservative number of native rows required by the rule.
    ///
    /// Under [`AddressSetMode::Set`] the remote addresses collapse into one
    /// native object, so they contribute a single factor instead of one row
    /// each. When both `remote_addresses` and `local_addresses` are populated,
    /// only same-family `(remote, local)` pairs are counted.
    ///
    /// # Errors
    ///
    /// Returns an error when the expansion calculation overflows.
    pub fn native_expansion(&self) -> Result<usize, Error> {
        let address_factor = match self.inner.address_set_mode {
            AddressSetMode::Cartesian => {
                if !self.remote_addresses().is_empty() && !self.local_addresses().is_empty() {
                    let remote_v4 = self
                        .remote_addresses()
                        .iter()
                        .filter(|n| n.addr().is_ipv4())
                        .count();
                    let remote_v6 = self.remote_addresses().len() - remote_v4;
                    let local_v4 = self
                        .local_addresses()
                        .iter()
                        .filter(|n| n.addr().is_ipv4())
                        .count();
                    let local_v6 = self.local_addresses().len() - local_v4;
                    remote_v4
                        .checked_mul(local_v4)
                        .and_then(|v4| {
                            remote_v6
                                .checked_mul(local_v6)
                                .and_then(|v6| v4.checked_add(v6))
                        })
                        .ok_or_else(|| {
                            Error::new(ErrorKind::LimitExceeded, "native expansion overflow")
                                .with_logical_key(self.logical_key())
                        })?
                        .max(1)
                } else {
                    self.remote_addresses()
                        .len()
                        .max(1)
                        .checked_mul(self.local_addresses().len().max(1))
                        .ok_or_else(|| {
                            Error::new(ErrorKind::LimitExceeded, "native expansion overflow")
                                .with_logical_key(self.logical_key())
                        })?
                }
            }
            AddressSetMode::Set => {
                if self.local_addresses().is_empty() {
                    1
                } else {
                    let has_remote_v4 = self.remote_addresses().iter().any(|n| n.addr().is_ipv4());
                    let has_remote_v6 = self.remote_addresses().iter().any(|n| n.addr().is_ipv6());
                    self.local_addresses()
                        .iter()
                        .filter(|n| {
                            (n.addr().is_ipv4() && has_remote_v4)
                                || (n.addr().is_ipv6() && has_remote_v6)
                        })
                        .count()
                        .max(1)
                }
            }
        };
        let factors = [
            if self.direction() == Direction::Both {
                2
            } else {
                1
            },
            address_factor,
            self.remote_ports().len().max(1),
            self.local_ports().len().max(1),
        ];
        factors.into_iter().try_fold(1usize, |total, factor| {
            total.checked_mul(factor).ok_or_else(|| {
                Error::new(ErrorKind::LimitExceeded, "native expansion overflow")
                    .with_logical_key(self.logical_key())
            })
        })
    }
}

fn validate_matcher_count(name: &str, count: usize) -> Result<(), Error> {
    if count > MAX_MATCHERS_PER_FIELD {
        return Err(Error::new(
            ErrorKind::LimitExceeded,
            format!("{name} count {count} exceeds {MAX_MATCHERS_PER_FIELD}"),
        ));
    }
    Ok(())
}

fn validate_package_sid(sid: &str) -> Result<(), Error> {
    if sid.is_empty() || sid.len() > MAX_PACKAGE_SID_LEN || !sid.is_ascii() {
        return Err(Error::new(
            ErrorKind::InvalidRule,
            "package SID has an invalid size or encoding",
        ));
    }
    let mut parts = sid.split('-');
    if parts.next() != Some("S")
        || parts.clone().count() < 3
        || parts.any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(Error::new(
            ErrorKind::InvalidRule,
            "package SID must use canonical S-1-... notation",
        ));
    }
    Ok(())
}

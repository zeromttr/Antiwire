//! ETW logger names derived from a collector's configured session name.
//!
//! Pure string rules, kept here so configuration can reject a name before the
//! Windows backend tries to start a trace with it.

/// Prefix every logger name owned by `netmetrics` starts with.
pub const ETW_LOGGER_PREFIX: &str = "netmetrics";
/// Longest logger name, in UTF-16 code units, the collector will start.
pub const ETW_LOGGER_LIMIT: usize = 200;

/// Kernel and optional DNS logger names for one configured session name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EtwLoggerNames {
    /// Kernel network trace logger.
    pub kernel: String,
    /// DNS client trace logger, when DNS hints are enabled.
    pub dns: Option<String>,
}

impl EtwLoggerNames {
    /// Derives the logger names for `configured`.
    ///
    /// A name that does not already start with `netmetrics` or `netmetrics-`
    /// (in any case) gets the `netmetrics-` prefix. The DNS logger appends
    /// `-dns` to the kernel name.
    ///
    /// # Errors
    ///
    /// Returns a message when `configured` contains NUL or a derived name is
    /// longer than [`ETW_LOGGER_LIMIT`] UTF-16 code units.
    pub fn derive(configured: &str, dns_enabled: bool) -> Result<Self, String> {
        if configured.contains('\0') {
            return Err("ETW session name must not contain NUL".to_owned());
        }
        let kernel = if has_owned_prefix(configured) {
            configured.to_owned()
        } else {
            format!("{ETW_LOGGER_PREFIX}-{configured}")
        };
        let dns = dns_enabled.then(|| format!("{kernel}-dns"));
        for name in std::iter::once(kernel.as_str()).chain(dns.as_deref()) {
            let units = name.encode_utf16().count();
            if units > ETW_LOGGER_LIMIT {
                return Err(format!(
                    "derived ETW logger name is {units} UTF-16 code units; maximum is {ETW_LOGGER_LIMIT}"
                ));
            }
        }
        Ok(Self { kernel, dns })
    }
}

/// Whether `name` already carries the `netmetrics` logger prefix, ignoring case.
#[must_use]
pub fn has_owned_prefix(name: &str) -> bool {
    name.eq_ignore_ascii_case(ETW_LOGGER_PREFIX)
        || name
            .get(..ETW_LOGGER_PREFIX.len() + 1)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("netmetrics-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_once_and_derives_the_dns_name() {
        let names = EtwLoggerNames::derive("Antiwire-Net", true).expect("valid");
        assert_eq!(names.kernel, "netmetrics-Antiwire-Net");
        assert_eq!(names.dns.as_deref(), Some("netmetrics-Antiwire-Net-dns"));

        let names = EtwLoggerNames::derive("NETMETRICS-x", false).expect("valid");
        assert_eq!(names.kernel, "NETMETRICS-x");
        assert_eq!(names.dns, None);
    }

    #[test]
    fn validates_derived_utf16_lengths_and_nul() {
        assert!(EtwLoggerNames::derive(&"a".repeat(189), false).is_ok());
        assert!(EtwLoggerNames::derive(&"a".repeat(190), false).is_err());
        assert!(EtwLoggerNames::derive(&"a".repeat(185), true).is_ok());
        assert!(EtwLoggerNames::derive(&"a".repeat(186), true).is_err());
        assert!(EtwLoggerNames::derive("valid\0invalid", false).is_err());

        let non_bmp = "😀".repeat(94);
        assert!(EtwLoggerNames::derive(&non_bmp, false).is_ok());
        assert!(EtwLoggerNames::derive(&(non_bmp + "ab"), false).is_err());
    }
}

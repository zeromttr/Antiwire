use netmetrics_core::EtwLoggerNames;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionNames {
    kernel: String,
    dns: Option<String>,
    process: String,
}

impl SessionNames {
    pub(crate) fn new(configured: &str, dns_enabled: bool) -> Result<Self, String> {
        let EtwLoggerNames { kernel, dns } = EtwLoggerNames::derive(configured, dns_enabled)?;
        // Fixed length keeps every previously valid configured name valid.
        let process = format!("netmetrics-process-{:016x}", identity_hash(&kernel));
        Ok(Self {
            kernel,
            dns,
            process,
        })
    }

    pub(crate) fn kernel(&self) -> &str {
        &self.kernel
    }

    pub(crate) fn dns(&self) -> Option<&str> {
        self.dns.as_deref()
    }

    pub(crate) fn all(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.kernel())
            .chain(self.dns())
            .chain(Some(self.process()))
    }

    pub(crate) fn process(&self) -> &str {
        &self.process
    }
}

pub(crate) fn identity_hash(name: &str) -> u64 {
    canonical_identity(name)
        .into_iter()
        .fold(0xcbf2_9ce4_8422_2325, |hash, unit| {
            unit.to_le_bytes().into_iter().fold(hash, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
            })
        })
}

pub(crate) fn canonical_identity(name: &str) -> Vec<u16> {
    name.to_lowercase().encode_utf16().collect()
}

#[cfg(test)]
mod tests {
    use super::{SessionNames, canonical_identity};

    #[test]
    fn preserves_short_names_and_derives_dns_name_once() {
        let names = SessionNames::new("Antiwire-Net", true).expect("valid names");
        assert_eq!(names.kernel(), "netmetrics-Antiwire-Net");
        assert_eq!(names.dns(), Some("netmetrics-Antiwire-Net-dns"));

        let names = SessionNames::new("netmetrics", true).expect("valid names");
        assert_eq!(names.kernel(), "netmetrics");
        assert_eq!(names.dns(), Some("netmetrics-dns"));
    }

    #[test]
    fn aliases_have_the_same_case_insensitive_lock_identity() {
        let plain = SessionNames::new("foo", false).unwrap();
        let prefixed = SessionNames::new("NETMETRICS-FOO", false).unwrap();
        assert_eq!(
            canonical_identity(plain.kernel()),
            canonical_identity(prefixed.kernel())
        );

        let with_dns = SessionNames::new("foo", true).unwrap();
        let dns_as_kernel = SessionNames::new("foo-dns", false).unwrap();
        assert_eq!(
            canonical_identity(with_dns.dns().unwrap()),
            canonical_identity(dns_as_kernel.kernel())
        );
    }
}

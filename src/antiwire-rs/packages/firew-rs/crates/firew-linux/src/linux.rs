//! Linux backend dispatch.

use firew_core::Error;
use firew_sys::{Backend, BackendConfig};

use crate::detect::{select_backend, BackendKind};
use crate::iptables::IptablesBackend;
use crate::nftables::NftablesBackend;

/// Linux firewall backend with nftables preference and iptables fallback.
pub struct LinuxBackend {
    inner: Box<dyn Backend>,
}

impl Backend for LinuxBackend {
    fn open(config: &BackendConfig) -> Result<Self, Error> {
        let inner: Box<dyn Backend> = match select_backend(config.prefer_backend)? {
            BackendKind::Nftables => Box::new(NftablesBackend::open(config)?),
            BackendKind::Iptables => Box::new(IptablesBackend::open(config)?),
        };
        Ok(Self { inner })
    }

    firew_sys::forward_backend!(inner);
}

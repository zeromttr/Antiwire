//! Windows backend dispatch (`INetFw` primary, WFP fallback).

use firew_core::{Error, ErrorKind};
use firew_sys::{Backend, BackendConfig, BackendPreference};

use crate::inetfw::InetFwBackend;
use crate::wfp::WfpBackend;

/// Windows firewall backend.
pub struct WindowsBackend {
    inner: Box<dyn Backend>,
}

impl Backend for WindowsBackend {
    fn open(config: &BackendConfig) -> Result<Self, Error> {
        let inner: Box<dyn Backend> = match config.prefer_backend {
            BackendPreference::Wfp => Box::new(WfpBackend::open(config)?),
            BackendPreference::InetFw => Box::new(InetFwBackend::open(config)?),
            BackendPreference::Auto => match InetFwBackend::open(config) {
                Ok(b) => Box::new(b),
                Err(primary_err) => match WfpBackend::open(config) {
                    Ok(b) => Box::new(b),
                    Err(fallback_err) => {
                        return Err(Error::new(
                            ErrorKind::BackendUnavailable,
                            format!("INetFw failed: {primary_err}; WFP failed: {fallback_err}"),
                        ));
                    }
                },
            },
            BackendPreference::Nftables | BackendPreference::Iptables | BackendPreference::Pf => {
                return Err(Error::new(
                    ErrorKind::BackendUnavailable,
                    "invalid backend preference for windows",
                ));
            }
        };
        Ok(Self { inner })
    }

    firew_sys::forward_backend!(inner);
}

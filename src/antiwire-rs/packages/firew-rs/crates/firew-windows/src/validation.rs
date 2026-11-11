//! Rule checks shared by the `INetFw` and WFP backends.

use std::os::windows::ffi::OsStrExt as _;

use firew_core::{Action, Error, ErrorKind, Rule};

/// Longest application path, in UTF-16 units, the native APIs accept.
const MAX_APPLICATION_PATH_UNITS: usize = 32_767;

/// Rejects application paths neither Windows backend can install.
///
/// `backend` names the backend in the error message.
pub(crate) fn validate_application_path(backend: &str, rule: &Rule) -> Result<(), Error> {
    let Some(path) = rule.application_path() else {
        return Ok(());
    };
    if !path.is_absolute() {
        return Err(Error::new(
            ErrorKind::InvalidRule,
            format!("{backend} application paths must be absolute"),
        )
        .with_logical_key(rule.logical_key()));
    }
    if path.as_os_str().encode_wide().count() >= MAX_APPLICATION_PATH_UNITS {
        return Err(Error::new(
            ErrorKind::LimitExceeded,
            format!("{backend} application path exceeds the native UTF-16 limit"),
        )
        .with_logical_key(rule.logical_key()));
    }
    Ok(())
}

/// Rejects `Action::Reject`: neither Windows API can answer with a reset or an
/// ICMP error, only allow or block.
///
/// `display` names the backend in the message; `platform` is the short tag
/// recorded as the error's platform detail.
pub(crate) fn refuse_reject(display: &str, platform: &str, rule: &Rule) -> Result<(), Error> {
    if rule.action() != Action::Reject {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::UnsupportedOperation,
        format!("{display} cannot represent reject semantics"),
    )
    .with_logical_key(rule.logical_key())
    .with_platform_detail(platform))
}

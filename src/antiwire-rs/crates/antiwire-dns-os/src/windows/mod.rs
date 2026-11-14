//! Windows per-adapter DNS capture, redirect, and restore.
#![allow(unsafe_code)]

mod boot_heal;
mod command;
pub mod command_line;
mod native;
mod powershell;
mod state;

use std::mem::size_of;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::AppliedRedirect;

// Live adapter restores belong to the interceptor's coordinated lifecycle.
// A hard-killed process is recovered from the durable snapshot by the reaper
// or this boot task, rather than an independent process-local restore path.
pub use boot_heal::{
    register as register_boot_heal, unregister as unregister_boot_heal, HEAL_HOST_STATE_FLAG,
};

/// Returns whether this process token is elevated (Administrator).
///
/// Uses `TokenElevation` rather than Shell32 `IsUserAnAdmin` so a pure console
/// daemon does not load `shell32`/`user32` solely for the elevation check.
/// Loading those DLLs causes Windows to skip `CTRL_LOGOFF` / `CTRL_SHUTDOWN`
/// console handlers for the process.
///
/// Each Win32 call sits in its own `unsafe` block (same style as the daemon's
/// `enable_debug_privilege`): the only memory we hand the OS is stack locals
/// sized for the requested information class.
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` is a process pseudo-handle; `token` is a
    // valid out-pointer that receives an open handle on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    let elevation_len = u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(u32::MAX);
    // SAFETY: buffer is a `TOKEN_ELEVATION` for `TokenElevation`; length matches
    // the type; `returned` is a valid out-pointer. `token` was opened above.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            elevation_len,
            &raw mut returned,
        )
    };
    // SAFETY: closes the handle from the successful `OpenProcessToken` above.
    let _ = unsafe { CloseHandle(token) };
    ok.is_ok() && elevation.TokenIsElevated != 0
}

/// Current adapter DNS as a JSON snapshot, or `None` when it cannot be captured.
pub fn capture_state() -> Option<String> {
    match dns_backend() {
        DnsBackend::Native => Some(native::capture_state()),
        DnsBackend::Powershell => powershell::capture_state(),
    }
}

/// Redirect adapters and return a JSON snapshot of **every** device/family
/// successfully changed. `prior_saved_json` preserves originals across unclean
/// restart recovery so re-redirect never records `127.0.0.1` as "original".
pub fn redirect_capturing(redirect_v6: bool, prior_saved_json: &str) -> Option<AppliedRedirect> {
    match dns_backend() {
        DnsBackend::Native => native::redirect_capturing(redirect_v6, prior_saved_json),
        DnsBackend::Powershell => crate::common::redirect_capturing(
            redirect_v6,
            prior_saved_json,
            powershell::capture_state,
            state::add_new_entries,
            powershell::redirect,
            powershell::flush_cache,
        ),
    }
}

/// The snapshot a redirect must be able to reverse: `prior_saved_json` plus
/// the originals of adapters it does not cover yet. Changes nothing.
///
/// Persist the result, then pass it to [`apply_redirect`]. That order means
/// no adapter is ever changed before its original is on disk.
pub fn plan_redirect(redirect_v6: bool, prior_saved_json: &str) -> Option<String> {
    match dns_backend() {
        DnsBackend::Native => native::plan_redirect(redirect_v6, prior_saved_json),
        DnsBackend::Powershell => crate::common::plan_redirect(
            prior_saved_json,
            powershell::capture_state,
            state::add_new_entries,
        ),
    }
}

/// Redirect the adapters `plan` records, and only those, to loopback.
///
/// Returns the snapshot restore must reverse, and whether every adapter it
/// tried was redirected, or `None` when nothing was.
pub fn apply_redirect(redirect_v6: bool, plan: &str) -> Option<AppliedRedirect> {
    match dns_backend() {
        DnsBackend::Native => native::apply_redirect(redirect_v6, plan),
        DnsBackend::Powershell => crate::common::apply_redirect(
            redirect_v6,
            plan,
            powershell::redirect,
            powershell::flush_cache,
        ),
    }
}

pub fn restore(saved_state_json: &str) -> bool {
    match dns_backend() {
        DnsBackend::Native => native::restore(saved_state_json),
        DnsBackend::Powershell => powershell::restore(saved_state_json),
    }
}

pub fn flush_cache() {
    match dns_backend() {
        DnsBackend::Native => native::flush_dns_cache(),
        DnsBackend::Powershell => powershell::flush_cache(),
    }
}

#[derive(Clone, Copy)]
enum DnsBackend {
    Native,
    Powershell,
}

fn dns_backend() -> DnsBackend {
    // `is_native_supported` queries the OS version. It cannot change while the
    // process lives, so resolving the backend once avoids a version call on
    // every capture/redirect/restore/flush.
    static BACKEND: std::sync::OnceLock<DnsBackend> = std::sync::OnceLock::new();
    *BACKEND.get_or_init(|| {
        if native::is_native_supported() {
            DnsBackend::Native
        } else {
            DnsBackend::Powershell
        }
    })
}

//! Interface name to index lookup.

use std::ffi::CString;

/// Kernel index of the interface called `name`, or `None` when no such
/// interface exists or the name contains a NUL byte.
#[must_use]
pub fn interface_index_by_name(name: &str) -> Option<u32> {
    let c_name = CString::new(name).ok()?;
    // SAFETY: `c_name` is a NUL-terminated interface name that outlives the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    (index != 0).then_some(index)
}

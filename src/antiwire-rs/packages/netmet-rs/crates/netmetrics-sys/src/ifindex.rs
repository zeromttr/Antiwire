//! Interface name to index lookup.

use std::collections::HashMap;
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

/// Interface indexes by name, each looked up once until [`forget`](Self::forget).
///
/// A packet reader learns the interface of every packet by name, and
/// [`interface_index_by_name`] is a system call. A host has a handful of interfaces, so
/// their indexes are kept. An interface that is removed and created again may get another
/// index, so the owner forgets what it knows from time to time.
#[derive(Debug, Default)]
pub struct InterfaceIndexes {
    known: HashMap<String, Option<u32>>,
}

impl InterfaceIndexes {
    /// The index of the interface called `name`, as [`interface_index_by_name`] gave it the
    /// first time it was asked since the last [`forget`](Self::forget).
    pub fn index(&mut self, name: &str) -> Option<u32> {
        self.index_with(name, interface_index_by_name)
    }

    fn index_with(&mut self, name: &str, lookup: impl FnOnce(&str) -> Option<u32>) -> Option<u32> {
        if let Some(index) = self.known.get(name) {
            return *index;
        }
        let index = lookup(name);
        self.known.insert(name.to_owned(), index);
        index
    }

    /// Forgets every index, so that each is looked up again when next asked for.
    pub fn forget(&mut self) {
        self.known.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn an_index_is_looked_up_once_until_it_is_forgotten() {
        let lookups = Cell::new(0_u32);
        let lookup = |name: &str| {
            lookups.set(lookups.get() + 1);
            (name == "en0").then_some(4)
        };
        let mut indexes = InterfaceIndexes::default();
        assert_eq!(indexes.index_with("en0", lookup), Some(4));
        assert_eq!(indexes.index_with("en0", lookup), Some(4));
        // An interface that does not exist is not asked about again either.
        assert_eq!(indexes.index_with("gone0", lookup), None);
        assert_eq!(indexes.index_with("gone0", lookup), None);
        assert_eq!(lookups.get(), 2);

        indexes.forget();
        assert_eq!(indexes.index_with("en0", lookup), Some(4));
        assert_eq!(lookups.get(), 3);
    }

    #[test]
    fn an_interface_that_does_not_exist_has_no_index() {
        let mut indexes = InterfaceIndexes::default();
        assert_eq!(indexes.index("netmetrics-no-such-interface"), None);
    }
}

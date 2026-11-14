//! Port range matchers.

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{Error, ErrorKind};

/// Inclusive port range matcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Creates a range covering a single port.
    /// # Errors
    ///
    /// Returns an error when `port` is zero.
    pub fn single(port: u16) -> Result<Self, Error> {
        Self::range(port, port)
    }

    /// Creates an inclusive port range.
    ///
    /// # Errors
    /// Returns an error when either port is zero or `start` is greater than `end`.
    pub fn range(start: u16, end: u16) -> Result<Self, Error> {
        if start == 0 || end == 0 || start > end {
            return Err(Error::new(
                ErrorKind::InvalidRule,
                format!("invalid port range {start}-{end}"),
            ));
        }
        Ok(Self { start, end })
    }

    /// Start port (inclusive).
    #[must_use]
    pub fn start(self) -> u16 {
        self.start
    }

    /// End port (inclusive).
    #[must_use]
    pub fn end(self) -> u16 {
        self.end
    }

    /// Returns whether only one port is covered.
    #[must_use]
    pub fn is_single(self) -> bool {
        self.start == self.end
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            start: u16,
            end: u16,
        }

        let repr = Repr::deserialize(deserializer)?;
        Self::range(repr.start, repr.end).map_err(serde::de::Error::custom)
    }
}

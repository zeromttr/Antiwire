//! Stable logical rule identity.

use std::borrow::Borrow;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{Error, ErrorKind};

/// Maximum number of ASCII bytes in a [`RuleKey`].
pub const MAX_RULE_KEY_LEN: usize = 32;

/// Stable, portable identifier for one logical firewall rule.
///
/// Keys contain only ASCII letters, digits, `_`, and `-`, and are limited to
/// [`MAX_RULE_KEY_LEN`] bytes so the complete ownership marker fits every
/// supported native firewall.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RuleKey(String);

impl RuleKey {
    /// Returns the key as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for RuleKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RuleKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for RuleKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<RuleKey> for String {
    fn from(value: RuleKey) -> Self {
        value.0
    }
}

impl From<&RuleKey> for String {
    fn from(value: &RuleKey) -> Self {
        value.0.clone()
    }
}

impl From<&RuleKey> for RuleKey {
    fn from(value: &RuleKey) -> Self {
        value.clone()
    }
}

impl PartialEq<str> for RuleKey {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for RuleKey {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl FromStr for RuleKey {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value)
    }
}

impl TryFrom<&str> for RuleKey {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::new(ErrorKind::InvalidRule, "empty rule key"));
        }
        if value.len() > MAX_RULE_KEY_LEN {
            return Err(Error::new(
                ErrorKind::LimitExceeded,
                format!("rule key exceeds {MAX_RULE_KEY_LEN} bytes"),
            ));
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(Error::new(
                ErrorKind::InvalidRule,
                "rule key must contain only ASCII letters, digits, '_' or '-'",
            ));
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for RuleKey {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str()).map(|_| Self(value))
    }
}

impl<'de> Deserialize<'de> for RuleKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

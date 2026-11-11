use std::fmt;
use zeroize::Zeroize;

/// In-memory secret byte buffer that zeroizes on drop.
#[derive(Clone, Default)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Takes ownership of `value`'s buffer. The `String` is not left allocated.
    #[must_use]
    pub fn from_string(value: String) -> Self {
        Self::new(value.into_bytes())
    }

    /// Views the secret as UTF-8.
    ///
    /// # Errors
    ///
    /// Returns an error when the buffer is not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.inner)
    }

    pub fn expose_secret(&self) -> &[u8] {
        &self.inner
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        if self.inner.len() != other.inner.len() {
            return false;
        }
        let mut difference = 0_u8;
        for (left, right) in self.inner.iter().zip(&other.inner) {
            difference |= left ^ right;
        }
        difference == 0
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

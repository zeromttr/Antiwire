//! Secure key storage and zeroized secret types.

mod acl;
mod error;
mod group;
mod keystore;
mod private_file;
mod secret;
mod unix;

#[cfg(windows)]
mod windows;

pub use acl::{
    is_privileged_owner, restrict_dir_to_owner_and_admins, restrict_to_owner_and_admins,
};
pub use error::KeyStoreError;
#[cfg(unix)]
pub use group::group_id;
#[cfg(windows)]
pub use group::restrict_to_admins_and_group;
pub use group::GroupAccess;
pub use keystore::{KeyStore, DB_KEY_LEN};
pub use private_file::write_private_file;
pub use secret::SecretBytes;
pub use unix::UnixSecureFileKeyProvider;

#[cfg(windows)]
pub use windows::WindowsDpapiKeyProvider;

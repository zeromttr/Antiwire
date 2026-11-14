//! Fixtures shared by the crate's unit tests.

use std::sync::Arc;

use antiwire_secrets::UnixSecureFileKeyProvider;
use antiwire_store::Store;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tempfile::TempDir;

/// A store in a fresh temporary directory. Keep the directory alive for as
/// long as the store is used; dropping it deletes the database.
pub(crate) fn temp_store() -> (TempDir, Arc<Store>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = UnixSecureFileKeyProvider::new(dir.path().join("key"));
    let store = Store::open_with_keystore(dir.path().join("db.sqlite"), &keystore).expect("store");
    (dir, Arc::new(store))
}

/// A store for fixtures that cannot hold its directory, such as a helper that
/// returns only the service built on it. The directory is leaked so the
/// database outlives the test body.
pub(crate) fn leaked_store() -> Arc<Store> {
    let (dir, store) = temp_store();
    std::mem::forget(dir);
    store
}

/// An `A` query for `name`, which must already be fully qualified
/// (`"example.test."`).
pub(crate) fn a_query(id: u16, name: &str) -> Message {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii(name).expect("query name"),
        RecordType::A,
    ));
    query
}

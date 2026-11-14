use antiwire_store::Store;
use tempfile::tempdir;

#[test]
fn disk_size_counts_the_database_and_its_companion_files() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("observations.sqlite");
    let store = Store::open(&path).unwrap();
    let on_disk: u64 = ["", "-wal", "-shm"]
        .iter()
        .filter_map(|suffix| std::fs::metadata(format!("{}{suffix}", path.display())).ok())
        .map(|meta| meta.len())
        .sum();
    let size = store.disk_size_bytes().expect("the database file exists");
    assert!(size > 0);
    assert_eq!(size, on_disk);
}

use super::*;

#[test]
fn process_start_field_survives_parenthesized_names() {
    // `starttime` is field 22; the state immediately after `)` is field 3.
    let stat = "42 (name with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 20";
    assert_eq!(parse_proc_start_ticks(stat), Some(4242));
}

#[test]
fn process_start_ticks_convert_from_boot_epoch() {
    let root = std::env::temp_dir().join(format!("netmetrics-proc-stat-{}", std::process::id()));
    fs::create_dir_all(&root).expect("create fixture root");
    fs::write(root.join("stat"), "cpu 1 2 3\nbtime 1700000000\n").expect("write fixture");
    // The exact value depends on the host clock tick rate, but it must be
    // at or after the boot epoch and retain millisecond precision.
    let converted = proc_start_epoch_ms(&root, 100).expect("conversion");
    let _ = fs::remove_file(root.join("stat"));
    let _ = fs::remove_dir(&root);
    assert!(converted >= 1_700_000_000_000);
    assert!(converted <= 1_700_000_100_000);
}

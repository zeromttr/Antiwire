use super::*;

#[test]
fn parses_interface_counters() {
    let temp = std::env::temp_dir().join(format!("netmetrics-proc-net-dev-{}", std::process::id()));
    fs::write(
        &temp,
        "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n eth0: 100 2 3 4 0 0 0 0 200 5 6 7 0 0 0 0\n",
    )
    .expect("write fixture");
    let rows = read_interface_stats(&temp, 9).expect("parse");
    let _ = fs::remove_file(&temp);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].rx_bytes, 100);
    assert_eq!(rows[0].tx_errors, 6);
    assert_eq!(rows[0].tx_drops, 7);
}

//! Maps `hosts_blocklist_update_frequency` setting values to sync intervals.

/// Hours between automatic blocklist downloads, or `None` for manual (no auto sync).
#[must_use]
pub fn blocklist_sync_interval_hours(frequency: &str) -> Option<f64> {
    let freq = frequency.trim().to_ascii_lowercase();
    if freq == "manual" {
        return None;
    }

    Some(match freq.as_str() {
        "1hour" | "1h" => 1.0,
        "3hours" | "3h" => 3.0,
        "6hours" | "6h" => 6.0,
        "12hours" | "12h" => 12.0,
        "24hours" | "24h" | "daily" => 24.0,
        "48hours" | "48h" => 48.0,
        "5days" | "5d" => 24.0 * 5.0,
        // `weekly` and unknown legacy values retain the historical default.
        "monthly" => 24.0 * 30.0,
        _ => 24.0 * 7.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_new_intervals() {
        assert_eq!(blocklist_sync_interval_hours("1hour"), Some(1.0));
        assert_eq!(blocklist_sync_interval_hours("3hours"), Some(3.0));
        assert_eq!(blocklist_sync_interval_hours("6hours"), Some(6.0));
        assert_eq!(blocklist_sync_interval_hours("12hours"), Some(12.0));
        assert_eq!(blocklist_sync_interval_hours("24hours"), Some(24.0));
        assert_eq!(blocklist_sync_interval_hours("48hours"), Some(48.0));
        assert_eq!(blocklist_sync_interval_hours("5days"), Some(120.0));
    }

    #[test]
    fn manual_disables_auto_sync() {
        assert_eq!(blocklist_sync_interval_hours("manual"), None);
    }

    #[test]
    fn legacy_values_still_work() {
        assert_eq!(blocklist_sync_interval_hours("daily"), Some(24.0));
        assert_eq!(blocklist_sync_interval_hours("weekly"), Some(168.0));
        assert_eq!(blocklist_sync_interval_hours("monthly"), Some(720.0));
    }
}

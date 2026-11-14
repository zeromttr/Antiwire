//! Country totals across all retained connection history.

use crate::{CountryStatistics, Result, Store};

impl Store {
    /// Counts each saved connection once, including countries absent from recent pages.
    pub fn query_country_statistics(&self) -> Result<CountryStatistics> {
        // One grouped query gives country and unknown totals from the same snapshot.
        let rows = self.db.query_map(
            "SELECT CASE
                WHEN UPPER(TRIM(country_code)) IN ('', '-', '—', 'OTHER') THEN ''
                ELSE UPPER(TRIM(country_code))
             END AS code, COUNT(*)
             FROM connection_logs GROUP BY code",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let mut statistics = CountryStatistics::default();
        for (code, count) in rows {
            let count = u64::try_from(count).unwrap_or(u64::MAX);
            statistics.total_count += count;
            if code.is_empty() {
                statistics.unknown_count += count;
            } else {
                statistics.country_counts.insert(code, count);
            }
        }
        Ok(statistics)
    }
}

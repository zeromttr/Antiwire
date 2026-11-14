//! The system DNS redirect record: what restores the host's DNS while it
//! points at Antiwire's resolver. Only `antiwire-dns-redirect` writes it.

use time::OffsetDateTime;

use crate::error::Result;
use crate::models::format_timestamp;

impl crate::store::Store {
    /// The snapshot that restores the redirect in place, or `None` when no
    /// redirect is recorded.
    pub fn get_dns_redirect(&self) -> Result<Option<String>> {
        self.db.query_optional(
            "SELECT snapshot FROM dns_redirect WHERE id = 1",
            [],
            |row| row.get(0),
        )
    }

    /// Records a redirect in place that `snapshot` restores, replacing any
    /// earlier record.
    pub fn set_dns_redirect(&self, snapshot: &str) -> Result<()> {
        self.db.execute(
            "INSERT INTO dns_redirect (id, snapshot, recorded_at) VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE
             SET snapshot = excluded.snapshot, recorded_at = excluded.recorded_at",
            rusqlite::params![snapshot, format_timestamp(OffsetDateTime::now_utc())],
        )?;
        Ok(())
    }

    /// Clears the record, once the redirect it describes is restored.
    pub fn clear_dns_redirect(&self) -> Result<()> {
        self.db
            .execute("DELETE FROM dns_redirect WHERE id = 1", [])?;
        Ok(())
    }
}

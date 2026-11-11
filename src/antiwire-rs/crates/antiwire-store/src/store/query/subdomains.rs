//! Names under a registered domain that this machine has already seen.

use time::OffsetDateTime;

use crate::error::Result;
use crate::models::parse_timestamp;
use crate::store::Store;
use crate::INFERRED_SUFFIX;

/// One hostname under a domain, from local connection and DNS history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenSubdomain {
    /// Lowercase hostname, without the inferred-domain marker.
    pub name: String,
    /// Connection log rows naming this host.
    pub connections: u64,
    /// Of those, rows that were blocked.
    pub blocked: u64,
    pub first_seen: Option<OffsetDateTime>,
    pub last_seen: Option<OffsetDateTime>,
}

impl Store {
    /// Hostnames equal to or under `domain`, busiest first, at most `limit`.
    ///
    /// Reads connection logs (the inferred-domain marker is dropped, so an
    /// inferred row counts toward its name) and the names the DNS listener
    /// has seen, which also covers lookups that never led to a connection.
    pub fn seen_subdomains(&self, domain: &str, limit: usize) -> Result<Vec<SeenSubdomain>> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return Ok(Vec::new());
        }
        let escaped = domain
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let under = format!("%.{escaped}");
        let inferred = INFERRED_SUFFIX;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let sql = "
            WITH names AS (
                SELECT LOWER(REPLACE(dst_domain, ?3, '')) AS name,
                       1 AS connections,
                       CASE WHEN LOWER(action_taken) IN ('blocked', 'block') THEN 1 ELSE 0 END
                           AS blocked,
                       timestamp AS first_seen,
                       last_seen
                FROM connection_logs
                WHERE dst_domain != ''
                  AND (LOWER(REPLACE(dst_domain, ?3, '')) = ?1
                       OR LOWER(REPLACE(dst_domain, ?3, '')) LIKE ?2 ESCAPE '\\')
                UNION ALL
                SELECT LOWER(domain), 0, 0, first_seen, first_seen
                FROM seen_domains
                WHERE LOWER(domain) = ?1 OR LOWER(domain) LIKE ?2 ESCAPE '\\'
            )
            SELECT name, SUM(connections), SUM(blocked), MIN(first_seen), MAX(last_seen)
            FROM names
            GROUP BY name
            ORDER BY SUM(connections) DESC, name
            LIMIT ?4";
        self.db.query_map(
            sql,
            rusqlite::params![domain, under, inferred, limit],
            |row| {
                let first: Option<String> = row.get(3)?;
                let last: Option<String> = row.get(4)?;
                Ok(SeenSubdomain {
                    name: row.get(0)?,
                    connections: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    blocked: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    first_seen: first.and_then(|text| parse_timestamp(&text).ok()),
                    last_seen: last.and_then(|text| parse_timestamp(&text).ok()),
                })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewConnectionLog;
    use time::macros::datetime;

    fn log(domain: &str, action: &str, at: OffsetDateTime) -> NewConnectionLog {
        NewConnectionLog {
            timestamp: at,
            app_id: 0,
            app_path: String::new(),
            protocol: "TCP".to_owned(),
            src_ip: "192.0.2.10".to_owned(),
            src_port: 50000,
            dst_ip: "198.51.100.7".to_owned(),
            dst_port: 443,
            dst_domain: domain.to_owned(),
            bytes_sent: 0,
            bytes_received: 0,
            action_taken: action.to_owned(),
            last_seen: at,
            country_code: String::new(),
            isp: String::new(),
            blocklist_names: String::new(),
            conn_id: 0,
            conn_pid: 0,
            is_close: false,
            replace_domain: false,
        }
    }

    #[test]
    fn collects_names_under_a_domain_from_logs_and_dns_sightings() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("subdomains.sqlite")).unwrap();
        let early = datetime!(2026-09-01 10:00 UTC);
        let late = datetime!(2026-09-20 10:00 UTC);
        store
            .insert_connection_logs(&[
                log("api.example.com", "ALLOWED", early),
                log("api.example.com", "ALLOWED", late),
                log("cdn.example.com (inferred)", "BLOCKED", late),
                log("example.com", "ALLOWED", early),
                log("notexample.com", "ALLOWED", early),
                log("api.example.org", "ALLOWED", early),
            ])
            .unwrap();
        store
            .record_domain_sighting("mail.example.com", late)
            .unwrap();
        store
            .record_domain_sighting("api.example.com", early)
            .unwrap();

        let seen = store.seen_subdomains("Example.com.", 50).unwrap();
        let names: Vec<&str> = seen.iter().map(|item| item.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "api.example.com",
                "cdn.example.com",
                "example.com",
                "mail.example.com"
            ]
        );
        let api = &seen[0];
        assert_eq!(api.connections, 2);
        assert_eq!(api.blocked, 0);
        assert_eq!(api.first_seen, Some(early));
        assert_eq!(api.last_seen, Some(late));
        assert_eq!(
            seen[1].blocked, 1,
            "the inferred row counts toward its name"
        );
        assert_eq!(seen[3].connections, 0, "a DNS-only name has no connections");
    }

    #[test]
    fn like_wildcards_in_the_domain_match_literally() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("wildcards.sqlite")).unwrap();
        let at = datetime!(2026-09-01 10:00 UTC);
        store
            .insert_connection_logs(&[log("a.exampleXcom", "ALLOWED", at)])
            .unwrap();
        assert!(store.seen_subdomains("example_com", 10).unwrap().is_empty());
        assert!(store.seen_subdomains("", 10).unwrap().is_empty());
    }
}

use anyhow::{Context, Result};
use chrono::Utc;
use mc_core::id::{EventId, MissionId};
use mc_core::trace::{TraceEvent, TraceEventType};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Append-only event log with cryptographic chaining for tamper evidence.
///
/// Each event's `prev_hash` is the SHA-256 hash of the previous event's
/// `(id, sequence, prev_hash, payload)`. The first event uses `"genesis"`.
pub struct EventLog {
    conn: Connection,
}

impl EventLog {
    /// Open (or create) an event log backed by SQLite.
    ///
    /// Use `":memory:"` for an in-memory database (useful for tests).
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open SQLite database")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                mission_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                parent_event TEXT,
                payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL
            );",
        )
        .context("failed to create events table")?;
        Ok(Self { conn })
    }

    /// Append a new event to the log.
    ///
    /// Assigns the next sequence number and computes the cryptographic chain hash.
    pub fn append(
        &self,
        mission_id: MissionId,
        event_type: TraceEventType,
        parent_event: Option<EventId>,
        payload: serde_json::Value,
    ) -> Result<TraceEvent> {
        let prev = self.last_event()?;

        let sequence = prev.as_ref().map_or(0, |e| e.sequence + 1);

        let prev_hash = match &prev {
            None => "genesis".to_string(),
            Some(e) => compute_hash(&e.id.to_string(), e.sequence, &e.prev_hash, &e.payload),
        };

        let id = EventId::new();
        let timestamp = Utc::now();
        let payload_str =
            serde_json::to_string(&payload).context("failed to serialize payload")?;
        let event_type_str =
            serde_json::to_string(&event_type).context("failed to serialize event_type")?;
        let parent_str = parent_event.map(|p| p.to_string());

        self.conn
            .execute(
                "INSERT INTO events (id, sequence, timestamp, mission_id, event_type, parent_event, payload, prev_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id.to_string(),
                    sequence,
                    timestamp.to_rfc3339(),
                    mission_id.to_string(),
                    event_type_str,
                    parent_str,
                    payload_str,
                    prev_hash,
                ],
            )
            .context("failed to insert event")?;

        Ok(TraceEvent {
            id,
            sequence,
            timestamp,
            mission_id,
            event_type,
            parent_event,
            payload,
            prev_hash,
        })
    }

    /// Retrieve all events for a given mission, ordered by sequence.
    pub fn get_events_for_mission(&self, mission_id: MissionId) -> Result<Vec<TraceEvent>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, sequence, timestamp, mission_id, event_type, parent_event, payload, prev_hash
                 FROM events WHERE mission_id = ?1 ORDER BY sequence ASC",
            )
            .context("failed to prepare query")?;

        let rows = stmt
            .query_map(params![mission_id.to_string()], |row| {
                Ok(RawEventRow {
                    id: row.get(0)?,
                    sequence: row.get(1)?,
                    timestamp: row.get(2)?,
                    mission_id: row.get(3)?,
                    event_type: row.get(4)?,
                    parent_event: row.get(5)?,
                    payload: row.get(6)?,
                    prev_hash: row.get(7)?,
                })
            })
            .context("failed to execute query")?;

        rows.map(|r| {
            let r = r.context("failed to read row")?;
            raw_to_trace_event(r)
        })
        .collect()
    }

    /// Retrieve the most recent `limit` events, ordered by sequence descending.
    pub fn get_recent(&self, limit: u32) -> Result<Vec<TraceEvent>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, sequence, timestamp, mission_id, event_type, parent_event, payload, prev_hash
                 FROM events ORDER BY sequence DESC LIMIT ?1",
            )
            .context("failed to prepare query")?;

        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(RawEventRow {
                    id: row.get(0)?,
                    sequence: row.get(1)?,
                    timestamp: row.get(2)?,
                    mission_id: row.get(3)?,
                    event_type: row.get(4)?,
                    parent_event: row.get(5)?,
                    payload: row.get(6)?,
                    prev_hash: row.get(7)?,
                })
            })
            .context("failed to execute query")?;

        rows.map(|r| {
            let r = r.context("failed to read row")?;
            raw_to_trace_event(r)
        })
        .collect()
    }

    /// Walk all events in sequence order and verify that each `prev_hash`
    /// matches the hash computed from the preceding event.
    ///
    /// Returns `Ok(true)` if the chain is intact, `Ok(false)` if any hash
    /// mismatch is detected.
    pub fn verify_chain_integrity(&self) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, sequence, timestamp, mission_id, event_type, parent_event, payload, prev_hash
                 FROM events ORDER BY sequence ASC",
            )
            .context("failed to prepare query")?;

        let rows: Vec<RawEventRow> = stmt
            .query_map([], |row| {
                Ok(RawEventRow {
                    id: row.get(0)?,
                    sequence: row.get(1)?,
                    timestamp: row.get(2)?,
                    mission_id: row.get(3)?,
                    event_type: row.get(4)?,
                    parent_event: row.get(5)?,
                    payload: row.get(6)?,
                    prev_hash: row.get(7)?,
                })
            })
            .context("failed to execute query")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to collect rows")?;

        let mut prev: Option<&RawEventRow> = None;
        for row in &rows {
            let expected = match prev {
                None => "genesis".to_string(),
                Some(p) => compute_hash(
                    &p.id,
                    p.sequence as u64,
                    &p.prev_hash,
                    &serde_json::from_str::<serde_json::Value>(&p.payload)
                        .context("failed to parse payload for verification")?,
                ),
            };
            if row.prev_hash != expected {
                tracing::warn!(
                    sequence = row.sequence,
                    expected = %expected,
                    actual = %row.prev_hash,
                    "chain integrity violation"
                );
                return Ok(false);
            }
            prev = Some(row);
        }

        Ok(true)
    }

    /// Returns the last event in the log (by highest sequence number).
    fn last_event(&self) -> Result<Option<TraceEvent>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, sequence, timestamp, mission_id, event_type, parent_event, payload, prev_hash
                 FROM events ORDER BY sequence DESC LIMIT 1",
            )
            .context("failed to prepare query")?;

        let mut rows = stmt
            .query_map([], |row| {
                Ok(RawEventRow {
                    id: row.get(0)?,
                    sequence: row.get(1)?,
                    timestamp: row.get(2)?,
                    mission_id: row.get(3)?,
                    event_type: row.get(4)?,
                    parent_event: row.get(5)?,
                    payload: row.get(6)?,
                    prev_hash: row.get(7)?,
                })
            })
            .context("failed to query last event")?;

        match rows.next() {
            Some(r) => {
                let r = r.context("failed to read row")?;
                Ok(Some(raw_to_trace_event(r)?))
            }
            None => Ok(None),
        }
    }
}

/// Compute SHA-256 hash from the concatenation of (id, sequence, prev_hash, payload).
fn compute_hash(id: &str, sequence: u64, prev_hash: &str, payload: &serde_json::Value) -> String {
    let payload_str = serde_json::to_string(payload).expect("payload must be serializable");
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(sequence.to_string().as_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(payload_str.as_bytes());
    hex::encode(hasher.finalize())
}

/// Raw row data from SQLite before parsing into domain types.
struct RawEventRow {
    id: String,
    sequence: i64,
    timestamp: String,
    mission_id: String,
    event_type: String,
    parent_event: Option<String>,
    payload: String,
    prev_hash: String,
}

/// Convert a raw SQLite row into a `TraceEvent`.
fn raw_to_trace_event(row: RawEventRow) -> Result<TraceEvent> {
    let id = EventId::from_uuid(
        Uuid::parse_str(&row.id).context("failed to parse event id as UUID")?,
    );
    let mission_id = MissionId::from_uuid(
        Uuid::parse_str(&row.mission_id).context("failed to parse mission_id as UUID")?,
    );
    let parent_event = row
        .parent_event
        .map(|p| {
            Uuid::parse_str(&p)
                .map(EventId::from_uuid)
                .context("failed to parse parent_event as UUID")
        })
        .transpose()?;
    let timestamp = chrono::DateTime::parse_from_rfc3339(&row.timestamp)
        .context("failed to parse timestamp")?
        .with_timezone(&chrono::Utc);
    let event_type: TraceEventType =
        serde_json::from_str(&row.event_type).context("failed to parse event_type")?;
    let payload: serde_json::Value =
        serde_json::from_str(&row.payload).context("failed to parse payload")?;

    Ok(TraceEvent {
        id,
        sequence: row.sequence as u64,
        timestamp,
        mission_id,
        event_type,
        parent_event,
        payload,
        prev_hash: row.prev_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_log() -> EventLog {
        EventLog::new(":memory:").expect("in-memory DB should open")
    }

    #[test]
    fn append_and_retrieve() {
        let log = test_log();
        let mid = MissionId::new();

        let event = log
            .append(
                mid,
                TraceEventType::MissionCreated,
                None,
                json!({"goal": "test"}),
            )
            .unwrap();

        assert_eq!(event.sequence, 0);
        assert_eq!(event.prev_hash, "genesis");
        assert_eq!(event.mission_id, mid);

        let events = log.get_events_for_mission(mid).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
        assert_eq!(events[0].payload, json!({"goal": "test"}));
    }

    #[test]
    fn chain_integrity() {
        let log = test_log();
        let mid = MissionId::new();

        let e0 = log
            .append(mid, TraceEventType::MissionCreated, None, json!({"seq": 0}))
            .unwrap();
        let e1 = log
            .append(
                mid,
                TraceEventType::OperationRequested,
                Some(e0.id),
                json!({"seq": 1}),
            )
            .unwrap();
        let _e2 = log
            .append(
                mid,
                TraceEventType::OperationAllowed,
                Some(e1.id),
                json!({"seq": 2}),
            )
            .unwrap();

        assert!(log.verify_chain_integrity().unwrap());
    }

    #[test]
    fn chain_integrity_detects_tampering() {
        let log = test_log();
        let mid = MissionId::new();

        log.append(mid, TraceEventType::MissionCreated, None, json!({"seq": 0}))
            .unwrap();
        log.append(
            mid,
            TraceEventType::OperationRequested,
            None,
            json!({"seq": 1}),
        )
        .unwrap();

        // Tamper with the first event's payload
        log.conn
            .execute(
                "UPDATE events SET payload = '{\"seq\":999}' WHERE sequence = 0",
                [],
            )
            .unwrap();

        assert!(!log.verify_chain_integrity().unwrap());
    }

    #[test]
    fn multiple_missions() {
        let log = test_log();
        let m1 = MissionId::new();
        let m2 = MissionId::new();

        log.append(m1, TraceEventType::MissionCreated, None, json!({"m": 1}))
            .unwrap();
        log.append(m2, TraceEventType::MissionCreated, None, json!({"m": 2}))
            .unwrap();
        log.append(
            m1,
            TraceEventType::OperationRequested,
            None,
            json!({"m": 1, "op": true}),
        )
        .unwrap();

        let m1_events = log.get_events_for_mission(m1).unwrap();
        let m2_events = log.get_events_for_mission(m2).unwrap();

        assert_eq!(m1_events.len(), 2);
        assert_eq!(m2_events.len(), 1);

        // All m1 events belong to m1
        for e in &m1_events {
            assert_eq!(e.mission_id, m1);
        }
        for e in &m2_events {
            assert_eq!(e.mission_id, m2);
        }
    }

    #[test]
    fn sequence_monotonic() {
        let log = test_log();
        let mid = MissionId::new();

        for i in 0..5 {
            log.append(
                mid,
                TraceEventType::MissionCreated,
                None,
                json!({"i": i}),
            )
            .unwrap();
        }

        let events = log.get_events_for_mission(mid).unwrap();
        assert_eq!(events.len(), 5);
        for (i, e) in events.iter().enumerate() {
            assert_eq!(e.sequence, i as u64, "sequence should be monotonic");
        }
    }

    #[test]
    fn get_recent_returns_most_recent_first() {
        let log = test_log();
        let mid = MissionId::new();

        for i in 0..5 {
            log.append(
                mid,
                TraceEventType::MissionCreated,
                None,
                json!({"i": i}),
            )
            .unwrap();
        }

        let recent = log.get_recent(3).unwrap();
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].sequence, 4);
        assert_eq!(recent[1].sequence, 3);
        assert_eq!(recent[2].sequence, 2);
    }

    #[test]
    fn genesis_hash_for_first_event() {
        let log = test_log();
        let event = log
            .append(
                MissionId::new(),
                TraceEventType::MissionCreated,
                None,
                json!({}),
            )
            .unwrap();
        assert_eq!(event.prev_hash, "genesis");
    }

    #[test]
    fn second_event_hash_is_sha256() {
        let log = test_log();
        let mid = MissionId::new();

        let e0 = log
            .append(mid, TraceEventType::MissionCreated, None, json!({"a": 1}))
            .unwrap();
        let e1 = log
            .append(
                mid,
                TraceEventType::OperationRequested,
                None,
                json!({"b": 2}),
            )
            .unwrap();

        // Manually compute expected hash
        let expected = compute_hash(
            &e0.id.to_string(),
            e0.sequence,
            &e0.prev_hash,
            &e0.payload,
        );
        assert_eq!(e1.prev_hash, expected);
        assert_ne!(e1.prev_hash, "genesis");
    }
}

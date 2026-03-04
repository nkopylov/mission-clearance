use anyhow::Result;
use mc_core::id::MissionId;
use mc_core::trace::TraceEvent;

use crate::event_log::EventLog;

/// Query engine for trace events.
///
/// Provides a higher-level interface over the raw `EventLog`, suitable for
/// dashboards, CLI tools, and API endpoints.
pub struct TraceQueryEngine<'a> {
    event_log: &'a EventLog,
}

impl<'a> TraceQueryEngine<'a> {
    /// Create a new query engine backed by the given event log.
    pub fn new(event_log: &'a EventLog) -> Self {
        Self { event_log }
    }

    /// Get all events for a specific mission, ordered by sequence.
    pub fn mission_events(&self, mission_id: MissionId) -> Result<Vec<TraceEvent>> {
        self.event_log.get_events_for_mission(mission_id)
    }

    /// Get the most recent events across all missions.
    pub fn recent_events(&self, limit: u32) -> Result<Vec<TraceEvent>> {
        self.event_log.get_recent(limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::trace::TraceEventType;
    use serde_json::json;

    #[test]
    fn query_mission_events() {
        let log = EventLog::new(":memory:").unwrap();
        let mid = MissionId::new();

        log.append(mid, TraceEventType::MissionCreated, None, json!({"goal": "test"}))
            .unwrap();
        log.append(mid, TraceEventType::OperationRequested, None, json!({"op": 1}))
            .unwrap();

        let engine = TraceQueryEngine::new(&log);
        let events = engine.mission_events(mid).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 0);
        assert_eq!(events[1].sequence, 1);
    }

    #[test]
    fn query_recent_events() {
        let log = EventLog::new(":memory:").unwrap();
        let m1 = MissionId::new();
        let m2 = MissionId::new();

        log.append(m1, TraceEventType::MissionCreated, None, json!({"m": 1}))
            .unwrap();
        log.append(m2, TraceEventType::MissionCreated, None, json!({"m": 2}))
            .unwrap();
        log.append(m1, TraceEventType::MissionCompleted, None, json!({"m": 1}))
            .unwrap();

        let engine = TraceQueryEngine::new(&log);
        let recent = engine.recent_events(2).unwrap();
        assert_eq!(recent.len(), 2);
        // Most recent first
        assert_eq!(recent[0].sequence, 2);
        assert_eq!(recent[1].sequence, 1);
    }

    #[test]
    fn query_empty_log() {
        let log = EventLog::new(":memory:").unwrap();
        let engine = TraceQueryEngine::new(&log);

        let events = engine.mission_events(MissionId::new()).unwrap();
        assert!(events.is_empty());

        let recent = engine.recent_events(10).unwrap();
        assert!(recent.is_empty());
    }
}

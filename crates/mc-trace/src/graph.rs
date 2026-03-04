use anyhow::{Context, Result};
use mc_core::trace::{GraphEdge, GraphFormat, GraphNode};
use rusqlite::{params, Connection};

/// A materialized graph of mission relationships backed by SQLite.
///
/// Nodes represent missions, operations, and decisions. Edges represent
/// causal and structural relationships between them.
pub struct MissionGraph {
    conn: Connection,
}

impl MissionGraph {
    /// Open (or create) a mission graph backed by SQLite.
    ///
    /// Use `":memory:"` for an in-memory database (useful for tests).
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open SQLite database")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_id TEXT NOT NULL,
                to_id TEXT NOT NULL,
                edge_type TEXT NOT NULL
            );",
        )
        .context("failed to create graph tables")?;
        Ok(Self { conn })
    }

    /// Add a node to the graph.
    ///
    /// The `id` is the string key for lookup. If a node with the same id
    /// already exists it is replaced.
    pub fn add_node(&self, id: &str, node: &GraphNode) -> Result<()> {
        let node_type = match node {
            GraphNode::Mission { .. } => "Mission",
            GraphNode::Operation { .. } => "Operation",
            GraphNode::Decision { .. } => "Decision",
        };
        let data = serde_json::to_string(node).context("failed to serialize node")?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO nodes (id, node_type, data) VALUES (?1, ?2, ?3)",
                params![id, node_type, data],
            )
            .context("failed to insert node")?;
        Ok(())
    }

    /// Add an edge to the graph.
    pub fn add_edge(&self, edge: &GraphEdge) -> Result<()> {
        let edge_type =
            serde_json::to_string(&edge.edge_type).context("failed to serialize edge_type")?;
        self.conn
            .execute(
                "INSERT INTO edges (from_id, to_id, edge_type) VALUES (?1, ?2, ?3)",
                params![edge.from.to_string(), edge.to.to_string(), edge_type],
            )
            .context("failed to insert edge")?;
        Ok(())
    }

    /// Get the children of a node: all nodes reachable via outgoing edges.
    pub fn get_children(&self, node_id: &str) -> Result<Vec<GraphNode>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT n.data FROM nodes n
                 INNER JOIN edges e ON n.id = e.to_id
                 WHERE e.from_id = ?1",
            )
            .context("failed to prepare children query")?;

        let rows = stmt
            .query_map(params![node_id], |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })
            .context("failed to query children")?;

        rows.map(|r| {
            let data = r.context("failed to read row")?;
            serde_json::from_str::<GraphNode>(&data).context("failed to deserialize node")
        })
        .collect()
    }

    /// Export the entire graph in the specified format.
    pub fn export(&self, format: GraphFormat) -> Result<String> {
        match format {
            GraphFormat::Dot => self.export_dot(),
            GraphFormat::Json => self.export_json(),
        }
    }

    fn export_dot(&self) -> Result<String> {
        let mut dot = String::from("digraph mission_graph {\n");

        // Nodes
        let mut stmt = self
            .conn
            .prepare("SELECT id, node_type, data FROM nodes")
            .context("failed to prepare nodes query")?;
        let nodes: Vec<(String, String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .context("failed to query nodes")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to collect nodes")?;

        for (id, node_type, _data) in &nodes {
            let label = format!("{node_type}\\n{}", truncate_id(id));
            dot.push_str(&format!("  \"{id}\" [label=\"{label}\"];\n"));
        }

        // Edges
        let mut stmt = self
            .conn
            .prepare("SELECT from_id, to_id, edge_type FROM edges")
            .context("failed to prepare edges query")?;
        let edges: Vec<(String, String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .context("failed to query edges")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to collect edges")?;

        for (from, to, edge_type) in &edges {
            // Strip JSON quotes from edge_type for cleaner labels
            let label = edge_type.trim_matches('"');
            dot.push_str(&format!("  \"{from}\" -> \"{to}\" [label=\"{label}\"];\n"));
        }

        dot.push_str("}\n");
        Ok(dot)
    }

    fn export_json(&self) -> Result<String> {
        // Collect nodes
        let mut stmt = self
            .conn
            .prepare("SELECT data FROM nodes")
            .context("failed to prepare nodes query")?;
        let nodes: Vec<serde_json::Value> = stmt
            .query_map([], |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })
            .context("failed to query nodes")?
            .map(|r| {
                let data = r.context("failed to read row")?;
                serde_json::from_str(&data).context("failed to parse node JSON")
            })
            .collect::<Result<Vec<_>>>()?;

        // Collect edges
        let mut stmt = self
            .conn
            .prepare("SELECT from_id, to_id, edge_type FROM edges")
            .context("failed to prepare edges query")?;
        let edges: Vec<serde_json::Value> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .context("failed to query edges")?
            .map(|r| {
                let (from, to, edge_type) = r.context("failed to read row")?;
                let edge_type_val: serde_json::Value =
                    serde_json::from_str(&edge_type).context("failed to parse edge_type")?;
                Ok(serde_json::json!({
                    "from": from,
                    "to": to,
                    "edge_type": edge_type_val,
                }))
            })
            .collect::<Result<Vec<_>>>()?;

        let graph = serde_json::json!({
            "nodes": nodes,
            "edges": edges,
        });

        serde_json::to_string_pretty(&graph).context("failed to serialize graph to JSON")
    }
}

/// Truncate a UUID string for display in DOT labels.
fn truncate_id(id: &str) -> &str {
    if id.len() > 8 {
        &id[..8]
    } else {
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::id::{EventId, MissionId, RequestId};
    use mc_core::trace::EdgeType;

    fn test_graph() -> MissionGraph {
        MissionGraph::new(":memory:").expect("in-memory DB should open")
    }

    #[test]
    fn add_and_query_nodes() {
        let graph = test_graph();
        let mid = MissionId::new();
        let eid = EventId::new();

        let mission_node = GraphNode::Mission {
            id: mid,
            goal: "deploy service".to_string(),
        };
        let decision_node = GraphNode::Decision {
            id: eid,
            kind: "Allow".to_string(),
        };

        graph.add_node(&mid.to_string(), &mission_node).unwrap();
        graph.add_node(&eid.to_string(), &decision_node).unwrap();

        // Add edge from mission to decision
        let edge = GraphEdge {
            from: EventId::from_uuid(*mid.as_uuid()),
            to: eid,
            edge_type: EdgeType::Caused,
        };
        graph.add_edge(&edge).unwrap();

        let children = graph.get_children(&mid.to_string()).unwrap();
        assert_eq!(children.len(), 1);

        // Verify the child is the decision node
        match &children[0] {
            GraphNode::Decision { kind, .. } => assert_eq!(kind, "Allow"),
            other => panic!("expected Decision node, got {other:?}"),
        }
    }

    #[test]
    fn get_children_empty() {
        let graph = test_graph();
        let mid = MissionId::new();
        let node = GraphNode::Mission {
            id: mid,
            goal: "test".to_string(),
        };
        graph.add_node(&mid.to_string(), &node).unwrap();

        let children = graph.get_children(&mid.to_string()).unwrap();
        assert!(children.is_empty());
    }

    #[test]
    fn export_dot() {
        let graph = test_graph();
        let mid = MissionId::new();
        let eid = EventId::new();

        let mission_node = GraphNode::Mission {
            id: mid,
            goal: "test".to_string(),
        };
        let decision_node = GraphNode::Decision {
            id: eid,
            kind: "Deny".to_string(),
        };

        graph.add_node(&mid.to_string(), &mission_node).unwrap();
        graph.add_node(&eid.to_string(), &decision_node).unwrap();

        let edge = GraphEdge {
            from: EventId::from_uuid(*mid.as_uuid()),
            to: eid,
            edge_type: EdgeType::Spawned,
        };
        graph.add_edge(&edge).unwrap();

        let dot = graph.export(GraphFormat::Dot).unwrap();
        assert!(dot.contains("digraph"), "DOT output must contain 'digraph'");
        assert!(dot.contains("->"), "DOT output must contain edges");
        assert!(
            dot.contains("Mission"),
            "DOT output must contain node types"
        );
    }

    #[test]
    fn export_json() {
        let graph = test_graph();
        let mid = MissionId::new();
        let rid = RequestId::new();

        let mission_node = GraphNode::Mission {
            id: mid,
            goal: "analyze data".to_string(),
        };
        let op_node = GraphNode::Operation {
            id: rid,
            resource: "https://api.example.com/data".to_string(),
        };

        graph.add_node(&mid.to_string(), &mission_node).unwrap();
        graph.add_node(&rid.to_string(), &op_node).unwrap();

        let edge = GraphEdge {
            from: EventId::from_uuid(*mid.as_uuid()),
            to: EventId::from_uuid(*rid.as_uuid()),
            edge_type: EdgeType::Performed,
        };
        graph.add_edge(&edge).unwrap();

        let json_str = graph.export(GraphFormat::Json).unwrap();

        // Must be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .expect("export_json must produce valid JSON");

        assert!(parsed["nodes"].is_array());
        assert!(parsed["edges"].is_array());
        assert_eq!(parsed["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["edges"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn node_replacement() {
        let graph = test_graph();
        let mid = MissionId::new();

        let node_v1 = GraphNode::Mission {
            id: mid,
            goal: "version 1".to_string(),
        };
        let node_v2 = GraphNode::Mission {
            id: mid,
            goal: "version 2".to_string(),
        };

        graph.add_node(&mid.to_string(), &node_v1).unwrap();
        graph.add_node(&mid.to_string(), &node_v2).unwrap();

        // Should have only one node (replaced)
        let json_str = graph.export(GraphFormat::Json).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["nodes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn multiple_children() {
        let graph = test_graph();
        let parent_id = MissionId::new();
        let child1_id = EventId::new();
        let child2_id = EventId::new();

        let parent = GraphNode::Mission {
            id: parent_id,
            goal: "parent".to_string(),
        };
        let child1 = GraphNode::Decision {
            id: child1_id,
            kind: "Allow".to_string(),
        };
        let child2 = GraphNode::Decision {
            id: child2_id,
            kind: "Deny".to_string(),
        };

        graph.add_node(&parent_id.to_string(), &parent).unwrap();
        graph.add_node(&child1_id.to_string(), &child1).unwrap();
        graph.add_node(&child2_id.to_string(), &child2).unwrap();

        graph
            .add_edge(&GraphEdge {
                from: EventId::from_uuid(*parent_id.as_uuid()),
                to: child1_id,
                edge_type: EdgeType::Caused,
            })
            .unwrap();
        graph
            .add_edge(&GraphEdge {
                from: EventId::from_uuid(*parent_id.as_uuid()),
                to: child2_id,
                edge_type: EdgeType::Caused,
            })
            .unwrap();

        let children = graph.get_children(&parent_id.to_string()).unwrap();
        assert_eq!(children.len(), 2);
    }
}

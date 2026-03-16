use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use mc_core::delegation::{BoundedAuthorization, DelegationEdge};
use mc_core::id::{
    DelegationEdgeId, GrantId, OrgPositionId, PrincipalId, RoleAssignmentId, RoleId, TeamId,
};
use mc_core::org::{OrgPosition, Team};
use mc_core::principal::{Principal, PrincipalStatus};
use mc_core::role::{Role, RoleAssignmentScope};
use rusqlite::{params, Connection};
use tracing::{debug, info};
use uuid::Uuid;

/// SQLite-backed permission graph store.
///
/// Manages principals, roles, delegation edges, org positions, teams, and
/// bounded authorizations. Complex fields (Vec, HashMap, etc.) are serialized
/// as JSON text columns.
pub struct PermissionGraphStore {
    conn: Connection,
}

impl PermissionGraphStore {
    /// Open (or create) a permission graph database at `path`.
    ///
    /// Use `":memory:"` for an in-memory database (useful for tests).
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open permission graph database")?;
        Self::init_schema(&conn)?;
        info!("permission graph store opened at {path}");
        Ok(Self { conn })
    }

    /// Initialize the database schema (idempotent).
    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS principals (
                id            TEXT PRIMARY KEY,
                kind          TEXT NOT NULL,
                status        TEXT NOT NULL,
                trust_level   TEXT NOT NULL,
                display_name  TEXT NOT NULL,
                details       TEXT NOT NULL,
                org_position  TEXT,
                teams         TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS roles (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL UNIQUE,
                permissions     TEXT NOT NULL,
                includes        TEXT NOT NULL,
                min_org_level   TEXT,
                conflicts_with  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS role_assignments (
                id            TEXT PRIMARY KEY,
                principal_id  TEXT NOT NULL,
                role_id       TEXT NOT NULL,
                scope         TEXT NOT NULL,
                expires_at    TEXT,
                FOREIGN KEY (principal_id) REFERENCES principals(id),
                FOREIGN KEY (role_id) REFERENCES roles(id)
            );

            CREATE TABLE IF NOT EXISTS delegation_edges (
                id            TEXT PRIMARY KEY,
                from_id       TEXT NOT NULL,
                to_id         TEXT NOT NULL,
                constraints   TEXT NOT NULL,
                revoked       INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL,
                FOREIGN KEY (from_id) REFERENCES principals(id),
                FOREIGN KEY (to_id) REFERENCES principals(id)
            );

            CREATE TABLE IF NOT EXISTS org_positions (
                id          TEXT PRIMARY KEY,
                title       TEXT NOT NULL,
                level       TEXT NOT NULL,
                reports_to  TEXT,
                team        TEXT,
                holder      TEXT
            );

            CREATE TABLE IF NOT EXISTS teams (
                id      TEXT PRIMARY KEY,
                name    TEXT NOT NULL,
                parent  TEXT
            );

            CREATE TABLE IF NOT EXISTS team_members (
                team_id      TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                PRIMARY KEY (team_id, principal_id),
                FOREIGN KEY (team_id) REFERENCES teams(id),
                FOREIGN KEY (principal_id) REFERENCES principals(id)
            );

            CREATE TABLE IF NOT EXISTS bounded_authorizations (
                id          TEXT PRIMARY KEY,
                principal   TEXT NOT NULL,
                capability  TEXT NOT NULL,
                bound_type  TEXT NOT NULL,
                consumed    INTEGER NOT NULL DEFAULT 0,
                use_count   INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                FOREIGN KEY (principal) REFERENCES principals(id)
            );",
        )
        .context("failed to initialize permission graph schema")?;
        Ok(())
    }

    // ── Principals ──────────────────────────────────────────────────────

    /// Add a new principal to the store.
    pub fn add_principal(&self, principal: &Principal) -> Result<PrincipalId> {
        let kind_json = serde_json::to_string(&principal.kind)?;
        let status_json = serde_json::to_string(&principal.status)?;
        let trust_level_json = serde_json::to_string(&principal.trust_level)?;
        let details_json = serde_json::to_string(&principal.details)?;
        let org_position_str = principal.org_position.map(|id| id.to_string());
        let teams_json = serde_json::to_string(&principal.teams)?;

        self.conn
            .execute(
                "INSERT INTO principals (id, kind, status, trust_level, display_name, details, org_position, teams)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    principal.id.to_string(),
                    kind_json,
                    status_json,
                    trust_level_json,
                    principal.display_name,
                    details_json,
                    org_position_str,
                    teams_json,
                ],
            )
            .context("failed to insert principal")?;

        info!(principal_id = %principal.id, name = %principal.display_name, "added principal");
        Ok(principal.id)
    }

    /// Retrieve a principal by ID.
    pub fn get_principal(&self, id: &PrincipalId) -> Result<Option<Principal>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, status, trust_level, display_name, details, org_position, teams
             FROM principals WHERE id = ?1",
        )?;

        let result = stmt
            .query_row(params![id.to_string()], |row| {
                Ok(RawPrincipalRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    status: row.get(2)?,
                    trust_level: row.get(3)?,
                    display_name: row.get(4)?,
                    details: row.get(5)?,
                    org_position: row.get(6)?,
                    teams: row.get(7)?,
                })
            })
            .optional()
            .context("failed to query principal")?;

        match result {
            Some(row) => Ok(Some(raw_to_principal(row)?)),
            None => Ok(None),
        }
    }

    /// Update the status of a principal.
    pub fn update_principal_status(
        &self,
        id: &PrincipalId,
        status: PrincipalStatus,
    ) -> Result<()> {
        let status_json = serde_json::to_string(&status)?;
        let affected = self.conn.execute(
            "UPDATE principals SET status = ?1 WHERE id = ?2",
            params![status_json, id.to_string()],
        )?;

        if affected == 0 {
            bail!("principal {id} not found");
        }

        info!(principal_id = %id, ?status, "updated principal status");
        Ok(())
    }

    /// List all principals in the store.
    pub fn list_principals(&self) -> Result<Vec<Principal>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, status, trust_level, display_name, details, org_position, teams
             FROM principals",
        )?;

        let rows = stmt
            .query_map([], |row| {
                Ok(RawPrincipalRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    status: row.get(2)?,
                    trust_level: row.get(3)?,
                    display_name: row.get(4)?,
                    details: row.get(5)?,
                    org_position: row.get(6)?,
                    teams: row.get(7)?,
                })
            })
            .context("failed to query principals")?;

        rows.map(|r| {
            let r = r.context("failed to read principal row")?;
            raw_to_principal(r)
        })
        .collect()
    }

    // ── Roles ───────────────────────────────────────────────────────────

    /// Add a new role to the store.
    pub fn add_role(&self, role: &Role) -> Result<RoleId> {
        let permissions_json = serde_json::to_string(&role.permissions)?;
        let includes_json = serde_json::to_string(&role.includes)?;
        let min_org_level_json = role
            .min_org_level
            .as_ref()
            .map(|l| serde_json::to_string(l))
            .transpose()?;
        let conflicts_json = serde_json::to_string(&role.conflicts_with)?;

        self.conn
            .execute(
                "INSERT INTO roles (id, name, permissions, includes, min_org_level, conflicts_with)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    role.id.to_string(),
                    role.name,
                    permissions_json,
                    includes_json,
                    min_org_level_json,
                    conflicts_json,
                ],
            )
            .context("failed to insert role")?;

        info!(role_id = %role.id, name = %role.name, "added role");
        Ok(role.id)
    }

    /// Retrieve a role by ID.
    pub fn get_role(&self, id: &RoleId) -> Result<Option<Role>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, permissions, includes, min_org_level, conflicts_with
             FROM roles WHERE id = ?1",
        )?;

        let result = stmt
            .query_row(params![id.to_string()], |row| {
                Ok(RawRoleRow {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    permissions: row.get(2)?,
                    includes: row.get(3)?,
                    min_org_level: row.get(4)?,
                    conflicts_with: row.get(5)?,
                })
            })
            .optional()
            .context("failed to query role")?;

        match result {
            Some(row) => Ok(Some(raw_to_role(row)?)),
            None => Ok(None),
        }
    }

    /// Assign a role to a principal with a given scope and optional expiry.
    pub fn assign_role(
        &self,
        principal_id: &PrincipalId,
        role_id: &RoleId,
        scope: RoleAssignmentScope,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<RoleAssignmentId> {
        let id = RoleAssignmentId::new();
        let scope_json = serde_json::to_string(&scope)?;
        let expires_str = expires_at.map(|dt| dt.to_rfc3339());

        self.conn
            .execute(
                "INSERT INTO role_assignments (id, principal_id, role_id, scope, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id.to_string(),
                    principal_id.to_string(),
                    role_id.to_string(),
                    scope_json,
                    expires_str,
                ],
            )
            .context("failed to insert role assignment")?;

        debug!(
            assignment_id = %id,
            principal_id = %principal_id,
            role_id = %role_id,
            "assigned role to principal"
        );
        Ok(id)
    }

    /// Get all role assignments for a principal.
    pub fn get_principal_roles(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<(RoleAssignmentId, RoleId, RoleAssignmentScope)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, role_id, scope FROM role_assignments WHERE principal_id = ?1",
        )?;

        let rows = stmt
            .query_map(params![principal_id.to_string()], |row| {
                let id_str: String = row.get(0)?;
                let role_id_str: String = row.get(1)?;
                let scope_json: String = row.get(2)?;
                Ok((id_str, role_id_str, scope_json))
            })
            .context("failed to query role assignments")?;

        let mut assignments = Vec::new();
        for row in rows {
            let (id_str, role_id_str, scope_json) = row.context("failed to read assignment row")?;
            let assignment_id = RoleAssignmentId::from_uuid(
                Uuid::parse_str(&id_str).context("invalid assignment UUID")?,
            );
            let role_id =
                RoleId::from_uuid(Uuid::parse_str(&role_id_str).context("invalid role UUID")?);
            let scope: RoleAssignmentScope =
                serde_json::from_str(&scope_json).context("invalid role assignment scope")?;
            assignments.push((assignment_id, role_id, scope));
        }

        Ok(assignments)
    }

    // ── Delegation edges ────────────────────────────────────────────────

    /// Add a delegation edge to the store.
    pub fn add_delegation_edge(&self, edge: &DelegationEdge) -> Result<DelegationEdgeId> {
        let constraints_json = serde_json::to_string(&edge.constraints)?;

        self.conn
            .execute(
                "INSERT INTO delegation_edges (id, from_id, to_id, constraints, revoked, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    edge.id.to_string(),
                    edge.from.to_string(),
                    edge.to.to_string(),
                    constraints_json,
                    edge.revoked as i32,
                    edge.created_at.to_rfc3339(),
                ],
            )
            .context("failed to insert delegation edge")?;

        info!(
            edge_id = %edge.id,
            from = %edge.from,
            to = %edge.to,
            "added delegation edge"
        );
        Ok(edge.id)
    }

    /// Retrieve a delegation edge by ID.
    pub fn get_delegation_edge(&self, id: &DelegationEdgeId) -> Result<Option<DelegationEdge>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, from_id, to_id, constraints, revoked, created_at
             FROM delegation_edges WHERE id = ?1",
        )?;

        let result = stmt
            .query_row(params![id.to_string()], |row| {
                Ok(RawDelegationEdgeRow {
                    id: row.get(0)?,
                    from_id: row.get(1)?,
                    to_id: row.get(2)?,
                    constraints: row.get(3)?,
                    revoked: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .optional()
            .context("failed to query delegation edge")?;

        match result {
            Some(row) => Ok(Some(raw_to_delegation_edge(row)?)),
            None => Ok(None),
        }
    }

    /// Get all delegation edges from a given principal.
    pub fn get_delegations_from(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<DelegationEdge>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, from_id, to_id, constraints, revoked, created_at
             FROM delegation_edges WHERE from_id = ?1",
        )?;

        let rows = stmt
            .query_map(params![principal_id.to_string()], |row| {
                Ok(RawDelegationEdgeRow {
                    id: row.get(0)?,
                    from_id: row.get(1)?,
                    to_id: row.get(2)?,
                    constraints: row.get(3)?,
                    revoked: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .context("failed to query delegations from principal")?;

        rows.map(|r| {
            let r = r.context("failed to read delegation row")?;
            raw_to_delegation_edge(r)
        })
        .collect()
    }

    /// Get all delegation edges to a given principal.
    pub fn get_delegations_to(&self, principal_id: &PrincipalId) -> Result<Vec<DelegationEdge>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, from_id, to_id, constraints, revoked, created_at
             FROM delegation_edges WHERE to_id = ?1",
        )?;

        let rows = stmt
            .query_map(params![principal_id.to_string()], |row| {
                Ok(RawDelegationEdgeRow {
                    id: row.get(0)?,
                    from_id: row.get(1)?,
                    to_id: row.get(2)?,
                    constraints: row.get(3)?,
                    revoked: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .context("failed to query delegations to principal")?;

        rows.map(|r| {
            let r = r.context("failed to read delegation row")?;
            raw_to_delegation_edge(r)
        })
        .collect()
    }

    /// Revoke a delegation edge.
    pub fn revoke_delegation_edge(&self, id: &DelegationEdgeId) -> Result<()> {
        let affected = self.conn.execute(
            "UPDATE delegation_edges SET revoked = 1 WHERE id = ?1",
            params![id.to_string()],
        )?;

        if affected == 0 {
            bail!("delegation edge {id} not found");
        }

        info!(edge_id = %id, "revoked delegation edge");
        Ok(())
    }

    /// Atomically increment the operations_used counter inside a delegation
    /// edge's constraints. Returns the new count.
    pub fn increment_operations_used(&self, id: &DelegationEdgeId) -> Result<u64> {
        // Read current constraints
        let constraints_json: String = self
            .conn
            .query_row(
                "SELECT constraints FROM delegation_edges WHERE id = ?1",
                params![id.to_string()],
                |row| row.get(0),
            )
            .context("delegation edge not found")?;

        let mut constraints: mc_core::delegation::DelegationConstraints =
            serde_json::from_str(&constraints_json)
                .context("failed to parse delegation constraints")?;

        constraints.operations_used += 1;
        let new_count = constraints.operations_used;

        let updated_json = serde_json::to_string(&constraints)?;
        self.conn.execute(
            "UPDATE delegation_edges SET constraints = ?1 WHERE id = ?2",
            params![updated_json, id.to_string()],
        )?;

        debug!(edge_id = %id, operations_used = new_count, "incremented operations used");
        Ok(new_count)
    }

    // ── Org positions ───────────────────────────────────────────────────

    /// Add an org position to the store.
    pub fn add_org_position(&self, pos: &OrgPosition) -> Result<OrgPositionId> {
        let level_json = serde_json::to_string(&pos.level)?;
        let reports_to_str = pos.reports_to.map(|id| id.to_string());
        let team_str = pos.team.map(|id| id.to_string());
        let holder_str = pos.holder.map(|id| id.to_string());

        self.conn
            .execute(
                "INSERT INTO org_positions (id, title, level, reports_to, team, holder)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    pos.id.to_string(),
                    pos.title,
                    level_json,
                    reports_to_str,
                    team_str,
                    holder_str,
                ],
            )
            .context("failed to insert org position")?;

        debug!(position_id = %pos.id, title = %pos.title, "added org position");
        Ok(pos.id)
    }

    /// Retrieve an org position by ID.
    pub fn get_org_position(&self, id: &OrgPositionId) -> Result<Option<OrgPosition>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, level, reports_to, team, holder
             FROM org_positions WHERE id = ?1",
        )?;

        let result = stmt
            .query_row(params![id.to_string()], |row| {
                Ok(RawOrgPositionRow {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    level: row.get(2)?,
                    reports_to: row.get(3)?,
                    team: row.get(4)?,
                    holder: row.get(5)?,
                })
            })
            .optional()
            .context("failed to query org position")?;

        match result {
            Some(row) => Ok(Some(raw_to_org_position(row)?)),
            None => Ok(None),
        }
    }

    // ── Teams ───────────────────────────────────────────────────────────

    /// Add a team to the store.
    pub fn add_team(&self, team: &Team) -> Result<TeamId> {
        let parent_str = team.parent.map(|id| id.to_string());

        self.conn
            .execute(
                "INSERT INTO teams (id, name, parent) VALUES (?1, ?2, ?3)",
                params![team.id.to_string(), team.name, parent_str],
            )
            .context("failed to insert team")?;

        debug!(team_id = %team.id, name = %team.name, "added team");
        Ok(team.id)
    }

    /// Retrieve a team by ID.
    pub fn get_team(&self, id: &TeamId) -> Result<Option<Team>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, parent FROM teams WHERE id = ?1")?;

        let result = stmt
            .query_row(params![id.to_string()], |row| {
                let id_str: String = row.get(0)?;
                let name: String = row.get(1)?;
                let parent_str: Option<String> = row.get(2)?;
                Ok((id_str, name, parent_str))
            })
            .optional()
            .context("failed to query team")?;

        match result {
            Some((id_str, name, parent_str)) => {
                let id =
                    TeamId::from_uuid(Uuid::parse_str(&id_str).context("invalid team UUID")?);
                let parent = parent_str
                    .map(|s| {
                        Uuid::parse_str(&s)
                            .map(TeamId::from_uuid)
                            .context("invalid parent team UUID")
                    })
                    .transpose()?;
                Ok(Some(Team { id, name, parent }))
            }
            None => Ok(None),
        }
    }

    // ── Bounded authorizations ──────────────────────────────────────────

    /// Add a bounded authorization to the store.
    pub fn add_bounded_authorization(&self, auth: &BoundedAuthorization) -> Result<GrantId> {
        let capability_json = serde_json::to_string(&auth.capability)?;
        let bound_type_json = serde_json::to_string(&auth.bound_type)?;

        self.conn
            .execute(
                "INSERT INTO bounded_authorizations (id, principal, capability, bound_type, consumed, use_count, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    auth.id.to_string(),
                    auth.principal.to_string(),
                    capability_json,
                    bound_type_json,
                    auth.consumed as i32,
                    auth.use_count as i64,
                    auth.created_at.to_rfc3339(),
                ],
            )
            .context("failed to insert bounded authorization")?;

        debug!(grant_id = %auth.id, "added bounded authorization");
        Ok(auth.id)
    }

    /// Atomically try to consume a bounded authorization.
    ///
    /// Sets `consumed=1` only if currently `consumed=0`. Returns `true` if the
    /// update succeeded (authorization was available), `false` if it was already
    /// consumed.
    pub fn try_consume_bounded(&self, id: &GrantId) -> Result<bool> {
        let affected = self.conn.execute(
            "UPDATE bounded_authorizations SET consumed = 1 WHERE id = ?1 AND consumed = 0",
            params![id.to_string()],
        )?;

        if affected > 0 {
            debug!(grant_id = %id, "consumed bounded authorization");
            Ok(true)
        } else {
            // Check if the grant exists at all
            let exists: bool = self
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM bounded_authorizations WHERE id = ?1",
                    params![id.to_string()],
                    |row| row.get::<_, i64>(0).map(|c| c > 0),
                )
                .context("failed to check bounded authorization existence")?;

            if !exists {
                bail!("bounded authorization {id} not found");
            }

            debug!(grant_id = %id, "bounded authorization already consumed");
            Ok(false)
        }
    }
}

// ── Raw row types ───────────────────────────────────────────────────────

struct RawPrincipalRow {
    id: String,
    kind: String,
    status: String,
    trust_level: String,
    display_name: String,
    details: String,
    org_position: Option<String>,
    teams: String,
}

fn raw_to_principal(row: RawPrincipalRow) -> Result<Principal> {
    let id =
        PrincipalId::from_uuid(Uuid::parse_str(&row.id).context("invalid principal UUID")?);
    let kind = serde_json::from_str(&row.kind).context("invalid principal kind")?;
    let status = serde_json::from_str(&row.status).context("invalid principal status")?;
    let trust_level =
        serde_json::from_str(&row.trust_level).context("invalid principal trust level")?;
    let details = serde_json::from_str(&row.details).context("invalid principal details")?;
    let org_position = row
        .org_position
        .map(|s| {
            Uuid::parse_str(&s)
                .map(OrgPositionId::from_uuid)
                .context("invalid org position UUID")
        })
        .transpose()?;
    let teams: Vec<TeamId> = serde_json::from_str(&row.teams).context("invalid teams")?;

    Ok(Principal {
        id,
        kind,
        status,
        trust_level,
        display_name: row.display_name,
        details,
        org_position,
        teams,
    })
}

struct RawRoleRow {
    id: String,
    name: String,
    permissions: String,
    includes: String,
    min_org_level: Option<String>,
    conflicts_with: String,
}

fn raw_to_role(row: RawRoleRow) -> Result<Role> {
    let id = RoleId::from_uuid(Uuid::parse_str(&row.id).context("invalid role UUID")?);
    let permissions = serde_json::from_str(&row.permissions).context("invalid role permissions")?;
    let includes = serde_json::from_str(&row.includes).context("invalid role includes")?;
    let min_org_level = row
        .min_org_level
        .map(|s| serde_json::from_str(&s))
        .transpose()
        .context("invalid min_org_level")?;
    let conflicts_with =
        serde_json::from_str(&row.conflicts_with).context("invalid conflicts_with")?;

    Ok(Role {
        id,
        name: row.name,
        permissions,
        includes,
        min_org_level,
        conflicts_with,
    })
}

struct RawDelegationEdgeRow {
    id: String,
    from_id: String,
    to_id: String,
    constraints: String,
    revoked: i32,
    created_at: String,
}

fn raw_to_delegation_edge(row: RawDelegationEdgeRow) -> Result<DelegationEdge> {
    let id = DelegationEdgeId::from_uuid(
        Uuid::parse_str(&row.id).context("invalid delegation edge UUID")?,
    );
    let from =
        PrincipalId::from_uuid(Uuid::parse_str(&row.from_id).context("invalid from UUID")?);
    let to = PrincipalId::from_uuid(Uuid::parse_str(&row.to_id).context("invalid to UUID")?);
    let constraints =
        serde_json::from_str(&row.constraints).context("invalid delegation constraints")?;
    let created_at: DateTime<Utc> = row
        .created_at
        .parse()
        .context("invalid created_at timestamp")?;

    Ok(DelegationEdge {
        id,
        from,
        to,
        constraints,
        revoked: row.revoked != 0,
        created_at,
    })
}

struct RawOrgPositionRow {
    id: String,
    title: String,
    level: String,
    reports_to: Option<String>,
    team: Option<String>,
    holder: Option<String>,
}

fn raw_to_org_position(row: RawOrgPositionRow) -> Result<OrgPosition> {
    let id = OrgPositionId::from_uuid(
        Uuid::parse_str(&row.id).context("invalid org position UUID")?,
    );
    let level = serde_json::from_str(&row.level).context("invalid org level")?;
    let reports_to = row
        .reports_to
        .map(|s| {
            Uuid::parse_str(&s)
                .map(OrgPositionId::from_uuid)
                .context("invalid reports_to UUID")
        })
        .transpose()?;
    let team = row
        .team
        .map(|s| {
            Uuid::parse_str(&s)
                .map(TeamId::from_uuid)
                .context("invalid team UUID")
        })
        .transpose()?;
    let holder = row
        .holder
        .map(|s| {
            Uuid::parse_str(&s)
                .map(PrincipalId::from_uuid)
                .context("invalid holder UUID")
        })
        .transpose()?;

    Ok(OrgPosition {
        id,
        title: row.title,
        level,
        reports_to,
        team,
        holder,
    })
}

/// Extension trait for `rusqlite::OptionalExtension`-like behavior.
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for std::result::Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::capability::{Capability, Constraints};
    use mc_core::delegation::{BoundedType, DelegationConstraints};
    use mc_core::id::CapabilityId;
    use mc_core::operation::Operation;
    use mc_core::org::OrgLevel;
    use mc_core::principal::{PrincipalDetails, PrincipalKind, PrincipalTrustLevel};
    use mc_core::resource::ResourcePattern;
    use std::collections::HashSet;

    fn test_store() -> PermissionGraphStore {
        PermissionGraphStore::new(":memory:").expect("in-memory DB should open")
    }

    fn make_human_principal(name: &str) -> Principal {
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::Human,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Human,
            display_name: name.to_string(),
            details: PrincipalDetails::Human {
                email: format!("{name}@example.com"),
                external_id: None,
            },
            org_position: None,
            teams: vec![],
        }
    }

    fn make_agent_principal(name: &str, spawned_by: Option<PrincipalId>) -> Principal {
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::AiAgent,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Agent,
            display_name: name.to_string(),
            details: PrincipalDetails::AiAgent {
                model: "claude-4".to_string(),
                spawned_by,
                spawning_mission: None,
            },
            org_position: None,
            teams: vec![],
        }
    }

    fn make_role(name: &str) -> Role {
        Role {
            id: RoleId::new(),
            name: name.to_string(),
            permissions: vec![],
            includes: vec![],
            min_org_level: None,
            conflicts_with: vec![],
        }
    }

    fn make_delegation_edge(from: PrincipalId, to: PrincipalId) -> DelegationEdge {
        DelegationEdge {
            id: DelegationEdgeId::new(),
            from,
            to,
            constraints: DelegationConstraints::default(),
            revoked: false,
            created_at: Utc::now(),
        }
    }

    fn make_bounded_auth(principal: PrincipalId) -> BoundedAuthorization {
        BoundedAuthorization {
            id: GrantId::new(),
            principal,
            capability: Capability {
                id: CapabilityId::new(),
                resource_pattern: ResourcePattern::new("http://api.example.com/**").unwrap(),
                operations: {
                    let mut ops = HashSet::new();
                    ops.insert(Operation::Read);
                    ops
                },
                constraints: Constraints::default(),
                delegatable: false,
            },
            bound_type: BoundedType::OneTime,
            consumed: false,
            use_count: 0,
            created_at: Utc::now(),
        }
    }

    // ── Principal tests ─────────────────────────────────────────────────

    #[test]
    fn add_and_get_principal() {
        let store = test_store();
        let alice = make_human_principal("Alice");

        let id = store.add_principal(&alice).unwrap();
        assert_eq!(id, alice.id);

        let fetched = store.get_principal(&id).unwrap().unwrap();
        assert_eq!(fetched.id, alice.id);
        assert_eq!(fetched.display_name, "Alice");
        assert_eq!(fetched.kind, PrincipalKind::Human);
        assert_eq!(fetched.status, PrincipalStatus::Active);
        assert_eq!(fetched.trust_level, PrincipalTrustLevel::Human);
    }

    #[test]
    fn get_nonexistent_principal_returns_none() {
        let store = test_store();
        let result = store.get_principal(&PrincipalId::new()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn update_principal_status() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        store.add_principal(&alice).unwrap();

        store
            .update_principal_status(&alice.id, PrincipalStatus::Suspended)
            .unwrap();

        let fetched = store.get_principal(&alice.id).unwrap().unwrap();
        assert_eq!(fetched.status, PrincipalStatus::Suspended);
    }

    #[test]
    fn update_status_nonexistent_fails() {
        let store = test_store();
        let result = store.update_principal_status(&PrincipalId::new(), PrincipalStatus::Revoked);
        assert!(result.is_err());
    }

    #[test]
    fn list_principals() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        let bob = make_agent_principal("Bot-Bob", None);
        store.add_principal(&alice).unwrap();
        store.add_principal(&bob).unwrap();

        let principals = store.list_principals().unwrap();
        assert_eq!(principals.len(), 2);

        let names: Vec<&str> = principals.iter().map(|p| p.display_name.as_str()).collect();
        assert!(names.contains(&"Alice"));
        assert!(names.contains(&"Bot-Bob"));
    }

    // ── Role tests ──────────────────────────────────────────────────────

    #[test]
    fn add_and_get_role() {
        let store = test_store();
        let role = make_role("developer");

        let id = store.add_role(&role).unwrap();
        assert_eq!(id, role.id);

        let fetched = store.get_role(&id).unwrap().unwrap();
        assert_eq!(fetched.id, role.id);
        assert_eq!(fetched.name, "developer");
    }

    #[test]
    fn get_nonexistent_role_returns_none() {
        let store = test_store();
        let result = store.get_role(&RoleId::new()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn assign_role_and_get_assignments() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        let dev_role = make_role("developer");
        let admin_role = make_role("admin");

        store.add_principal(&alice).unwrap();
        store.add_role(&dev_role).unwrap();
        store.add_role(&admin_role).unwrap();

        let a1 = store
            .assign_role(&alice.id, &dev_role.id, RoleAssignmentScope::Global, None)
            .unwrap();
        let a2 = store
            .assign_role(
                &alice.id,
                &admin_role.id,
                RoleAssignmentScope::Team,
                None,
            )
            .unwrap();

        let assignments = store.get_principal_roles(&alice.id).unwrap();
        assert_eq!(assignments.len(), 2);

        let assignment_ids: Vec<RoleAssignmentId> = assignments.iter().map(|a| a.0).collect();
        assert!(assignment_ids.contains(&a1));
        assert!(assignment_ids.contains(&a2));

        // Verify scopes
        let dev_assignment = assignments.iter().find(|a| a.1 == dev_role.id).unwrap();
        assert_eq!(dev_assignment.2, RoleAssignmentScope::Global);

        let admin_assignment = assignments.iter().find(|a| a.1 == admin_role.id).unwrap();
        assert_eq!(admin_assignment.2, RoleAssignmentScope::Team);
    }

    #[test]
    fn get_roles_for_principal_with_no_assignments() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        store.add_principal(&alice).unwrap();

        let assignments = store.get_principal_roles(&alice.id).unwrap();
        assert!(assignments.is_empty());
    }

    // ── Delegation edge tests ───────────────────────────────────────────

    #[test]
    fn add_and_get_delegation_edge() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        let bot = make_agent_principal("Bot", Some(alice.id));
        store.add_principal(&alice).unwrap();
        store.add_principal(&bot).unwrap();

        let edge = make_delegation_edge(alice.id, bot.id);
        let id = store.add_delegation_edge(&edge).unwrap();
        assert_eq!(id, edge.id);

        let fetched = store.get_delegation_edge(&id).unwrap().unwrap();
        assert_eq!(fetched.id, edge.id);
        assert_eq!(fetched.from, alice.id);
        assert_eq!(fetched.to, bot.id);
        assert!(!fetched.revoked);
    }

    #[test]
    fn get_nonexistent_delegation_edge_returns_none() {
        let store = test_store();
        let result = store
            .get_delegation_edge(&DelegationEdgeId::new())
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_delegations_from_and_to() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        let bot1 = make_agent_principal("Bot-1", Some(alice.id));
        let bot2 = make_agent_principal("Bot-2", Some(alice.id));
        store.add_principal(&alice).unwrap();
        store.add_principal(&bot1).unwrap();
        store.add_principal(&bot2).unwrap();

        let edge1 = make_delegation_edge(alice.id, bot1.id);
        let edge2 = make_delegation_edge(alice.id, bot2.id);
        store.add_delegation_edge(&edge1).unwrap();
        store.add_delegation_edge(&edge2).unwrap();

        // Delegations from Alice
        let from_alice = store.get_delegations_from(&alice.id).unwrap();
        assert_eq!(from_alice.len(), 2);

        // Delegations to Bot-1
        let to_bot1 = store.get_delegations_to(&bot1.id).unwrap();
        assert_eq!(to_bot1.len(), 1);
        assert_eq!(to_bot1[0].from, alice.id);

        // Delegations to Bot-2
        let to_bot2 = store.get_delegations_to(&bot2.id).unwrap();
        assert_eq!(to_bot2.len(), 1);
        assert_eq!(to_bot2[0].from, alice.id);

        // No delegations to Alice
        let to_alice = store.get_delegations_to(&alice.id).unwrap();
        assert!(to_alice.is_empty());
    }

    #[test]
    fn revoke_delegation_edge() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        let bot = make_agent_principal("Bot", Some(alice.id));
        store.add_principal(&alice).unwrap();
        store.add_principal(&bot).unwrap();

        let edge = make_delegation_edge(alice.id, bot.id);
        let id = store.add_delegation_edge(&edge).unwrap();

        store.revoke_delegation_edge(&id).unwrap();

        let fetched = store.get_delegation_edge(&id).unwrap().unwrap();
        assert!(fetched.revoked);
    }

    #[test]
    fn revoke_nonexistent_delegation_fails() {
        let store = test_store();
        let result = store.revoke_delegation_edge(&DelegationEdgeId::new());
        assert!(result.is_err());
    }

    #[test]
    fn increment_operations_used() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        let bot = make_agent_principal("Bot", Some(alice.id));
        store.add_principal(&alice).unwrap();
        store.add_principal(&bot).unwrap();

        let edge = make_delegation_edge(alice.id, bot.id);
        let id = store.add_delegation_edge(&edge).unwrap();

        let count1 = store.increment_operations_used(&id).unwrap();
        assert_eq!(count1, 1);

        let count2 = store.increment_operations_used(&id).unwrap();
        assert_eq!(count2, 2);

        let count3 = store.increment_operations_used(&id).unwrap();
        assert_eq!(count3, 3);

        // Verify the stored edge reflects the updated count
        let fetched = store.get_delegation_edge(&id).unwrap().unwrap();
        assert_eq!(fetched.constraints.operations_used, 3);
    }

    // ── Org position tests ──────────────────────────────────────────────

    #[test]
    fn add_and_get_org_position() {
        let store = test_store();
        let pos = OrgPosition {
            id: OrgPositionId::new(),
            title: "Engineering Manager".to_string(),
            level: OrgLevel::Manager,
            reports_to: None,
            team: None,
            holder: None,
        };

        let id = store.add_org_position(&pos).unwrap();
        assert_eq!(id, pos.id);

        let fetched = store.get_org_position(&id).unwrap().unwrap();
        assert_eq!(fetched.title, "Engineering Manager");
        assert_eq!(fetched.level, OrgLevel::Manager);
    }

    #[test]
    fn get_nonexistent_org_position_returns_none() {
        let store = test_store();
        let result = store.get_org_position(&OrgPositionId::new()).unwrap();
        assert!(result.is_none());
    }

    // ── Team tests ──────────────────────────────────────────────────────

    #[test]
    fn add_and_get_team() {
        let store = test_store();
        let team = Team {
            id: TeamId::new(),
            name: "Platform".to_string(),
            parent: None,
        };

        let id = store.add_team(&team).unwrap();
        assert_eq!(id, team.id);

        let fetched = store.get_team(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "Platform");
        assert!(fetched.parent.is_none());
    }

    #[test]
    fn get_nonexistent_team_returns_none() {
        let store = test_store();
        let result = store.get_team(&TeamId::new()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn team_with_parent() {
        let store = test_store();
        let parent_team = Team {
            id: TeamId::new(),
            name: "Engineering".to_string(),
            parent: None,
        };
        let child_team = Team {
            id: TeamId::new(),
            name: "Platform".to_string(),
            parent: Some(parent_team.id),
        };

        store.add_team(&parent_team).unwrap();
        store.add_team(&child_team).unwrap();

        let fetched = store.get_team(&child_team.id).unwrap().unwrap();
        assert_eq!(fetched.parent, Some(parent_team.id));
    }

    // ── Bounded authorization tests ─────────────────────────────────────

    #[test]
    fn add_bounded_authorization_and_consume() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        store.add_principal(&alice).unwrap();

        let auth = make_bounded_auth(alice.id);
        let id = store.add_bounded_authorization(&auth).unwrap();
        assert_eq!(id, auth.id);

        // First consume succeeds
        let consumed = store.try_consume_bounded(&id).unwrap();
        assert!(consumed);

        // Second consume fails (already consumed)
        let consumed_again = store.try_consume_bounded(&id).unwrap();
        assert!(!consumed_again);
    }

    #[test]
    fn try_consume_nonexistent_fails() {
        let store = test_store();
        let result = store.try_consume_bounded(&GrantId::new());
        assert!(result.is_err());
    }

    #[test]
    fn double_consume_returns_false() {
        let store = test_store();
        let alice = make_human_principal("Alice");
        store.add_principal(&alice).unwrap();

        let auth = make_bounded_auth(alice.id);
        store.add_bounded_authorization(&auth).unwrap();

        // Consume once
        assert!(store.try_consume_bounded(&auth.id).unwrap());
        // Second attempt
        assert!(!store.try_consume_bounded(&auth.id).unwrap());
        // Third attempt still false
        assert!(!store.try_consume_bounded(&auth.id).unwrap());
    }

    // ── Integration-style test ──────────────────────────────────────────

    #[test]
    fn full_graph_scenario() {
        let store = test_store();

        // Create principals
        let alice = make_human_principal("Alice");
        let bot = make_agent_principal("Bot", Some(alice.id));
        store.add_principal(&alice).unwrap();
        store.add_principal(&bot).unwrap();

        // Create and assign roles
        let dev_role = make_role("developer");
        store.add_role(&dev_role).unwrap();
        store
            .assign_role(&alice.id, &dev_role.id, RoleAssignmentScope::Global, None)
            .unwrap();

        // Create delegation
        let edge = make_delegation_edge(alice.id, bot.id);
        store.add_delegation_edge(&edge).unwrap();

        // Create org structure
        let team = Team {
            id: TeamId::new(),
            name: "Platform".to_string(),
            parent: None,
        };
        store.add_team(&team).unwrap();

        let pos = OrgPosition {
            id: OrgPositionId::new(),
            title: "Tech Lead".to_string(),
            level: OrgLevel::Lead,
            reports_to: None,
            team: Some(team.id),
            holder: Some(alice.id),
        };
        store.add_org_position(&pos).unwrap();

        // Create bounded authorization
        let auth = make_bounded_auth(bot.id);
        store.add_bounded_authorization(&auth).unwrap();

        // Verify everything is retrievable
        assert!(store.get_principal(&alice.id).unwrap().is_some());
        assert!(store.get_principal(&bot.id).unwrap().is_some());
        assert!(store.get_role(&dev_role.id).unwrap().is_some());
        assert_eq!(store.get_principal_roles(&alice.id).unwrap().len(), 1);
        assert_eq!(store.get_delegations_from(&alice.id).unwrap().len(), 1);
        assert_eq!(store.get_delegations_to(&bot.id).unwrap().len(), 1);
        assert!(store.get_team(&team.id).unwrap().is_some());
        assert!(store.get_org_position(&pos.id).unwrap().is_some());
        assert!(store.try_consume_bounded(&auth.id).unwrap());
    }
}

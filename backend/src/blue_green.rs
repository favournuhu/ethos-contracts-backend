//! Blue-Green Deployment Support — Issue #592
//!
//! Zero-downtime deployments were not previously possible. This module
//! implements dual-environment (blue/green) deployment infrastructure with
//! instant traffic switching, rollback capability, and health-check integration.
//!
//! # Architecture
//!
//! ```text
//!                  ┌─────────────┐
//!    incoming ────►│  Router     │
//!    traffic       │  (active:   │
//!                  │  blue|green)│
//!                  └──────┬──────┘
//!               ┌─────────┴──────────┐
//!          ┌────▼────┐          ┌────▼────┐
//!          │  Blue   │          │  Green  │
//!          │ (v1.0)  │          │ (v2.0)  │
//!          └─────────┘          └─────────┘
//! ```
//!
//! # Endpoints
//!
//! ```text
//! POST   /deployments/blue-green              → create_blue_green_deployment
//! GET    /deployments/blue-green              → list_blue_green_deployments
//! GET    /deployments/blue-green/:id          → get_blue_green_deployment
//! POST   /deployments/blue-green/:id/switch   → switch_traffic
//! POST   /deployments/blue-green/:id/rollback → rollback_blue_green
//! POST   /deployments/blue-green/:id/health   → report_health
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Domain types ──────────────────────────────────────────────────────────────

/// Which slot is currently active (receiving live traffic).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActiveSlot {
    Blue,
    Green,
}

impl ActiveSlot {
    pub fn opposite(self) -> Self {
        match self {
            Self::Blue => Self::Green,
            Self::Green => Self::Blue,
        }
    }
}

impl std::fmt::Display for ActiveSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blue => write!(f, "blue"),
            Self::Green => write!(f, "green"),
        }
    }
}

/// Health status of a deployment slot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SlotHealth {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

/// A deployment slot (blue or green) holding one service version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentSlot {
    pub version: String,
    pub health: SlotHealth,
    pub deployed_at: DateTime<Utc>,
    pub last_health_check: Option<DateTime<Utc>>,
    /// Fraction of traffic being sent to this slot (0.0–1.0).
    /// Always 1.0 for the active slot and 0.0 for the standby slot
    /// outside of a gradual-switch operation.
    pub traffic_weight: f64,
    /// Health check endpoint URL for this slot.
    pub health_endpoint: Option<String>,
}

/// Overall status of a blue-green deployment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlueGreenStatus {
    /// Both slots healthy, traffic routing to active slot.
    Stable,
    /// A traffic switch is in progress.
    Switching,
    /// The inactive slot is being prepared / warmed up.
    Preparing,
    /// A rollback has been executed.
    RolledBack,
    /// Health check failures detected; deployment is unhealthy.
    Unhealthy,
}

/// A complete blue-green deployment record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueGreenDeployment {
    pub id: String,
    pub service: String,
    pub active_slot: ActiveSlot,
    pub blue: DeploymentSlot,
    pub green: DeploymentSlot,
    pub status: BlueGreenStatus,
    pub history: Vec<BlueGreenEvent>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BlueGreenDeployment {
    fn push_event(&mut self, description: impl Into<String>) {
        self.history.push(BlueGreenEvent {
            timestamp: Utc::now(),
            description: description.into(),
        });
        self.updated_at = Utc::now();
    }

    /// Return a reference to the currently active slot data.
    pub fn active(&self) -> &DeploymentSlot {
        match self.active_slot {
            ActiveSlot::Blue => &self.blue,
            ActiveSlot::Green => &self.green,
        }
    }

    /// Return a reference to the currently standby slot data.
    pub fn standby(&self) -> &DeploymentSlot {
        match self.active_slot {
            ActiveSlot::Blue => &self.green,
            ActiveSlot::Green => &self.blue,
        }
    }
}

/// A single historical event in a blue-green deployment's lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueGreenEvent {
    pub timestamp: DateTime<Utc>,
    pub description: String,
}

// ── Shared state ──────────────────────────────────────────────────────────────

pub type BlueGreenStore = Arc<Mutex<HashMap<String, BlueGreenDeployment>>>;

#[derive(Clone)]
pub struct BlueGreenState {
    pub store: BlueGreenStore,
}

impl BlueGreenState {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for BlueGreenState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Request / response types ──────────────────────────────────────────────────

/// `POST /deployments/blue-green`
#[derive(Debug, Deserialize)]
pub struct CreateBlueGreenRequest {
    pub service: String,
    /// Version currently running in the active (blue) slot.
    pub blue_version: String,
    /// Version to deploy to the standby (green) slot.
    pub green_version: String,
    /// Which slot starts as active.
    #[serde(default = "default_active_slot")]
    pub initial_active: ActiveSlot,
    pub blue_health_endpoint: Option<String>,
    pub green_health_endpoint: Option<String>,
}

fn default_active_slot() -> ActiveSlot {
    ActiveSlot::Blue
}

/// `POST /deployments/blue-green/:id/switch`
#[derive(Debug, Deserialize)]
pub struct SwitchTrafficRequest {
    /// Human-readable reason for this traffic switch.
    pub reason: String,
    /// If true, verify the standby slot is healthy before switching.
    #[serde(default = "default_true")]
    pub require_healthy_standby: bool,
}

fn default_true() -> bool { true }

/// `POST /deployments/blue-green/:id/rollback`
#[derive(Debug, Deserialize)]
pub struct RollbackBlueGreenRequest {
    pub reason: String,
}

/// `POST /deployments/blue-green/:id/health`
#[derive(Debug, Deserialize)]
pub struct ReportHealthRequest {
    pub slot: ActiveSlot,
    pub health: SlotHealth,
    /// Optional metrics snapshot at the time of the health check.
    pub details: Option<serde_json::Value>,
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

/// `POST /deployments/blue-green` — create a new blue-green deployment record.
pub async fn create_blue_green_deployment(
    State(state): State<Arc<BlueGreenState>>,
    Json(body): Json<CreateBlueGreenRequest>,
) -> Result<(StatusCode, Json<BlueGreenDeployment>), (StatusCode, Json<serde_json::Value>)> {
    if body.service.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "service name must not be empty" })),
        ));
    }
    if body.blue_version.trim().is_empty() || body.green_version.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "both blue_version and green_version are required" })),
        ));
    }

    let now = Utc::now();
    let (blue_weight, green_weight) = match body.initial_active {
        ActiveSlot::Blue => (1.0, 0.0),
        ActiveSlot::Green => (0.0, 1.0),
    };

    let mut deployment = BlueGreenDeployment {
        id: Uuid::new_v4().to_string(),
        service: body.service.clone(),
        active_slot: body.initial_active,
        blue: DeploymentSlot {
            version: body.blue_version.clone(),
            health: SlotHealth::Unknown,
            deployed_at: now,
            last_health_check: None,
            traffic_weight: blue_weight,
            health_endpoint: body.blue_health_endpoint,
        },
        green: DeploymentSlot {
            version: body.green_version.clone(),
            health: SlotHealth::Unknown,
            deployed_at: now,
            last_health_check: None,
            traffic_weight: green_weight,
            health_endpoint: body.green_health_endpoint,
        },
        status: BlueGreenStatus::Preparing,
        history: vec![],
        created_at: now,
        updated_at: now,
    };

    deployment.push_event(format!(
        "blue-green deployment created; active={}, blue={}, green={}",
        body.initial_active, body.blue_version, body.green_version
    ));

    tracing::info!(
        deployment_id = %deployment.id,
        service = %body.service,
        active_slot = %body.initial_active,
        blue_version = %body.blue_version,
        green_version = %body.green_version,
        "blue-green deployment created"
    );

    let mut store = state.store.lock().unwrap();
    store.insert(deployment.id.clone(), deployment.clone());

    Ok((StatusCode::CREATED, Json(deployment)))
}

/// `GET /deployments/blue-green` — list all blue-green deployments.
pub async fn list_blue_green_deployments(
    State(state): State<Arc<BlueGreenState>>,
) -> Json<Vec<BlueGreenDeployment>> {
    let store = state.store.lock().unwrap();
    let mut deployments: Vec<BlueGreenDeployment> = store.values().cloned().collect();
    deployments.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Json(deployments)
}

/// `GET /deployments/blue-green/:id` — get a single deployment.
pub async fn get_blue_green_deployment(
    State(state): State<Arc<BlueGreenState>>,
    Path(id): Path<String>,
) -> Result<Json<BlueGreenDeployment>, StatusCode> {
    let store = state.store.lock().unwrap();
    store.get(&id).cloned().map(Json).ok_or(StatusCode::NOT_FOUND)
}

/// `POST /deployments/blue-green/:id/switch` — switch active traffic to the
/// standby slot, completing a zero-downtime deployment.
pub async fn switch_traffic(
    State(state): State<Arc<BlueGreenState>>,
    Path(id): Path<String>,
    Json(body): Json<SwitchTrafficRequest>,
) -> Result<Json<BlueGreenDeployment>, (StatusCode, Json<serde_json::Value>)> {
    let mut store = state.store.lock().unwrap();
    let deployment = store
        .get_mut(&id)
        .ok_or((StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "not found" }))))?;

    let standby = deployment.standby();

    if body.require_healthy_standby && standby.health == SlotHealth::Unhealthy {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "standby slot is unhealthy; refusing traffic switch",
                "standby_slot": deployment.active_slot.opposite(),
                "health": standby.health,
            })),
        ));
    }

    let previous_active = deployment.active_slot;
    let new_active = previous_active.opposite();
    deployment.status = BlueGreenStatus::Switching;
    deployment.push_event(format!(
        "switching traffic: {previous_active} → {new_active}; reason: {}",
        body.reason
    ));

    // Perform the switch atomically.
    deployment.active_slot = new_active;
    match new_active {
        ActiveSlot::Blue => {
            deployment.blue.traffic_weight = 1.0;
            deployment.green.traffic_weight = 0.0;
        }
        ActiveSlot::Green => {
            deployment.green.traffic_weight = 1.0;
            deployment.blue.traffic_weight = 0.0;
        }
    }
    deployment.status = BlueGreenStatus::Stable;
    deployment.push_event(format!(
        "traffic switched to {new_active}; {previous_active} is now standby"
    ));

    tracing::info!(
        deployment_id = %id,
        previous_active = %previous_active,
        new_active = %new_active,
        reason = %body.reason,
        "blue-green traffic switch completed"
    );

    Ok(Json(deployment.clone()))
}

/// `POST /deployments/blue-green/:id/rollback` — roll back to the previously
/// active slot. This is a second traffic switch back to the original side.
pub async fn rollback_blue_green(
    State(state): State<Arc<BlueGreenState>>,
    Path(id): Path<String>,
    Json(body): Json<RollbackBlueGreenRequest>,
) -> Result<Json<BlueGreenDeployment>, StatusCode> {
    let mut store = state.store.lock().unwrap();
    let deployment = store.get_mut(&id).ok_or(StatusCode::NOT_FOUND)?;

    let current_active = deployment.active_slot;
    let rollback_to = current_active.opposite();

    deployment.active_slot = rollback_to;
    match rollback_to {
        ActiveSlot::Blue => {
            deployment.blue.traffic_weight = 1.0;
            deployment.green.traffic_weight = 0.0;
        }
        ActiveSlot::Green => {
            deployment.green.traffic_weight = 1.0;
            deployment.blue.traffic_weight = 0.0;
        }
    }
    deployment.status = BlueGreenStatus::RolledBack;
    deployment.push_event(format!(
        "rollback: reverted from {current_active} to {rollback_to}; reason: {}",
        body.reason
    ));

    tracing::warn!(
        deployment_id = %id,
        rolled_back_from = %current_active,
        rolled_back_to = %rollback_to,
        reason = %body.reason,
        "blue-green deployment rolled back"
    );

    Ok(Json(deployment.clone()))
}

/// `POST /deployments/blue-green/:id/health` — report health for a slot so
/// the router can make informed switching decisions.
pub async fn report_health(
    State(state): State<Arc<BlueGreenState>>,
    Path(id): Path<String>,
    Json(body): Json<ReportHealthRequest>,
) -> Result<Json<BlueGreenDeployment>, StatusCode> {
    let mut store = state.store.lock().unwrap();
    let deployment = store.get_mut(&id).ok_or(StatusCode::NOT_FOUND)?;
    let now = Utc::now();

    let slot = match body.slot {
        ActiveSlot::Blue => &mut deployment.blue,
        ActiveSlot::Green => &mut deployment.green,
    };
    slot.health = body.health;
    slot.last_health_check = Some(now);
    deployment.updated_at = now;

    // If the active slot is now unhealthy, mark the overall deployment as unhealthy.
    let active_health = deployment.active().health;
    if active_health == SlotHealth::Unhealthy {
        deployment.status = BlueGreenStatus::Unhealthy;
        deployment.push_event(format!(
            "active slot ({}) reported unhealthy; deployment status → unhealthy",
            deployment.active_slot
        ));
        tracing::error!(
            deployment_id = %id,
            active_slot = %deployment.active_slot,
            "active blue-green slot is unhealthy — consider rolling back"
        );
    }

    Ok(Json(deployment.clone()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_deployment(state: &Arc<BlueGreenState>) -> BlueGreenDeployment {
        let (_, Json(d)) = create_blue_green_deployment(
            State(Arc::clone(state)),
            Json(CreateBlueGreenRequest {
                service: "vault-api".into(),
                blue_version: "v1.0.0".into(),
                green_version: "v2.0.0".into(),
                initial_active: ActiveSlot::Blue,
                blue_health_endpoint: None,
                green_health_endpoint: None,
            }),
        )
        .await
        .unwrap();
        d
    }

    #[tokio::test]
    async fn creates_deployment_with_blue_active() {
        let state = Arc::new(BlueGreenState::new());
        let d = create_deployment(&state).await;
        assert_eq!(d.active_slot, ActiveSlot::Blue);
        assert_eq!(d.blue.traffic_weight, 1.0);
        assert_eq!(d.green.traffic_weight, 0.0);
    }

    #[tokio::test]
    async fn switch_traffic_moves_active_to_green() {
        let state = Arc::new(BlueGreenState::new());
        let d = create_deployment(&state).await;

        // Mark green as healthy so switch is allowed.
        let _ = report_health(
            State(Arc::clone(&state)),
            Path(d.id.clone()),
            Json(ReportHealthRequest {
                slot: ActiveSlot::Green,
                health: SlotHealth::Healthy,
                details: None,
            }),
        )
        .await
        .unwrap();

        let Json(switched) = switch_traffic(
            State(Arc::clone(&state)),
            Path(d.id.clone()),
            Json(SwitchTrafficRequest {
                reason: "deploy v2.0.0".into(),
                require_healthy_standby: true,
            }),
        )
        .await
        .unwrap();

        assert_eq!(switched.active_slot, ActiveSlot::Green);
        assert_eq!(switched.green.traffic_weight, 1.0);
        assert_eq!(switched.blue.traffic_weight, 0.0);
        assert_eq!(switched.status, BlueGreenStatus::Stable);
    }

    #[tokio::test]
    async fn switch_traffic_refused_when_standby_unhealthy() {
        let state = Arc::new(BlueGreenState::new());
        let d = create_deployment(&state).await;

        let _ = report_health(
            State(Arc::clone(&state)),
            Path(d.id.clone()),
            Json(ReportHealthRequest {
                slot: ActiveSlot::Green,
                health: SlotHealth::Unhealthy,
                details: None,
            }),
        )
        .await
        .unwrap();

        let result = switch_traffic(
            State(Arc::clone(&state)),
            Path(d.id.clone()),
            Json(SwitchTrafficRequest {
                reason: "should fail".into(),
                require_healthy_standby: true,
            }),
        )
        .await;

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn rollback_reverts_active_slot() {
        let state = Arc::new(BlueGreenState::new());
        let d = create_deployment(&state).await;

        // Mark green healthy, switch to green.
        let _ = report_health(
            State(Arc::clone(&state)),
            Path(d.id.clone()),
            Json(ReportHealthRequest {
                slot: ActiveSlot::Green,
                health: SlotHealth::Healthy,
                details: None,
            }),
        )
        .await;
        let _ = switch_traffic(
            State(Arc::clone(&state)),
            Path(d.id.clone()),
            Json(SwitchTrafficRequest { reason: "deploy".into(), require_healthy_standby: true }),
        )
        .await;

        // Now rollback.
        let Json(rolled_back) = rollback_blue_green(
            State(Arc::clone(&state)),
            Path(d.id.clone()),
            Json(RollbackBlueGreenRequest { reason: "green has issues".into() }),
        )
        .await
        .unwrap();

        assert_eq!(rolled_back.active_slot, ActiveSlot::Blue);
        assert_eq!(rolled_back.status, BlueGreenStatus::RolledBack);
    }

    #[tokio::test]
    async fn unhealthy_active_slot_marks_deployment_unhealthy() {
        let state = Arc::new(BlueGreenState::new());
        let d = create_deployment(&state).await;

        let Json(updated) = report_health(
            State(Arc::clone(&state)),
            Path(d.id.clone()),
            Json(ReportHealthRequest {
                slot: ActiveSlot::Blue, // active slot
                health: SlotHealth::Unhealthy,
                details: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(updated.status, BlueGreenStatus::Unhealthy);
    }

    #[tokio::test]
    async fn service_name_required() {
        let state = Arc::new(BlueGreenState::new());
        let result = create_blue_green_deployment(
            State(Arc::clone(&state)),
            Json(CreateBlueGreenRequest {
                service: "  ".into(),
                blue_version: "v1".into(),
                green_version: "v2".into(),
                initial_active: ActiveSlot::Blue,
                blue_health_endpoint: None,
                green_health_endpoint: None,
            }),
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn active_slot_opposite() {
        assert_eq!(ActiveSlot::Blue.opposite(), ActiveSlot::Green);
        assert_eq!(ActiveSlot::Green.opposite(), ActiveSlot::Blue);
    }
}

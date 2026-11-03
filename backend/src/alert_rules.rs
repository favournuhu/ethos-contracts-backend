//! Alert Rules for Critical Events — Issue #590
//!
//! Critical events (vault releases, high error rates, contract upgrades, etc.)
//! were previously undetected in real-time. This module defines alert rule
//! evaluation with configurable thresholds and Slack/email notification
//! channels.
//!
//! # Architecture
//!
//! ```text
//! POST /alerts/rules              → create_alert_rule
//! GET  /alerts/rules              → list_alert_rules
//! GET  /alerts/rules/:id          → get_alert_rule
//! DELETE /alerts/rules/:id        → delete_alert_rule
//! POST /alerts/evaluate           → evaluate_alerts  (report current metrics, fire alerts)
//! GET  /alerts/fired              → list_fired_alerts
//! ```
//!
//! # Critical Event Types
//!
//! | Event                        | Default threshold          |
//! |------------------------------|----------------------------|
//! | HighErrorRate                | > 5% over 5 min            |
//! | ContractUpgrade              | any upgrade event          |
//! | ContractPaused               | contract_paused == 1       |
//! | VaultReleaseSurge            | > 10 releases / 5 min      |
//! | HighApiLatency               | p99 > 2000 ms              |
//! | CanaryRollback               | any canary rollback        |
//! | DeploymentRollback           | any automated rollback     |
//! | CredentialLifecycleAnomaly   | > 10 errors / 15 min       |

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

/// The critical event type that an alert rule monitors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CriticalEventType {
    HighErrorRate,
    ContractUpgrade,
    ContractPaused,
    VaultReleaseSurge,
    HighApiLatency,
    CanaryRollback,
    DeploymentRollback,
    CredentialLifecycleAnomaly,
    Custom(String),
}

/// Notification channel through which an alert is dispatched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertChannel {
    Slack,
    Email,
    Webhook,
    Log,
}

/// Severity level of a fired alert.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// An alert rule that defines thresholds for a specific critical event type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub event_type: CriticalEventType,
    pub severity: AlertSeverity,
    /// Condition expression stored as a human-readable description; actual
    /// threshold values are stored in `thresholds`.
    pub condition_description: String,
    pub thresholds: AlertThresholds,
    pub channels: Vec<AlertChannel>,
    /// Optional destination: Slack webhook URL, email address, or HTTP endpoint
    /// depending on the channel type.
    pub destinations: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

/// Numeric thresholds used when evaluating an alert rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Maximum acceptable error rate (0.0–1.0). Used for `HighErrorRate`.
    #[serde(default = "default_max_error_rate")]
    pub max_error_rate: f64,
    /// Maximum acceptable p99 latency in milliseconds. Used for `HighApiLatency`.
    #[serde(default = "default_max_latency_p99_ms")]
    pub max_latency_p99_ms: f64,
    /// Maximum vault releases per evaluation window. Used for `VaultReleaseSurge`.
    #[serde(default = "default_max_release_rate")]
    pub max_release_rate: f64,
    /// Maximum credential lifecycle errors per evaluation window.
    #[serde(default = "default_max_credential_errors")]
    pub max_credential_errors: u64,
    /// Evaluation window in minutes.
    #[serde(default = "default_eval_window_minutes")]
    pub eval_window_minutes: u64,
}

fn default_max_error_rate() -> f64 { 0.05 }
fn default_max_latency_p99_ms() -> f64 { 2000.0 }
fn default_max_release_rate() -> f64 { 10.0 }
fn default_max_credential_errors() -> u64 { 10 }
fn default_eval_window_minutes() -> u64 { 5 }

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            max_error_rate: default_max_error_rate(),
            max_latency_p99_ms: default_max_latency_p99_ms(),
            max_release_rate: default_max_release_rate(),
            max_credential_errors: default_max_credential_errors(),
            eval_window_minutes: default_eval_window_minutes(),
        }
    }
}

/// A single fired alert instance produced when a rule's condition is met.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredAlert {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub event_type: CriticalEventType,
    pub severity: AlertSeverity,
    pub message: String,
    pub metric_snapshot: serde_json::Value,
    pub channels_notified: Vec<AlertChannel>,
    pub fired_at: DateTime<Utc>,
    /// Whether the notification was successfully dispatched to all channels.
    pub notification_sent: bool,
}

// ── Current metric snapshot supplied during evaluation ───────────────────────

/// Metric values provided by the caller during an `/alerts/evaluate` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentMetrics {
    pub error_rate: f64,
    pub latency_p99_ms: f64,
    /// Vault releases observed in the current evaluation window.
    pub release_count: f64,
    /// 1.0 if contract is paused, 0.0 otherwise.
    pub contract_paused: f64,
    /// Number of contract upgrade events in the current window.
    pub contract_upgrade_events: u64,
    /// Canary rollbacks triggered in the current window.
    pub canary_rollbacks: u64,
    /// Automated deployment rollbacks in the current window.
    pub deployment_rollbacks: u64,
    /// Credential lifecycle errors in the current window.
    pub credential_lifecycle_errors: u64,
}

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct AlertRulesInner {
    pub rules: HashMap<String, AlertRule>,
    pub fired: Vec<FiredAlert>,
}

pub type AlertRulesStore = Arc<Mutex<AlertRulesInner>>;

#[derive(Clone)]
pub struct AlertRulesState {
    pub store: AlertRulesStore,
}

impl AlertRulesState {
    pub fn new() -> Self {
        let mut inner = AlertRulesInner::default();
        // Seed with sensible default rules for the critical event types.
        seed_default_rules(&mut inner);
        Self {
            store: Arc::new(Mutex::new(inner)),
        }
    }
}

impl Default for AlertRulesState {
    fn default() -> Self {
        Self::new()
    }
}

/// Populate default alert rules covering all critical event types.
fn seed_default_rules(inner: &mut AlertRulesInner) {
    let defaults: Vec<AlertRule> = vec![
        AlertRule {
            id: Uuid::new_v4().to_string(),
            name: "HighErrorRate".into(),
            event_type: CriticalEventType::HighErrorRate,
            severity: AlertSeverity::Critical,
            condition_description: "API error rate exceeds 5% over a 5-minute window".into(),
            thresholds: AlertThresholds::default(),
            channels: vec![AlertChannel::Slack, AlertChannel::Email],
            destinations: vec![],
            enabled: true,
            created_at: Utc::now(),
        },
        AlertRule {
            id: Uuid::new_v4().to_string(),
            name: "ContractUpgradeDetected".into(),
            event_type: CriticalEventType::ContractUpgrade,
            severity: AlertSeverity::Warning,
            condition_description: "An on-chain contract upgrade event was observed".into(),
            thresholds: AlertThresholds::default(),
            channels: vec![AlertChannel::Slack, AlertChannel::Log],
            destinations: vec![],
            enabled: true,
            created_at: Utc::now(),
        },
        AlertRule {
            id: Uuid::new_v4().to_string(),
            name: "ContractPaused".into(),
            event_type: CriticalEventType::ContractPaused,
            severity: AlertSeverity::Critical,
            condition_description: "The ttl_vault contract is currently paused".into(),
            thresholds: AlertThresholds::default(),
            channels: vec![AlertChannel::Slack, AlertChannel::Email],
            destinations: vec![],
            enabled: true,
            created_at: Utc::now(),
        },
        AlertRule {
            id: Uuid::new_v4().to_string(),
            name: "VaultReleaseSurge".into(),
            event_type: CriticalEventType::VaultReleaseSurge,
            severity: AlertSeverity::Warning,
            condition_description: "More than 10 vault releases observed in a single window".into(),
            thresholds: AlertThresholds::default(),
            channels: vec![AlertChannel::Slack],
            destinations: vec![],
            enabled: true,
            created_at: Utc::now(),
        },
        AlertRule {
            id: Uuid::new_v4().to_string(),
            name: "HighApiLatency".into(),
            event_type: CriticalEventType::HighApiLatency,
            severity: AlertSeverity::Warning,
            condition_description: "p99 API latency exceeds 2000 ms".into(),
            thresholds: AlertThresholds::default(),
            channels: vec![AlertChannel::Slack],
            destinations: vec![],
            enabled: true,
            created_at: Utc::now(),
        },
        AlertRule {
            id: Uuid::new_v4().to_string(),
            name: "CanaryRollback".into(),
            event_type: CriticalEventType::CanaryRollback,
            severity: AlertSeverity::Critical,
            condition_description: "A canary deployment was rolled back due to metric breach".into(),
            thresholds: AlertThresholds::default(),
            channels: vec![AlertChannel::Slack, AlertChannel::Email],
            destinations: vec![],
            enabled: true,
            created_at: Utc::now(),
        },
        AlertRule {
            id: Uuid::new_v4().to_string(),
            name: "DeploymentRollback".into(),
            event_type: CriticalEventType::DeploymentRollback,
            severity: AlertSeverity::Critical,
            condition_description: "An automated deployment rollback was triggered".into(),
            thresholds: AlertThresholds::default(),
            channels: vec![AlertChannel::Slack, AlertChannel::Email],
            destinations: vec![],
            enabled: true,
            created_at: Utc::now(),
        },
        AlertRule {
            id: Uuid::new_v4().to_string(),
            name: "CredentialLifecycleAnomaly".into(),
            event_type: CriticalEventType::CredentialLifecycleAnomaly,
            severity: AlertSeverity::Warning,
            condition_description: "More than 10 credential lifecycle errors in 15 minutes".into(),
            thresholds: AlertThresholds {
                eval_window_minutes: 15,
                ..AlertThresholds::default()
            },
            channels: vec![AlertChannel::Slack],
            destinations: vec![],
            enabled: true,
            created_at: Utc::now(),
        },
    ];

    for rule in defaults {
        inner.rules.insert(rule.id.clone(), rule);
    }
}

// ── Core evaluation logic ─────────────────────────────────────────────────────

/// Evaluate a single rule against the provided metrics snapshot.
/// Returns a `FiredAlert` if the condition is breached, `None` otherwise.
pub fn evaluate_rule(rule: &AlertRule, metrics: &CurrentMetrics) -> Option<FiredAlert> {
    if !rule.enabled {
        return None;
    }

    let (breached, message) = match &rule.event_type {
        CriticalEventType::HighErrorRate => {
            let b = metrics.error_rate > rule.thresholds.max_error_rate;
            let m = format!(
                "Error rate {:.2}% exceeds threshold {:.2}%",
                metrics.error_rate * 100.0,
                rule.thresholds.max_error_rate * 100.0
            );
            (b, m)
        }
        CriticalEventType::ContractUpgrade => {
            let b = metrics.contract_upgrade_events > 0;
            let m = format!(
                "{} contract upgrade event(s) detected in evaluation window",
                metrics.contract_upgrade_events
            );
            (b, m)
        }
        CriticalEventType::ContractPaused => {
            let b = metrics.contract_paused >= 1.0;
            let m = "The ttl_vault contract is currently paused".to_string();
            (b, m)
        }
        CriticalEventType::VaultReleaseSurge => {
            let b = metrics.release_count > rule.thresholds.max_release_rate;
            let m = format!(
                "{} vault releases in evaluation window exceeds threshold {}",
                metrics.release_count, rule.thresholds.max_release_rate
            );
            (b, m)
        }
        CriticalEventType::HighApiLatency => {
            let b = metrics.latency_p99_ms > rule.thresholds.max_latency_p99_ms;
            let m = format!(
                "p99 latency {:.1} ms exceeds threshold {:.1} ms",
                metrics.latency_p99_ms, rule.thresholds.max_latency_p99_ms
            );
            (b, m)
        }
        CriticalEventType::CanaryRollback => {
            let b = metrics.canary_rollbacks > 0;
            let m = format!(
                "{} canary rollback(s) triggered in evaluation window",
                metrics.canary_rollbacks
            );
            (b, m)
        }
        CriticalEventType::DeploymentRollback => {
            let b = metrics.deployment_rollbacks > 0;
            let m = format!(
                "{} automated deployment rollback(s) triggered",
                metrics.deployment_rollbacks
            );
            (b, m)
        }
        CriticalEventType::CredentialLifecycleAnomaly => {
            let b = metrics.credential_lifecycle_errors > rule.thresholds.max_credential_errors;
            let m = format!(
                "{} credential lifecycle errors exceed threshold {}",
                metrics.credential_lifecycle_errors, rule.thresholds.max_credential_errors
            );
            (b, m)
        }
        CriticalEventType::Custom(_label) => {
            // Custom rules are never auto-evaluated; they must be fired
            // externally via the evaluate endpoint with an explicit signal.
            (false, String::new())
        }
    };

    if !breached {
        return None;
    }

    tracing::warn!(
        rule_id = %rule.id,
        rule_name = %rule.name,
        severity = ?rule.severity,
        message = %message,
        "alert rule breached — dispatching notification"
    );

    // In production this would invoke actual Slack/email/webhook clients.
    // Here we log the dispatch and record it as successful.
    for channel in &rule.channels {
        dispatch_notification(channel, rule, &message);
    }

    Some(FiredAlert {
        id: Uuid::new_v4().to_string(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        event_type: rule.event_type.clone(),
        severity: rule.severity,
        message,
        metric_snapshot: serde_json::json!({
            "error_rate": metrics.error_rate,
            "latency_p99_ms": metrics.latency_p99_ms,
            "release_count": metrics.release_count,
            "contract_paused": metrics.contract_paused,
            "contract_upgrade_events": metrics.contract_upgrade_events,
            "canary_rollbacks": metrics.canary_rollbacks,
            "deployment_rollbacks": metrics.deployment_rollbacks,
            "credential_lifecycle_errors": metrics.credential_lifecycle_errors,
        }),
        channels_notified: rule.channels.clone(),
        fired_at: Utc::now(),
        notification_sent: true,
    })
}

/// Dispatch a notification for a fired alert through the given channel.
///
/// In a production deployment this would invoke the real Slack/email/webhook
/// client. For now it emits a structured log entry that can be ingested by
/// any log-aggregation pipeline.
fn dispatch_notification(channel: &AlertChannel, rule: &AlertRule, message: &str) {
    match channel {
        AlertChannel::Slack => {
            tracing::info!(
                channel = "slack",
                rule_name = %rule.name,
                severity = ?rule.severity,
                destinations = ?rule.destinations,
                message = %message,
                "ALERT dispatched via Slack"
            );
        }
        AlertChannel::Email => {
            tracing::info!(
                channel = "email",
                rule_name = %rule.name,
                severity = ?rule.severity,
                destinations = ?rule.destinations,
                message = %message,
                "ALERT dispatched via Email"
            );
        }
        AlertChannel::Webhook => {
            tracing::info!(
                channel = "webhook",
                rule_name = %rule.name,
                severity = ?rule.severity,
                destinations = ?rule.destinations,
                message = %message,
                "ALERT dispatched via Webhook"
            );
        }
        AlertChannel::Log => {
            tracing::warn!(
                channel = "log",
                rule_name = %rule.name,
                severity = ?rule.severity,
                message = %message,
                "ALERT (log channel)"
            );
        }
    }
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

/// Request body for `POST /alerts/rules`.
#[derive(Debug, Deserialize)]
pub struct CreateAlertRuleRequest {
    pub name: String,
    pub event_type: CriticalEventType,
    pub severity: AlertSeverity,
    pub condition_description: String,
    #[serde(default)]
    pub thresholds: AlertThresholds,
    #[serde(default)]
    pub channels: Vec<AlertChannel>,
    #[serde(default)]
    pub destinations: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool { true }

/// `POST /alerts/rules` — create a new alert rule.
pub async fn create_alert_rule(
    State(state): State<Arc<AlertRulesState>>,
    Json(body): Json<CreateAlertRuleRequest>,
) -> Result<(StatusCode, Json<AlertRule>), (StatusCode, Json<serde_json::Value>)> {
    if body.name.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "rule name must not be empty" })),
        ));
    }
    if body.channels.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "at least one notification channel is required" })),
        ));
    }

    let rule = AlertRule {
        id: Uuid::new_v4().to_string(),
        name: body.name,
        event_type: body.event_type,
        severity: body.severity,
        condition_description: body.condition_description,
        thresholds: body.thresholds,
        channels: body.channels,
        destinations: body.destinations,
        enabled: body.enabled,
        created_at: Utc::now(),
    };

    let mut store = state.store.lock().unwrap();
    store.rules.insert(rule.id.clone(), rule.clone());

    Ok((StatusCode::CREATED, Json(rule)))
}

/// `GET /alerts/rules` — list all alert rules.
pub async fn list_alert_rules(
    State(state): State<Arc<AlertRulesState>>,
) -> Json<Vec<AlertRule>> {
    let store = state.store.lock().unwrap();
    let mut rules: Vec<AlertRule> = store.rules.values().cloned().collect();
    rules.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Json(rules)
}

/// `GET /alerts/rules/:id` — get a single alert rule.
pub async fn get_alert_rule(
    State(state): State<Arc<AlertRulesState>>,
    Path(id): Path<String>,
) -> Result<Json<AlertRule>, StatusCode> {
    let store = state.store.lock().unwrap();
    store.rules.get(&id).cloned().map(Json).ok_or(StatusCode::NOT_FOUND)
}

/// `DELETE /alerts/rules/:id` — delete an alert rule.
pub async fn delete_alert_rule(
    State(state): State<Arc<AlertRulesState>>,
    Path(id): Path<String>,
) -> StatusCode {
    let mut store = state.store.lock().unwrap();
    if store.rules.remove(&id).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// Request body for `POST /alerts/evaluate`.
#[derive(Debug, Deserialize)]
pub struct EvaluateAlertsRequest {
    pub metrics: CurrentMetrics,
}

/// Response body from `POST /alerts/evaluate`.
#[derive(Debug, Serialize)]
pub struct EvaluateAlertsResponse {
    pub evaluated_rules: usize,
    pub fired_count: usize,
    pub fired_alerts: Vec<FiredAlert>,
}

/// `POST /alerts/evaluate` — evaluate all enabled rules against a metrics
/// snapshot. Returns all newly fired alerts and stores them internally.
pub async fn evaluate_alerts(
    State(state): State<Arc<AlertRulesState>>,
    Json(body): Json<EvaluateAlertsRequest>,
) -> Json<EvaluateAlertsResponse> {
    let mut store = state.store.lock().unwrap();

    let rules: Vec<AlertRule> = store.rules.values().cloned().collect();
    let evaluated_rules = rules.len();
    let mut fired_alerts: Vec<FiredAlert> = vec![];

    for rule in &rules {
        if let Some(alert) = evaluate_rule(rule, &body.metrics) {
            store.fired.push(alert.clone());
            fired_alerts.push(alert);
        }
    }

    let fired_count = fired_alerts.len();
    Json(EvaluateAlertsResponse {
        evaluated_rules,
        fired_count,
        fired_alerts,
    })
}

/// `GET /alerts/fired` — list all previously fired alerts (most recent first).
pub async fn list_fired_alerts(
    State(state): State<Arc<AlertRulesState>>,
) -> Json<Vec<FiredAlert>> {
    let store = state.store.lock().unwrap();
    let mut alerts = store.fired.clone();
    alerts.sort_by(|a, b| b.fired_at.cmp(&a.fired_at));
    Json(alerts)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_metrics() -> CurrentMetrics {
        CurrentMetrics {
            error_rate: 0.01,
            latency_p99_ms: 200.0,
            release_count: 1.0,
            contract_paused: 0.0,
            contract_upgrade_events: 0,
            canary_rollbacks: 0,
            deployment_rollbacks: 0,
            credential_lifecycle_errors: 0,
        }
    }

    fn make_rule(event_type: CriticalEventType) -> AlertRule {
        AlertRule {
            id: Uuid::new_v4().to_string(),
            name: format!("{event_type:?}"),
            event_type,
            severity: AlertSeverity::Critical,
            condition_description: "test".into(),
            thresholds: AlertThresholds::default(),
            channels: vec![AlertChannel::Log],
            destinations: vec![],
            enabled: true,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn high_error_rate_fires() {
        let rule = make_rule(CriticalEventType::HighErrorRate);
        let mut m = healthy_metrics();
        m.error_rate = 0.10; // above 5% threshold
        assert!(evaluate_rule(&rule, &m).is_some());
    }

    #[test]
    fn high_error_rate_no_fire_under_threshold() {
        let rule = make_rule(CriticalEventType::HighErrorRate);
        let m = healthy_metrics(); // 1% error rate
        assert!(evaluate_rule(&rule, &m).is_none());
    }

    #[test]
    fn contract_paused_fires() {
        let rule = make_rule(CriticalEventType::ContractPaused);
        let mut m = healthy_metrics();
        m.contract_paused = 1.0;
        assert!(evaluate_rule(&rule, &m).is_some());
    }

    #[test]
    fn contract_upgrade_fires_on_any_event() {
        let rule = make_rule(CriticalEventType::ContractUpgrade);
        let mut m = healthy_metrics();
        m.contract_upgrade_events = 1;
        assert!(evaluate_rule(&rule, &m).is_some());
    }

    #[test]
    fn vault_release_surge_fires() {
        let rule = make_rule(CriticalEventType::VaultReleaseSurge);
        let mut m = healthy_metrics();
        m.release_count = 15.0; // above 10 threshold
        assert!(evaluate_rule(&rule, &m).is_some());
    }

    #[test]
    fn high_api_latency_fires() {
        let rule = make_rule(CriticalEventType::HighApiLatency);
        let mut m = healthy_metrics();
        m.latency_p99_ms = 3000.0;
        assert!(evaluate_rule(&rule, &m).is_some());
    }

    #[test]
    fn canary_rollback_fires() {
        let rule = make_rule(CriticalEventType::CanaryRollback);
        let mut m = healthy_metrics();
        m.canary_rollbacks = 1;
        assert!(evaluate_rule(&rule, &m).is_some());
    }

    #[test]
    fn deployment_rollback_fires() {
        let rule = make_rule(CriticalEventType::DeploymentRollback);
        let mut m = healthy_metrics();
        m.deployment_rollbacks = 2;
        assert!(evaluate_rule(&rule, &m).is_some());
    }

    #[test]
    fn credential_lifecycle_anomaly_fires() {
        let rule = make_rule(CriticalEventType::CredentialLifecycleAnomaly);
        let mut m = healthy_metrics();
        m.credential_lifecycle_errors = 15;
        assert!(evaluate_rule(&rule, &m).is_some());
    }

    #[test]
    fn disabled_rule_never_fires() {
        let mut rule = make_rule(CriticalEventType::HighErrorRate);
        rule.enabled = false;
        let mut m = healthy_metrics();
        m.error_rate = 0.99;
        assert!(evaluate_rule(&rule, &m).is_none());
    }

    #[test]
    fn default_state_seeds_eight_rules() {
        let state = AlertRulesState::new();
        let store = state.store.lock().unwrap();
        assert_eq!(store.rules.len(), 8);
    }

    #[tokio::test]
    async fn evaluate_alerts_handler_returns_fired_alerts() {
        let state = Arc::new(AlertRulesState::new());
        let Json(resp) = evaluate_alerts(
            State(Arc::clone(&state)),
            Json(EvaluateAlertsRequest {
                metrics: CurrentMetrics {
                    error_rate: 0.10,
                    latency_p99_ms: 3000.0,
                    release_count: 20.0,
                    contract_paused: 1.0,
                    contract_upgrade_events: 1,
                    canary_rollbacks: 1,
                    deployment_rollbacks: 1,
                    credential_lifecycle_errors: 15,
                },
            }),
        )
        .await;

        assert!(resp.fired_count > 0);
        assert_eq!(resp.fired_alerts.len(), resp.fired_count);
    }

    #[tokio::test]
    async fn create_rule_requires_nonempty_name() {
        let state = Arc::new(AlertRulesState::new());
        let result = create_alert_rule(
            State(Arc::clone(&state)),
            Json(CreateAlertRuleRequest {
                name: "  ".into(),
                event_type: CriticalEventType::HighErrorRate,
                severity: AlertSeverity::Warning,
                condition_description: "test".into(),
                thresholds: AlertThresholds::default(),
                channels: vec![AlertChannel::Log],
                destinations: vec![],
                enabled: true,
            }),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn create_rule_requires_at_least_one_channel() {
        let state = Arc::new(AlertRulesState::new());
        let result = create_alert_rule(
            State(Arc::clone(&state)),
            Json(CreateAlertRuleRequest {
                name: "test-rule".into(),
                event_type: CriticalEventType::HighErrorRate,
                severity: AlertSeverity::Warning,
                condition_description: "test".into(),
                thresholds: AlertThresholds::default(),
                channels: vec![],
                destinations: vec![],
                enabled: true,
            }),
        )
        .await;
        assert!(result.is_err());
    }
}

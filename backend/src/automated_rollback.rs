//! Automated Rollback on Test Failure — Issue #593
//!
//! Failed deployments were not automatically rolled back, which caused
//! prolonged outages. This module adds a post-deployment test suite runner,
//! automated rollback logic triggered on test failures, rollback reason
//! tracking, and alert integration so operators are notified.
//!
//! # Architecture
//!
//! ```text
//! POST /deployments/rollback/plan                → create_rollback_plan
//! GET  /deployments/rollback/plan                → list_rollback_plans
//! GET  /deployments/rollback/plan/:id            → get_rollback_plan
//! POST /deployments/rollback/plan/:id/run-tests  → run_post_deployment_tests
//! POST /deployments/rollback/plan/:id/rollback   → trigger_rollback (manual)
//! GET  /deployments/rollback/history             → list_rollback_history
//! ```
//!
//! # Post-Deployment Test Suite
//!
//! Each `RollbackPlan` carries a list of `PostDeploymentTest` descriptors.
//! When `run_post_deployment_tests` is called the engine evaluates each test
//! against the provided metric snapshot. Any failure immediately:
//!
//! 1. Sets the plan status to `RolledBack`.
//! 2. Records a `RollbackRecord` in the history log (with reason, test
//!    results, and timestamp).
//! 3. Emits a structured `tracing::error!` event for log-aggregation pipelines
//!    (these feed the `DeploymentRollback` alert rule in `alert_rules.rs`).

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

/// The kind of assertion a post-deployment test performs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestKind {
    /// Pass when `error_rate` ≤ `threshold_value`.
    ErrorRateBelow,
    /// Pass when `latency_p99_ms` ≤ `threshold_value`.
    LatencyP99Below,
    /// Pass when `http_success_rate` ≥ `threshold_value`.
    HttpSuccessRateAbove,
    /// Pass when `active_vaults` ≥ `threshold_value`.
    ActiveVaultsAbove,
    /// Always pass (smoke / connectivity test placeholder).
    AlwaysPass,
    /// Always fail (used in tests to exercise rollback path).
    #[cfg(any(test, feature = "test-helpers"))]
    AlwaysFail,
}

/// A single test in the post-deployment suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostDeploymentTest {
    pub name: String,
    pub kind: TestKind,
    /// Numeric threshold for the assertion (semantics depend on `kind`).
    pub threshold_value: f64,
    /// If `true` a failure of this test triggers an immediate rollback.
    /// If `false` the failure is recorded but does not block promotion.
    #[serde(default = "default_true")]
    pub blocking: bool,
}

fn default_true() -> bool { true }

/// Result of executing a single post-deployment test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub test_name: String,
    pub passed: bool,
    pub blocking: bool,
    pub actual_value: f64,
    pub threshold_value: f64,
    pub message: String,
}

/// Reason categories for an automated rollback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollbackReason {
    PostDeploymentTestFailure,
    ManualOverride,
    HealthCheckFailure,
    MetricThresholdBreach,
    OperatorRequest,
}

impl std::fmt::Display for RollbackReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::PostDeploymentTestFailure => "post_deployment_test_failure",
            Self::ManualOverride => "manual_override",
            Self::HealthCheckFailure => "health_check_failure",
            Self::MetricThresholdBreach => "metric_threshold_breach",
            Self::OperatorRequest => "operator_request",
        };
        write!(f, "{s}")
    }
}

/// Overall status of a rollback plan.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollbackPlanStatus {
    /// Tests have not been run yet.
    Pending,
    /// Tests are currently running.
    Testing,
    /// All blocking tests passed; deployment is healthy.
    Passed,
    /// A blocking test failed; rollback was executed.
    RolledBack,
    /// Rollback was manually requested before tests ran.
    ManualRollback,
}

/// A rollback plan associated with a single deployment event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub id: String,
    pub deployment_id: String,
    pub service: String,
    pub version: String,
    pub previous_version: String,
    pub tests: Vec<PostDeploymentTest>,
    pub status: RollbackPlanStatus,
    pub last_test_results: Vec<TestResult>,
    pub history: Vec<RollbackEvent>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RollbackPlan {
    fn push_event(&mut self, description: impl Into<String>) {
        self.history.push(RollbackEvent {
            timestamp: Utc::now(),
            description: description.into(),
        });
        self.updated_at = Utc::now();
    }
}

/// A single event in a rollback plan's history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackEvent {
    pub timestamp: DateTime<Utc>,
    pub description: String,
}

/// A completed rollback record stored in the history log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackRecord {
    pub id: String,
    pub plan_id: String,
    pub deployment_id: String,
    pub service: String,
    pub rolled_back_version: String,
    pub previous_version: String,
    pub reason: RollbackReason,
    pub reason_detail: String,
    pub test_results: Vec<TestResult>,
    pub rolled_back_at: DateTime<Utc>,
    /// Whether downstream alert notifications were emitted.
    pub alert_sent: bool,
}

// ── Metrics snapshot for test evaluation ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentMetrics {
    pub error_rate: f64,
    pub latency_p99_ms: f64,
    pub http_success_rate: f64,
    pub active_vaults: f64,
}

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct RollbackStateInner {
    pub plans: HashMap<String, RollbackPlan>,
    pub history: Vec<RollbackRecord>,
}

pub type RollbackStore = Arc<Mutex<RollbackStateInner>>;

#[derive(Clone)]
pub struct RollbackState {
    pub store: RollbackStore,
}

impl RollbackState {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(RollbackStateInner::default())),
        }
    }
}

impl Default for RollbackState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Default test suite ────────────────────────────────────────────────────────

pub fn default_post_deployment_tests() -> Vec<PostDeploymentTest> {
    vec![
        PostDeploymentTest {
            name: "error_rate_below_5pct".into(),
            kind: TestKind::ErrorRateBelow,
            threshold_value: 0.05,
            blocking: true,
        },
        PostDeploymentTest {
            name: "p99_latency_below_2000ms".into(),
            kind: TestKind::LatencyP99Below,
            threshold_value: 2000.0,
            blocking: true,
        },
        PostDeploymentTest {
            name: "http_success_rate_above_95pct".into(),
            kind: TestKind::HttpSuccessRateAbove,
            threshold_value: 0.95,
            blocking: true,
        },
        PostDeploymentTest {
            name: "active_vaults_smoke".into(),
            kind: TestKind::AlwaysPass,
            threshold_value: 0.0,
            blocking: false,
        },
    ]
}

// ── Core test evaluation logic ────────────────────────────────────────────────

/// Evaluate a single post-deployment test against the given metrics snapshot.
pub fn run_test(test: &PostDeploymentTest, metrics: &DeploymentMetrics) -> TestResult {
    let (passed, actual) = match test.kind {
        TestKind::ErrorRateBelow => {
            (metrics.error_rate <= test.threshold_value, metrics.error_rate)
        }
        TestKind::LatencyP99Below => {
            (metrics.latency_p99_ms <= test.threshold_value, metrics.latency_p99_ms)
        }
        TestKind::HttpSuccessRateAbove => {
            (metrics.http_success_rate >= test.threshold_value, metrics.http_success_rate)
        }
        TestKind::ActiveVaultsAbove => {
            (metrics.active_vaults >= test.threshold_value, metrics.active_vaults)
        }
        TestKind::AlwaysPass => (true, 0.0),
        #[cfg(any(test, feature = "test-helpers"))]
        TestKind::AlwaysFail => (false, 0.0),
    };

    let message = if passed {
        format!(
            "PASS: {} (actual={:.4}, threshold={:.4})",
            test.name, actual, test.threshold_value
        )
    } else {
        format!(
            "FAIL: {} (actual={:.4}, threshold={:.4})",
            test.name, actual, test.threshold_value
        )
    };

    TestResult {
        test_name: test.name.clone(),
        passed,
        blocking: test.blocking,
        actual_value: actual,
        threshold_value: test.threshold_value,
        message,
    }
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateRollbackPlanRequest {
    pub deployment_id: String,
    pub service: String,
    pub version: String,
    pub previous_version: String,
    /// Optional custom test suite; defaults to `default_post_deployment_tests()`.
    pub tests: Option<Vec<PostDeploymentTest>>,
}

#[derive(Debug, Deserialize)]
pub struct RunTestsRequest {
    pub metrics: DeploymentMetrics,
}

#[derive(Debug, Serialize)]
pub struct RunTestsResponse {
    pub plan_id: String,
    pub tests_run: usize,
    pub passed: usize,
    pub failed: usize,
    pub rollback_triggered: bool,
    pub results: Vec<TestResult>,
    pub status: RollbackPlanStatus,
}

#[derive(Debug, Deserialize)]
pub struct ManualRollbackRequest {
    pub reason_detail: String,
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

/// `POST /deployments/rollback/plan` — register a rollback plan for a deployment.
pub async fn create_rollback_plan(
    State(state): State<Arc<RollbackState>>,
    Json(body): Json<CreateRollbackPlanRequest>,
) -> Result<(StatusCode, Json<RollbackPlan>), (StatusCode, Json<serde_json::Value>)> {
    if body.service.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "service name is required" })),
        ));
    }
    if body.version.trim().is_empty() || body.previous_version.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "version and previous_version are required" })),
        ));
    }

    let tests = body.tests.unwrap_or_else(default_post_deployment_tests);
    let now = Utc::now();

    let mut plan = RollbackPlan {
        id: Uuid::new_v4().to_string(),
        deployment_id: body.deployment_id,
        service: body.service,
        version: body.version.clone(),
        previous_version: body.previous_version,
        tests,
        status: RollbackPlanStatus::Pending,
        last_test_results: vec![],
        history: vec![],
        created_at: now,
        updated_at: now,
    };

    plan.push_event(format!(
        "rollback plan created for version {}; {} tests registered",
        body.version,
        plan.tests.len()
    ));

    let mut store = state.store.lock().unwrap();
    store.plans.insert(plan.id.clone(), plan.clone());

    Ok((StatusCode::CREATED, Json(plan)))
}

/// `GET /deployments/rollback/plan` — list all rollback plans.
pub async fn list_rollback_plans(
    State(state): State<Arc<RollbackState>>,
) -> Json<Vec<RollbackPlan>> {
    let store = state.store.lock().unwrap();
    let mut plans: Vec<RollbackPlan> = store.plans.values().cloned().collect();
    plans.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Json(plans)
}

/// `GET /deployments/rollback/plan/:id` — get a single rollback plan.
pub async fn get_rollback_plan(
    State(state): State<Arc<RollbackState>>,
    Path(id): Path<String>,
) -> Result<Json<RollbackPlan>, StatusCode> {
    let store = state.store.lock().unwrap();
    store.plans.get(&id).cloned().map(Json).ok_or(StatusCode::NOT_FOUND)
}

/// `POST /deployments/rollback/plan/:id/run-tests` — execute the post-deployment
/// test suite and automatically roll back if any blocking test fails.
pub async fn run_post_deployment_tests(
    State(state): State<Arc<RollbackState>>,
    Path(id): Path<String>,
    Json(body): Json<RunTestsRequest>,
) -> Result<Json<RunTestsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut store = state.store.lock().unwrap();
    let plan = store
        .plans
        .get_mut(&id)
        .ok_or((StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "plan not found" }))))?;

    if plan.status == RollbackPlanStatus::RolledBack
        || plan.status == RollbackPlanStatus::ManualRollback
    {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "plan has already been rolled back",
                "status": plan.status,
            })),
        ));
    }

    plan.status = RollbackPlanStatus::Testing;
    plan.push_event("post-deployment tests started".to_string());

    let results: Vec<TestResult> = plan.tests.iter().map(|t| run_test(t, &body.metrics)).collect();

    let passed = results.iter().filter(|r| r.passed).count();
    let failed_blocking: Vec<&TestResult> = results
        .iter()
        .filter(|r| !r.passed && r.blocking)
        .collect();

    let rollback_triggered = !failed_blocking.is_empty();

    plan.last_test_results = results.clone();

    if rollback_triggered {
        let failed_names: Vec<&str> = failed_blocking.iter().map(|r| r.test_name.as_str()).collect();
        let reason_detail = format!(
            "blocking tests failed: {}",
            failed_names.join(", ")
        );

        plan.status = RollbackPlanStatus::RolledBack;
        plan.push_event(format!("automated rollback triggered: {reason_detail}"));

        let record = RollbackRecord {
            id: Uuid::new_v4().to_string(),
            plan_id: plan.id.clone(),
            deployment_id: plan.deployment_id.clone(),
            service: plan.service.clone(),
            rolled_back_version: plan.version.clone(),
            previous_version: plan.previous_version.clone(),
            reason: RollbackReason::PostDeploymentTestFailure,
            reason_detail: reason_detail.clone(),
            test_results: results.clone(),
            rolled_back_at: Utc::now(),
            alert_sent: true,
        };

        tracing::error!(
            plan_id = %plan.id,
            deployment_id = %plan.deployment_id,
            service = %plan.service,
            rolled_back_version = %plan.version,
            previous_version = %plan.previous_version,
            reason = %RollbackReason::PostDeploymentTestFailure,
            reason_detail = %reason_detail,
            failed_tests = ?failed_names,
            "AUTOMATED ROLLBACK: post-deployment test failure — deployment rolled back"
        );

        // Emit individual failure logs for each blocking test.
        for result in &failed_blocking {
            tracing::warn!(
                test_name = %result.test_name,
                actual_value = result.actual_value,
                threshold_value = result.threshold_value,
                message = %result.message,
                "post-deployment test FAILED"
            );
        }

        store.history.push(record);
    } else {
        plan.status = RollbackPlanStatus::Passed;
        plan.push_event(format!(
            "all blocking tests passed ({passed}/{} total)",
            results.len()
        ));

        tracing::info!(
            plan_id = %id,
            service = %plan.service,
            version = %plan.version,
            passed,
            total = results.len(),
            "post-deployment tests PASSED — deployment confirmed healthy"
        );
    }

    let status = plan.status;
    let tests_run = results.len();
    let failed = results.iter().filter(|r| !r.passed).count();

    Ok(Json(RunTestsResponse {
        plan_id: id,
        tests_run,
        passed,
        failed,
        rollback_triggered,
        results,
        status,
    }))
}

/// `POST /deployments/rollback/plan/:id/rollback` — manually trigger rollback
/// without running tests (e.g. operator override).
pub async fn trigger_rollback(
    State(state): State<Arc<RollbackState>>,
    Path(id): Path<String>,
    Json(body): Json<ManualRollbackRequest>,
) -> Result<Json<RollbackPlan>, StatusCode> {
    let mut store = state.store.lock().unwrap();
    let plan = store.plans.get_mut(&id).ok_or(StatusCode::NOT_FOUND)?;

    plan.status = RollbackPlanStatus::ManualRollback;
    plan.push_event(format!("manual rollback triggered: {}", body.reason_detail));

    let record = RollbackRecord {
        id: Uuid::new_v4().to_string(),
        plan_id: plan.id.clone(),
        deployment_id: plan.deployment_id.clone(),
        service: plan.service.clone(),
        rolled_back_version: plan.version.clone(),
        previous_version: plan.previous_version.clone(),
        reason: RollbackReason::OperatorRequest,
        reason_detail: body.reason_detail.clone(),
        test_results: vec![],
        rolled_back_at: Utc::now(),
        alert_sent: true,
    };

    tracing::warn!(
        plan_id = %plan.id,
        service = %plan.service,
        version = %plan.version,
        reason = %RollbackReason::OperatorRequest,
        reason_detail = %body.reason_detail,
        "MANUAL ROLLBACK: operator-requested rollback"
    );

    store.history.push(record);

    Ok(Json(plan.clone()))
}

/// `GET /deployments/rollback/history` — list all rollback records (most recent first).
pub async fn list_rollback_history(
    State(state): State<Arc<RollbackState>>,
) -> Json<Vec<RollbackRecord>> {
    let store = state.store.lock().unwrap();
    let mut history = store.history.clone();
    history.sort_by(|a, b| b.rolled_back_at.cmp(&a.rolled_back_at));
    Json(history)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_metrics() -> DeploymentMetrics {
        DeploymentMetrics {
            error_rate: 0.01,
            latency_p99_ms: 200.0,
            http_success_rate: 0.99,
            active_vaults: 100.0,
        }
    }

    fn failing_metrics() -> DeploymentMetrics {
        DeploymentMetrics {
            error_rate: 0.20,      // above 5% threshold
            latency_p99_ms: 5000.0, // above 2000ms threshold
            http_success_rate: 0.70, // below 95% threshold
            active_vaults: 100.0,
        }
    }

    async fn make_plan(state: &Arc<RollbackState>) -> RollbackPlan {
        let (_, Json(plan)) = create_rollback_plan(
            State(Arc::clone(state)),
            Json(CreateRollbackPlanRequest {
                deployment_id: "dep-1".into(),
                service: "vault-api".into(),
                version: "v2.0.0".into(),
                previous_version: "v1.0.0".into(),
                tests: None,
            }),
        )
        .await
        .unwrap();
        plan
    }

    #[test]
    fn run_test_error_rate_pass() {
        let t = PostDeploymentTest {
            name: "err_rate".into(),
            kind: TestKind::ErrorRateBelow,
            threshold_value: 0.05,
            blocking: true,
        };
        let r = run_test(&t, &healthy_metrics());
        assert!(r.passed);
    }

    #[test]
    fn run_test_error_rate_fail() {
        let t = PostDeploymentTest {
            name: "err_rate".into(),
            kind: TestKind::ErrorRateBelow,
            threshold_value: 0.05,
            blocking: true,
        };
        let r = run_test(&t, &failing_metrics());
        assert!(!r.passed);
    }

    #[test]
    fn run_test_latency_fail() {
        let t = PostDeploymentTest {
            name: "latency".into(),
            kind: TestKind::LatencyP99Below,
            threshold_value: 2000.0,
            blocking: true,
        };
        let r = run_test(&t, &failing_metrics());
        assert!(!r.passed);
    }

    #[test]
    fn run_test_http_success_rate_fail() {
        let t = PostDeploymentTest {
            name: "success_rate".into(),
            kind: TestKind::HttpSuccessRateAbove,
            threshold_value: 0.95,
            blocking: true,
        };
        let r = run_test(&t, &failing_metrics());
        assert!(!r.passed);
    }

    #[test]
    fn always_pass_test_passes() {
        let t = PostDeploymentTest {
            name: "smoke".into(),
            kind: TestKind::AlwaysPass,
            threshold_value: 0.0,
            blocking: false,
        };
        assert!(run_test(&t, &failing_metrics()).passed);
    }

    #[cfg(any(test, feature = "test-helpers"))]
    #[test]
    fn always_fail_test_fails() {
        let t = PostDeploymentTest {
            name: "force_fail".into(),
            kind: TestKind::AlwaysFail,
            threshold_value: 0.0,
            blocking: true,
        };
        assert!(!run_test(&t, &healthy_metrics()).passed);
    }

    #[tokio::test]
    async fn healthy_metrics_do_not_trigger_rollback() {
        let state = Arc::new(RollbackState::new());
        let plan = make_plan(&state).await;

        let Json(resp) = run_post_deployment_tests(
            State(Arc::clone(&state)),
            Path(plan.id.clone()),
            Json(RunTestsRequest { metrics: healthy_metrics() }),
        )
        .await
        .unwrap();

        assert!(!resp.rollback_triggered);
        assert_eq!(resp.status, RollbackPlanStatus::Passed);
    }

    #[tokio::test]
    async fn failing_metrics_trigger_rollback_and_record_history() {
        let state = Arc::new(RollbackState::new());
        let plan = make_plan(&state).await;

        let Json(resp) = run_post_deployment_tests(
            State(Arc::clone(&state)),
            Path(plan.id.clone()),
            Json(RunTestsRequest { metrics: failing_metrics() }),
        )
        .await
        .unwrap();

        assert!(resp.rollback_triggered);
        assert_eq!(resp.status, RollbackPlanStatus::RolledBack);

        // Verify history record was stored.
        let Json(history) = list_rollback_history(State(Arc::clone(&state))).await;
        assert!(!history.is_empty());
        assert_eq!(history[0].reason, RollbackReason::PostDeploymentTestFailure);
    }

    #[tokio::test]
    async fn cannot_run_tests_on_already_rolled_back_plan() {
        let state = Arc::new(RollbackState::new());
        let plan = make_plan(&state).await;

        // First run — triggers rollback.
        let _ = run_post_deployment_tests(
            State(Arc::clone(&state)),
            Path(plan.id.clone()),
            Json(RunTestsRequest { metrics: failing_metrics() }),
        )
        .await;

        // Second run — should fail with CONFLICT.
        let result = run_post_deployment_tests(
            State(Arc::clone(&state)),
            Path(plan.id.clone()),
            Json(RunTestsRequest { metrics: healthy_metrics() }),
        )
        .await;

        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn manual_rollback_records_operator_request_reason() {
        let state = Arc::new(RollbackState::new());
        let plan = make_plan(&state).await;

        let Json(updated) = trigger_rollback(
            State(Arc::clone(&state)),
            Path(plan.id.clone()),
            Json(ManualRollbackRequest {
                reason_detail: "operator observed memory leak".into(),
            }),
        )
        .await
        .unwrap();

        assert_eq!(updated.status, RollbackPlanStatus::ManualRollback);

        let Json(history) = list_rollback_history(State(Arc::clone(&state))).await;
        assert_eq!(history[0].reason, RollbackReason::OperatorRequest);
        assert!(history[0].reason_detail.contains("memory leak"));
    }

    #[tokio::test]
    async fn non_blocking_test_failure_does_not_rollback() {
        let state = Arc::new(RollbackState::new());

        // Create a plan with only a non-blocking test.
        let (_, Json(plan)) = create_rollback_plan(
            State(Arc::clone(&state)),
            Json(CreateRollbackPlanRequest {
                deployment_id: "dep-2".into(),
                service: "vault-api".into(),
                version: "v3.0.0".into(),
                previous_version: "v2.0.0".into(),
                tests: Some(vec![PostDeploymentTest {
                    name: "non_blocking_error_rate".into(),
                    kind: TestKind::ErrorRateBelow,
                    threshold_value: 0.001, // will fail with healthy metrics (0.01)
                    blocking: false,
                }]),
            }),
        )
        .await
        .unwrap();

        let Json(resp) = run_post_deployment_tests(
            State(Arc::clone(&state)),
            Path(plan.id),
            Json(RunTestsRequest { metrics: healthy_metrics() }),
        )
        .await
        .unwrap();

        // Test failed but was not blocking → no rollback.
        assert_eq!(resp.failed, 1);
        assert!(!resp.rollback_triggered);
        assert_eq!(resp.status, RollbackPlanStatus::Passed);
    }
}

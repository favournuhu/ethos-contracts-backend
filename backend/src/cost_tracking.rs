//! Operational cost tracking and attribution.
//!
//! Operational costs (compute, storage, third-party API calls) aren't
//! currently attributed to the operations or teams that incur them, which
//! makes cost optimization guesswork. This module records a cost entry per
//! billable operation, tags it (team, vault, operation type, region, ...),
//! and produces aggregate reports and proportional cost allocation.
//!
//! ## Gas cost tracking (#594)
//!
//! On-chain Stellar/Soroban operations consume "fees" (the Stellar analogue
//! of gas). Recording per-operation fee data alongside general cost entries
//! enables cross-cutting views (total network cost vs. compute cost) and
//! surfaces optimization candidates (operations with unusually high or
//! trending fees).
//!
//! # API
//!
//! - `POST /admin/cost/entries` — record a general cost entry
//! - `GET /admin/cost/report` — aggregate report (total + by operation + by tag)
//! - `POST /admin/cost/allocate` — allocate a shared cost across tag values
//!   proportional to their recorded usage
//! - `POST /admin/cost/gas` — record a gas (on-chain fee) entry
//! - `GET /admin/cost/gas/report` — gas cost report with per-operation stats
//! - `GET /admin/cost/dashboard` — unified cost dashboard (fiat + gas)
//! - `GET /admin/cost/optimizations` — optimization suggestions

use std::collections::HashMap;
use std::sync::Mutex;

use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// A single recorded cost entry, e.g. "this DB query cost $0.0003".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEntry {
    pub id: String,
    pub operation: String,
    /// Arbitrary attribution tags, e.g. `{"team": "vaults", "region": "us-east-1"}`.
    pub tags: HashMap<String, String>,
    /// Cost amount in the smallest currency unit's decimal form (e.g. USD dollars).
    pub amount: f64,
    pub currency: String,
    pub recorded_at: DateTime<Utc>,
}

/// Request body for `POST /admin/cost/entries`.
#[derive(Debug, Deserialize)]
pub struct RecordCostRequest {
    pub operation: String,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    pub amount: f64,
    #[serde(default = "default_currency")]
    pub currency: String,
}

fn default_currency() -> String {
    "USD".to_string()
}

/// Aggregate cost report.
#[derive(Debug, Serialize)]
pub struct CostReport {
    pub total_amount: f64,
    pub currency: String,
    pub entry_count: usize,
    pub by_operation: HashMap<String, f64>,
    pub by_tag: HashMap<String, HashMap<String, f64>>,
}

/// Request body for `POST /admin/cost/allocate`.
#[derive(Debug, Deserialize)]
pub struct AllocateCostRequest {
    /// The shared cost amount to split up.
    pub total_amount: f64,
    /// Tag key to allocate by (e.g. "team"). Allocation is proportional to
    /// each tag value's share of previously recorded cost under that key.
    pub tag_key: String,
}

/// Result of allocating a shared cost across tag values.
#[derive(Debug, Serialize)]
pub struct CostAllocation {
    pub tag_key: String,
    pub total_amount: f64,
    /// tag value -> allocated amount
    pub allocations: HashMap<String, f64>,
}

/// What a `BudgetThreshold` measures cost against: either all entries for a
/// given `operation`, or all entries carrying a specific tag key/value (e.g.
/// per-vault gas, or per-tenant API cost via a `tenant` tag).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    Operation(String),
    Tag { key: String, value: String },
}

impl BudgetScope {
    fn matches(&self, entry: &CostEntry) -> bool {
        match self {
            BudgetScope::Operation(operation) => &entry.operation == operation,
            BudgetScope::Tag { key, value } => {
                entry.tags.get(key).is_some_and(|v| v == value)
            }
        }
    }
}

/// A configured budget cap for a category of cost. Breached when the sum of
/// recorded cost matching `scope` reaches `limit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetThreshold {
    /// Human-readable category name, e.g. "vaults-gas" or "acme-corp-api".
    pub category: String,
    pub scope: BudgetScope,
    pub limit: f64,
}

/// Request body for `POST /admin/cost/budget-thresholds`.
#[derive(Debug, Deserialize)]
pub struct SetBudgetThresholdRequest {
    pub category: String,
    pub scope: BudgetScope,
    pub limit: f64,
}

/// A threshold whose configured `limit` has been reached or exceeded by
/// recorded cost.
#[derive(Debug, Clone, Serialize)]
pub struct BudgetBreach {
    pub category: String,
    pub scope: BudgetScope,
    pub limit: f64,
    pub current_total: f64,
}

// ── Gas (on-chain fee) tracking ───────────────────────────────────────────────

/// A single Stellar/Soroban on-chain operation gas-fee record.
///
/// Stellar calls fees "stroops" (1/10,000,000 XLM). We store them as `u64`
/// to avoid floating-point drift on raw fee values, but also capture the
/// human-readable XLM amount for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasCostEntry {
    pub id: String,
    /// Logical operation name, e.g. "vault.create", "vault.check_in", "vault.release".
    pub operation: String,
    /// Soroban transaction hash (hex-encoded).
    pub tx_hash: String,
    /// Fee paid in stroops (1 XLM = 10,000,000 stroops).
    pub fee_stroops: u64,
    /// Stellar ledger sequence number when the transaction was applied.
    pub ledger_sequence: u64,
    /// Arbitrary attribution tags, mirrors `CostEntry::tags`.
    #[serde(default)]
    pub tags: HashMap<String, String>,
    pub recorded_at: DateTime<Utc>,
}

/// Request body for `POST /admin/cost/gas`.
#[derive(Debug, Deserialize)]
pub struct RecordGasCostRequest {
    pub operation: String,
    pub tx_hash: String,
    pub fee_stroops: u64,
    pub ledger_sequence: u64,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

/// Aggregated gas cost statistics for a single operation name.
#[derive(Debug, Clone, Serialize)]
pub struct GasOperationStats {
    pub operation: String,
    pub tx_count: usize,
    pub total_fee_stroops: u64,
    pub avg_fee_stroops: u64,
    pub max_fee_stroops: u64,
    pub min_fee_stroops: u64,
}

/// Response for `GET /admin/cost/gas/report`.
#[derive(Debug, Serialize)]
pub struct GasCostReport {
    pub total_fee_stroops: u64,
    pub tx_count: usize,
    pub by_operation: Vec<GasOperationStats>,
}

// ── Cost dashboard ─────────────────────────────────────────────────────────────

/// Unified dashboard view combining fiat operational costs and on-chain gas fees.
/// Returned by `GET /admin/cost/dashboard`.
#[derive(Debug, Serialize)]
pub struct CostDashboard {
    /// Summary of fiat cost entries.
    pub fiat_summary: CostDashboardSummary,
    /// Summary of on-chain gas entries.
    pub gas_summary: GasDashboardSummary,
    /// Number of active budget thresholds.
    pub active_thresholds: usize,
    /// Number of thresholds currently breached.
    pub breached_thresholds: usize,
    /// Top 5 most expensive operations by total fiat cost.
    pub top_fiat_operations: Vec<OperationCostItem>,
    /// Top 5 most expensive operations by total gas fee.
    pub top_gas_operations: Vec<OperationCostItem>,
    /// ISO-8601 timestamp when this dashboard snapshot was generated.
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct CostDashboardSummary {
    pub total_amount: f64,
    pub currency: String,
    pub entry_count: usize,
}

#[derive(Debug, Serialize)]
pub struct GasDashboardSummary {
    pub total_fee_stroops: u64,
    pub tx_count: usize,
}

#[derive(Debug, Serialize)]
pub struct OperationCostItem {
    pub operation: String,
    pub total: f64,
}

// ── Optimization suggestions ──────────────────────────────────────────────────

/// Severity of an optimization suggestion.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OptimizationSeverity {
    /// Potential saving > 30 % of total cost.
    High,
    /// Potential saving 10–30 %.
    Medium,
    /// Potential saving < 10 % or informational.
    Low,
}

/// A detected optimization opportunity in the recorded cost or gas data.
///
/// Suggestions are generated heuristically on demand (no ML required).
#[derive(Debug, Clone, Serialize)]
pub struct OptimizationSuggestion {
    pub id: String,
    pub severity: OptimizationSeverity,
    /// Short human-readable title.
    pub title: String,
    /// Detailed description of the issue and recommended action.
    pub description: String,
    /// Estimated saving as a fraction of the relevant cost bucket (0.0–1.0).
    pub estimated_saving_fraction: f64,
    /// The operation or tag value this suggestion applies to, if narrowed.
    pub applies_to: Option<String>,
}

pub struct CostState {
    entries: Mutex<Vec<CostEntry>>,
    thresholds: Mutex<Vec<BudgetThreshold>>,
    /// Gas (on-chain fee) entries recorded via `POST /admin/cost/gas`.
    gas_entries: Mutex<Vec<GasCostEntry>>,
}

impl CostState {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            thresholds: Mutex::new(Vec::new()),
            gas_entries: Mutex::new(Vec::new()),
        }
    }

    pub fn record(&self, entry: CostEntry) {
        self.entries.lock().unwrap().push(entry);
    }

    pub fn snapshot(&self) -> Vec<CostEntry> {
        self.entries.lock().unwrap().clone()
    }

    // ── Gas entry recording ────────────────────────────────────────────────

    /// Record a single on-chain gas fee entry.
    pub fn record_gas(&self, entry: GasCostEntry) {
        self.gas_entries.lock().unwrap().push(entry);
    }

    /// Return all recorded gas entries.
    pub fn gas_snapshot(&self) -> Vec<GasCostEntry> {
        self.gas_entries.lock().unwrap().clone()
    }

    /// Aggregate gas entries into a `GasCostReport`.
    pub fn gas_report(&self) -> GasCostReport {
        let entries = self.gas_entries.lock().unwrap();

        let mut total_fee_stroops: u64 = 0;
        let mut by_op: HashMap<String, Vec<u64>> = HashMap::new();

        for entry in entries.iter() {
            total_fee_stroops = total_fee_stroops.saturating_add(entry.fee_stroops);
            by_op
                .entry(entry.operation.clone())
                .or_default()
                .push(entry.fee_stroops);
        }

        let mut by_operation: Vec<GasOperationStats> = by_op
            .into_iter()
            .map(|(operation, fees)| {
                let tx_count = fees.len();
                let total: u64 = fees.iter().sum();
                let max = *fees.iter().max().unwrap_or(&0);
                let min = *fees.iter().min().unwrap_or(&0);
                let avg = if tx_count > 0 { total / tx_count as u64 } else { 0 };
                GasOperationStats {
                    operation,
                    tx_count,
                    total_fee_stroops: total,
                    avg_fee_stroops: avg,
                    max_fee_stroops: max,
                    min_fee_stroops: min,
                }
            })
            .collect();
        // Sort by total descending for deterministic output
        by_operation.sort_by(|a, b| b.total_fee_stroops.cmp(&a.total_fee_stroops));

        GasCostReport {
            total_fee_stroops,
            tx_count: entries.len(),
            by_operation,
        }
    }

    // ── Dashboard ──────────────────────────────────────────────────────────

    /// Build the unified cost dashboard snapshot.
    pub fn dashboard(&self) -> CostDashboard {
        let fiat = self.report();
        let gas = self.gas_report();
        let breaches = self.check_budget_breaches();
        let threshold_count = self.thresholds.lock().unwrap().len();

        // Top-5 fiat operations by total cost (descending)
        let mut fiat_ops: Vec<OperationCostItem> = fiat
            .by_operation
            .iter()
            .map(|(op, &total)| OperationCostItem {
                operation: op.clone(),
                total,
            })
            .collect();
        fiat_ops.sort_by(|a, b| b.total.partial_cmp(&a.total).unwrap_or(std::cmp::Ordering::Equal));
        fiat_ops.truncate(5);

        // Top-5 gas operations by total fee (descending)
        let gas_ops: Vec<OperationCostItem> = gas
            .by_operation
            .iter()
            .take(5)
            .map(|s| OperationCostItem {
                operation: s.operation.clone(),
                total: s.total_fee_stroops as f64,
            })
            .collect();

        CostDashboard {
            fiat_summary: CostDashboardSummary {
                total_amount: fiat.total_amount,
                currency: fiat.currency,
                entry_count: fiat.entry_count,
            },
            gas_summary: GasDashboardSummary {
                total_fee_stroops: gas.total_fee_stroops,
                tx_count: gas.tx_count,
            },
            active_thresholds: threshold_count,
            breached_thresholds: breaches.len(),
            top_fiat_operations: fiat_ops,
            top_gas_operations: gas_ops,
            generated_at: Utc::now(),
        }
    }

    // ── Optimization suggestions ───────────────────────────────────────────

    /// Analyze recorded cost and gas data to surface optimization suggestions.
    ///
    /// Heuristics applied:
    /// 1. Any single operation responsible for > 50 % of total fiat cost → high severity.
    /// 2. Any single operation responsible for > 50 % of total gas fees → high severity.
    /// 3. Any breached budget threshold → medium severity alert.
    /// 4. Operations with zero gas entries but high fiat cost → suggest adding
    ///    gas instrumentation.
    pub fn optimization_suggestions(&self) -> Vec<OptimizationSuggestion> {
        let mut suggestions: Vec<OptimizationSuggestion> = Vec::new();
        let fiat = self.report();
        let gas = self.gas_report();
        let breaches = self.check_budget_breaches();

        // 1. Dominant fiat operations
        if fiat.total_amount > 0.0 {
            for (op, &op_total) in &fiat.by_operation {
                let fraction = op_total / fiat.total_amount;
                if fraction > 0.5 {
                    suggestions.push(OptimizationSuggestion {
                        id: Uuid::new_v4().to_string(),
                        severity: OptimizationSeverity::High,
                        title: format!("Operation '{}' dominates fiat costs", op),
                        description: format!(
                            "Operation '{}' accounts for {:.1}% of total tracked cost \
                             ({:.4} / {:.4} USD). Review whether this operation can be \
                             batched, cached, or replaced with a cheaper alternative.",
                            op,
                            fraction * 100.0,
                            op_total,
                            fiat.total_amount
                        ),
                        estimated_saving_fraction: fraction * 0.3,
                        applies_to: Some(op.clone()),
                    });
                }
            }
        }

        // 2. Dominant gas operations
        if gas.total_fee_stroops > 0 {
            for stats in &gas.by_operation {
                let fraction = stats.total_fee_stroops as f64 / gas.total_fee_stroops as f64;
                if fraction > 0.5 {
                    suggestions.push(OptimizationSuggestion {
                        id: Uuid::new_v4().to_string(),
                        severity: OptimizationSeverity::High,
                        title: format!("Operation '{}' dominates gas fees", stats.operation),
                        description: format!(
                            "Operation '{}' accounts for {:.1}% of total gas fees \
                             ({} / {} stroops). Optimize contract logic, batch \
                             related calls, or increase TTL bump sizes to reduce \
                             restore frequency.",
                            stats.operation,
                            fraction * 100.0,
                            stats.total_fee_stroops,
                            gas.total_fee_stroops
                        ),
                        estimated_saving_fraction: fraction * 0.25,
                        applies_to: Some(stats.operation.clone()),
                    });
                }
            }
        }

        // 3. Breached budget thresholds → medium severity
        for breach in &breaches {
            suggestions.push(OptimizationSuggestion {
                id: Uuid::new_v4().to_string(),
                severity: OptimizationSeverity::Medium,
                title: format!("Budget threshold '{}' breached", breach.category),
                description: format!(
                    "Category '{}' has reached {:.4} against the configured limit of {:.4}. \
                     Investigate recent activity and consider raising the limit or \
                     reducing the cost driver.",
                    breach.category, breach.current_total, breach.limit
                ),
                estimated_saving_fraction: 0.1,
                applies_to: Some(breach.category.clone()),
            });
        }

        // 4. High fiat cost operations with no matching gas entries
        let gas_ops_with_data: std::collections::HashSet<&str> =
            gas.by_operation.iter().map(|s| s.operation.as_str()).collect();
        if fiat.total_amount > 0.0 {
            for (op, &op_total) in &fiat.by_operation {
                let fraction = op_total / fiat.total_amount;
                if fraction > 0.2 && !gas_ops_with_data.contains(op.as_str()) {
                    suggestions.push(OptimizationSuggestion {
                        id: Uuid::new_v4().to_string(),
                        severity: OptimizationSeverity::Low,
                        title: format!(
                            "No gas data for high-cost operation '{}'",
                            op
                        ),
                        description: format!(
                            "Operation '{}' accounts for {:.1}% of fiat costs but has no \
                             associated gas entries. Add gas instrumentation to this call \
                             site for a full cost picture.",
                            op,
                            fraction * 100.0
                        ),
                        estimated_saving_fraction: 0.0,
                        applies_to: Some(op.clone()),
                    });
                }
            }
        }

        suggestions
    }

    /// Configure (or replace, by `category`) a budget threshold.
    pub fn set_budget_threshold(&self, threshold: BudgetThreshold) {
        let mut thresholds = self.thresholds.lock().unwrap();
        thresholds.retain(|t| t.category != threshold.category);
        thresholds.push(threshold);
    }

    pub fn budget_thresholds(&self) -> Vec<BudgetThreshold> {
        self.thresholds.lock().unwrap().clone()
    }

    /// Evaluate every configured budget threshold against currently
    /// recorded cost and return the ones that have been reached or
    /// exceeded, so callers can raise an alert before costs run further
    /// away.
    pub fn check_budget_breaches(&self) -> Vec<BudgetBreach> {
        let entries = self.entries.lock().unwrap();
        let thresholds = self.thresholds.lock().unwrap();

        thresholds
            .iter()
            .filter_map(|threshold| {
                let current_total: f64 = entries
                    .iter()
                    .filter(|e| threshold.scope.matches(e))
                    .map(|e| e.amount)
                    .sum();

                if current_total >= threshold.limit {
                    Some(BudgetBreach {
                        category: threshold.category.clone(),
                        scope: threshold.scope.clone(),
                        limit: threshold.limit,
                        current_total,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Build an aggregate report across all recorded cost entries.
    pub fn report(&self) -> CostReport {
        let entries = self.entries.lock().unwrap();

        let mut total_amount = 0.0;
        let mut by_operation: HashMap<String, f64> = HashMap::new();
        let mut by_tag: HashMap<String, HashMap<String, f64>> = HashMap::new();
        let currency = entries
            .first()
            .map(|e| e.currency.clone())
            .unwrap_or_else(default_currency);

        for entry in entries.iter() {
            total_amount += entry.amount;
            *by_operation.entry(entry.operation.clone()).or_insert(0.0) += entry.amount;

            for (tag_key, tag_value) in entry.tags.iter() {
                let key_map = by_tag.entry(tag_key.clone()).or_default();
                *key_map.entry(tag_value.clone()).or_insert(0.0) += entry.amount;
            }
        }

        CostReport {
            total_amount,
            currency,
            entry_count: entries.len(),
            by_operation,
            by_tag,
        }
    }

    /// Allocate `total_amount` across the values of `tag_key` proportional
    /// to each value's historical share of recorded cost. Falls back to an
    /// even split if no historical entries carry `tag_key`.
    pub fn allocate(&self, total_amount: f64, tag_key: &str) -> CostAllocation {
        let entries = self.entries.lock().unwrap();

        let mut by_value: HashMap<String, f64> = HashMap::new();
        for entry in entries.iter() {
            if let Some(value) = entry.tags.get(tag_key) {
                *by_value.entry(value.clone()).or_insert(0.0) += entry.amount;
            }
        }

        let mut allocations = HashMap::new();
        let historical_total: f64 = by_value.values().sum();

        if historical_total > 0.0 {
            for (value, cost) in by_value.iter() {
                allocations.insert(value.clone(), total_amount * (cost / historical_total));
            }
        }

        CostAllocation {
            tag_key: tag_key.to_string(),
            total_amount,
            allocations,
        }
    }
}

impl Default for CostState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Incident/on-call wiring ──────────────────────────────────────────────────

/// Turn a budget breach into an incident creation request, so a threshold
/// crossing can be filed through the standard incident workflow
/// (`incidents::create_incident`).
pub fn breach_to_incident_request(breach: &BudgetBreach) -> crate::incidents::CreateIncidentRequest {
    crate::incidents::CreateIncidentRequest {
        title: format!("Budget threshold breached: {}", breach.category),
        description: format!(
            "Category '{}' ({:?}) reached {:.4} against a configured limit of {:.4}.",
            breach.category, breach.scope, breach.current_total, breach.limit
        ),
        severity: crate::incidents::IncidentSeverity::Sev3,
        assigned_to: None,
    }
}

/// Turn a budget breach into an on-call escalation trigger
/// (`oncall::trigger_escalation`), so a threshold crossing can page whoever
/// is on call for cost overruns.
pub fn breach_to_escalation_request(breach: &BudgetBreach) -> crate::oncall::TriggerEscalationRequest {
    crate::oncall::TriggerEscalationRequest {
        reason: format!(
            "budget threshold '{}' breached: {:.4} >= {:.4}",
            breach.category, breach.current_total, breach.limit
        ),
        current_level: 0,
    }
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

/// `POST /admin/cost/entries` — record a cost entry.
pub async fn record_cost_entry(
    State(state): State<Arc<CostState>>,
    Json(body): Json<RecordCostRequest>,
) -> Result<(StatusCode, Json<CostEntry>), (StatusCode, Json<serde_json::Value>)> {
    if body.operation.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "operation must not be empty" })),
        ));
    }
    if body.amount < 0.0 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "amount must be non-negative" })),
        ));
    }

    let entry = CostEntry {
        id: Uuid::new_v4().to_string(),
        operation: body.operation,
        tags: body.tags,
        amount: body.amount,
        currency: body.currency,
        recorded_at: Utc::now(),
    };
    state.record(entry.clone());

    for breach in state.check_budget_breaches() {
        tracing::warn!(
            category = %breach.category,
            limit = breach.limit,
            current_total = breach.current_total,
            "cost budget threshold breached"
        );
    }

    Ok((StatusCode::CREATED, Json(entry)))
}

/// `GET /admin/cost/report` — aggregate cost report.
pub async fn get_cost_report(State(state): State<Arc<CostState>>) -> Json<CostReport> {
    Json(state.report())
}

/// `POST /admin/cost/allocate` — allocate a shared cost across tag values.
pub async fn allocate_cost(
    State(state): State<Arc<CostState>>,
    Json(body): Json<AllocateCostRequest>,
) -> Result<Json<CostAllocation>, (StatusCode, Json<serde_json::Value>)> {
    if body.tag_key.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "tag_key must not be empty" })),
        ));
    }
    Ok(Json(state.allocate(body.total_amount, &body.tag_key)))
}

/// `POST /admin/cost/budget-thresholds` — configure (or replace, by
/// `category`) a budget alert threshold.
pub async fn set_budget_threshold(
    State(state): State<Arc<CostState>>,
    Json(body): Json<SetBudgetThresholdRequest>,
) -> Result<(StatusCode, Json<BudgetThreshold>), (StatusCode, Json<serde_json::Value>)> {
    if body.category.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "category must not be empty" })),
        ));
    }
    if body.limit < 0.0 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "limit must be non-negative" })),
        ));
    }

    let threshold = BudgetThreshold {
        category: body.category,
        scope: body.scope,
        limit: body.limit,
    };
    state.set_budget_threshold(threshold.clone());

    Ok((StatusCode::CREATED, Json(threshold)))
}

/// `GET /admin/cost/budget-breaches` — evaluate all configured thresholds
/// against currently recorded cost and return the ones that are breached.
pub async fn get_budget_breaches(
    State(state): State<Arc<CostState>>,
) -> Json<Vec<BudgetBreach>> {
    Json(state.check_budget_breaches())
}

/// `POST /admin/cost/gas` — record an on-chain gas (fee) entry.
pub async fn record_gas_cost(
    State(state): State<Arc<CostState>>,
    Json(body): Json<RecordGasCostRequest>,
) -> Result<(StatusCode, Json<GasCostEntry>), (StatusCode, Json<serde_json::Value>)> {
    if body.operation.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "operation must not be empty" })),
        ));
    }
    if body.tx_hash.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "tx_hash must not be empty" })),
        ));
    }

    let entry = GasCostEntry {
        id: Uuid::new_v4().to_string(),
        operation: body.operation,
        tx_hash: body.tx_hash,
        fee_stroops: body.fee_stroops,
        ledger_sequence: body.ledger_sequence,
        tags: body.tags,
        recorded_at: Utc::now(),
    };
    state.record_gas(entry.clone());

    Ok((StatusCode::CREATED, Json(entry)))
}

/// `GET /admin/cost/gas/report` — aggregate gas cost report.
pub async fn get_gas_cost_report(
    State(state): State<Arc<CostState>>,
) -> Json<GasCostReport> {
    Json(state.gas_report())
}

/// `GET /admin/cost/dashboard` — unified cost dashboard.
pub async fn get_cost_dashboard(
    State(state): State<Arc<CostState>>,
) -> Json<CostDashboard> {
    Json(state.dashboard())
}

/// `GET /admin/cost/optimizations` — list current optimization suggestions.
pub async fn get_optimization_suggestions(
    State(state): State<Arc<CostState>>,
) -> Json<Vec<OptimizationSuggestion>> {
    Json(state.optimization_suggestions())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(operation: &str, team: &str, amount: f64) -> CostEntry {
        let mut tags = HashMap::new();
        tags.insert("team".to_string(), team.to_string());
        CostEntry {
            id: Uuid::new_v4().to_string(),
            operation: operation.to_string(),
            tags,
            amount,
            currency: "USD".to_string(),
            recorded_at: Utc::now(),
        }
    }

    #[test]
    fn report_aggregates_totals_and_tags() {
        let state = CostState::new();
        state.record(entry("db.query", "vaults", 1.0));
        state.record(entry("db.query", "vaults", 2.0));
        state.record(entry("api.call", "billing", 3.0));

        let report = state.report();
        assert_eq!(report.total_amount, 6.0);
        assert_eq!(report.entry_count, 3);
        assert_eq!(report.by_operation.get("db.query"), Some(&3.0));
        assert_eq!(report.by_tag.get("team").unwrap().get("vaults"), Some(&3.0));
        assert_eq!(
            report.by_tag.get("team").unwrap().get("billing"),
            Some(&3.0)
        );
    }

    #[test]
    fn allocation_is_proportional_to_historical_share() {
        let state = CostState::new();
        state.record(entry("db.query", "vaults", 3.0));
        state.record(entry("db.query", "billing", 1.0));

        let allocation = state.allocate(100.0, "team");
        assert_eq!(allocation.allocations.get("vaults"), Some(&75.0));
        assert_eq!(allocation.allocations.get("billing"), Some(&25.0));
    }

    #[test]
    fn allocation_with_no_history_is_empty() {
        let state = CostState::new();
        let allocation = state.allocate(100.0, "team");
        assert!(allocation.allocations.is_empty());
    }

    // ── Gas tracking tests ────────────────────────────────────────────────

    fn gas_entry(operation: &str, fee_stroops: u64, ledger: u64) -> GasCostEntry {
        GasCostEntry {
            id: Uuid::new_v4().to_string(),
            operation: operation.to_string(),
            tx_hash: format!("txhash-{}", Uuid::new_v4()),
            fee_stroops,
            ledger_sequence: ledger,
            tags: HashMap::new(),
            recorded_at: Utc::now(),
        }
    }

    #[test]
    fn gas_report_empty_state() {
        let state = CostState::new();
        let report = state.gas_report();
        assert_eq!(report.total_fee_stroops, 0);
        assert_eq!(report.tx_count, 0);
        assert!(report.by_operation.is_empty());
    }

    #[test]
    fn gas_report_aggregates_by_operation() {
        let state = CostState::new();
        state.record_gas(gas_entry("vault.create", 1_000, 100));
        state.record_gas(gas_entry("vault.create", 2_000, 101));
        state.record_gas(gas_entry("vault.check_in", 500, 102));

        let report = state.gas_report();
        assert_eq!(report.total_fee_stroops, 3_500);
        assert_eq!(report.tx_count, 3);

        let vault_create = report
            .by_operation
            .iter()
            .find(|s| s.operation == "vault.create")
            .expect("vault.create stats missing");
        assert_eq!(vault_create.tx_count, 2);
        assert_eq!(vault_create.total_fee_stroops, 3_000);
        assert_eq!(vault_create.avg_fee_stroops, 1_500);
        assert_eq!(vault_create.max_fee_stroops, 2_000);
        assert_eq!(vault_create.min_fee_stroops, 1_000);

        let check_in = report
            .by_operation
            .iter()
            .find(|s| s.operation == "vault.check_in")
            .expect("vault.check_in stats missing");
        assert_eq!(check_in.tx_count, 1);
        assert_eq!(check_in.total_fee_stroops, 500);
    }

    #[test]
    fn gas_report_sorted_descending_by_total_fee() {
        let state = CostState::new();
        state.record_gas(gas_entry("op.cheap", 100, 1));
        state.record_gas(gas_entry("op.expensive", 10_000, 2));
        state.record_gas(gas_entry("op.medium", 500, 3));

        let report = state.gas_report();
        let ops: Vec<&str> = report.by_operation.iter().map(|s| s.operation.as_str()).collect();
        // Most expensive first
        assert_eq!(ops[0], "op.expensive");
        assert_eq!(ops[1], "op.medium");
        assert_eq!(ops[2], "op.cheap");
    }

    #[test]
    fn gas_snapshot_returns_all_entries() {
        let state = CostState::new();
        state.record_gas(gas_entry("op.a", 100, 1));
        state.record_gas(gas_entry("op.b", 200, 2));
        assert_eq!(state.gas_snapshot().len(), 2);
    }

    // ── Dashboard tests ───────────────────────────────────────────────────

    #[test]
    fn dashboard_empty_state() {
        let state = CostState::new();
        let dash = state.dashboard();
        assert_eq!(dash.fiat_summary.entry_count, 0);
        assert_eq!(dash.fiat_summary.total_amount, 0.0);
        assert_eq!(dash.gas_summary.tx_count, 0);
        assert_eq!(dash.gas_summary.total_fee_stroops, 0);
        assert_eq!(dash.active_thresholds, 0);
        assert_eq!(dash.breached_thresholds, 0);
        assert!(dash.top_fiat_operations.is_empty());
        assert!(dash.top_gas_operations.is_empty());
    }

    #[test]
    fn dashboard_reflects_recorded_data() {
        let state = CostState::new();
        state.record(entry("db.query", "vaults", 10.0));
        state.record(entry("api.call", "billing", 5.0));
        state.record_gas(gas_entry("vault.create", 1_000, 1));

        let dash = state.dashboard();
        assert_eq!(dash.fiat_summary.entry_count, 2);
        assert_eq!(dash.fiat_summary.total_amount, 15.0);
        assert_eq!(dash.gas_summary.tx_count, 1);
        assert_eq!(dash.gas_summary.total_fee_stroops, 1_000);
    }

    #[test]
    fn dashboard_shows_active_and_breached_thresholds() {
        let state = CostState::new();
        state.record(entry("db.query", "vaults", 100.0));
        // Set a threshold that is breached
        state.set_budget_threshold(BudgetThreshold {
            category: "over".to_string(),
            scope: BudgetScope::Operation("db.query".to_string()),
            limit: 50.0,
        });
        // Set a threshold that is not breached
        state.set_budget_threshold(BudgetThreshold {
            category: "ok".to_string(),
            scope: BudgetScope::Operation("db.query".to_string()),
            limit: 200.0,
        });

        let dash = state.dashboard();
        assert_eq!(dash.active_thresholds, 2);
        assert_eq!(dash.breached_thresholds, 1);
    }

    #[test]
    fn dashboard_top_fiat_operations_capped_at_5() {
        let state = CostState::new();
        for i in 0..10u32 {
            state.record(entry(&format!("op.{}", i), "team", (i + 1) as f64));
        }
        let dash = state.dashboard();
        assert_eq!(dash.top_fiat_operations.len(), 5);
        // Highest should be first (op.9 = 10.0)
        assert_eq!(dash.top_fiat_operations[0].total, 10.0);
    }

    // ── Optimization suggestion tests ─────────────────────────────────────

    #[test]
    fn no_suggestions_on_empty_state() {
        let state = CostState::new();
        assert!(state.optimization_suggestions().is_empty());
    }

    #[test]
    fn high_severity_suggestion_for_dominant_fiat_operation() {
        let state = CostState::new();
        // op.heavy dominates with > 50 % of cost
        state.record(entry("op.heavy", "team", 80.0));
        state.record(entry("op.light", "team", 10.0));

        let suggestions = state.optimization_suggestions();
        let high = suggestions
            .iter()
            .find(|s| s.severity == OptimizationSeverity::High && s.applies_to.as_deref() == Some("op.heavy"));
        assert!(high.is_some(), "expected a High suggestion for op.heavy");
    }

    #[test]
    fn high_severity_suggestion_for_dominant_gas_operation() {
        let state = CostState::new();
        state.record_gas(gas_entry("op.heavy", 90_000, 1));
        state.record_gas(gas_entry("op.light", 5_000, 2));

        let suggestions = state.optimization_suggestions();
        let high = suggestions
            .iter()
            .find(|s| s.severity == OptimizationSeverity::High && s.applies_to.as_deref() == Some("op.heavy"));
        assert!(high.is_some(), "expected a High suggestion for dominant gas op");
    }

    #[test]
    fn medium_severity_suggestion_for_breached_threshold() {
        let state = CostState::new();
        state.record(entry("db.query", "vaults", 100.0));
        state.set_budget_threshold(BudgetThreshold {
            category: "vaults-db".to_string(),
            scope: BudgetScope::Operation("db.query".to_string()),
            limit: 50.0,
        });

        let suggestions = state.optimization_suggestions();
        let med = suggestions
            .iter()
            .find(|s| s.severity == OptimizationSeverity::Medium);
        assert!(med.is_some(), "expected a Medium suggestion for breached threshold");
    }

    #[test]
    fn low_severity_suggestion_for_missing_gas_instrumentation() {
        let state = CostState::new();
        // op.heavy has > 20 % of fiat cost but zero gas entries
        state.record(entry("op.heavy", "team", 80.0));
        state.record(entry("op.light", "team", 5.0));

        let suggestions = state.optimization_suggestions();
        let low = suggestions
            .iter()
            .find(|s| s.severity == OptimizationSeverity::Low && s.applies_to.as_deref() == Some("op.heavy"));
        assert!(low.is_some(), "expected a Low suggestion for missing gas data");
    }

    #[test]
    fn no_low_instrumentation_suggestion_when_gas_data_exists() {
        let state = CostState::new();
        state.record(entry("op.heavy", "team", 80.0));
        state.record(entry("op.light", "team", 5.0));
        // Add gas data for op.heavy — the Low suggestion should be suppressed
        state.record_gas(gas_entry("op.heavy", 1_000, 1));

        let suggestions = state.optimization_suggestions();
        let instrumentation_hint = suggestions.iter().find(|s| {
            s.severity == OptimizationSeverity::Low
                && s.applies_to.as_deref() == Some("op.heavy")
                && s.description.contains("gas instrumentation")
        });
        assert!(instrumentation_hint.is_none(), "no Low instrumentation suggestion expected when gas data present");
    }
}

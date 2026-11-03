//! Disaster-recovery runbook automation hooks.
//!
//! `docs/disaster-recovery-runbook.md` documents manual `stellar contract
//! invoke` steps for pausing the contract, restoring an archived vault, and
//! so on. Running these by hand during an actual incident is error-prone —
//! a mistyped vault id or a skipped verification step compounds an already
//! bad situation. This module exposes the highest-risk manual steps as
//! admin-only HTTP endpoints, gated by a two-phase confirmation token for
//! anything destructive, so the exact commands from the runbook can be
//! triggered programmatically instead of retyped under pressure.
//!
//! ## RTO / RPO definitions (#595)
//!
//! Recovery Time Objective (RTO) and Recovery Point Objective (RPO) for
//! Ethos-Protocol are defined as structured data alongside the automation
//! endpoints so they can be queried programmatically and embedded in
//! dashboards or alert workflows.
//!
//! ## DR testing schedule (#595)
//!
//! DR tests should be run regularly. A schedule is encoded here and
//! surfaced via `GET /admin/dr/test-schedule`.
//!
//! ## Incident response playbooks (#595)
//!
//! Common incident scenarios are enumerated as structured playbooks
//! surfaced via `GET /admin/dr/playbooks` so they can be consumed by
//! tooling without parsing Markdown.
//!
//! # Architecture
//!
//! ```text
//! POST /admin/dr/actions               → request_dr_action  (phase 1: non-destructive steps run immediately; destructive steps return a confirmation token)
//! POST /admin/dr/actions/:token/confirm → confirm_dr_action  (phase 2: executes a previously requested destructive step)
//! GET  /admin/dr/rto-rpo               → get_rto_rpo        (RTO/RPO targets)
//! GET  /admin/dr/test-schedule         → get_dr_test_schedule (DR testing schedule)
//! GET  /admin/dr/playbooks             → list_playbooks      (incident response playbooks)
//! ```

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How long a requested destructive action's confirmation token remains
/// valid before it must be re-requested.
const CONFIRMATION_TTL_MINUTES: i64 = 5;

/// One of the manual runbook steps exposed for automation. Names and
/// underlying `stellar contract invoke` commands mirror
/// `docs/disaster-recovery-runbook.md`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DrStep {
    /// Runbook §1 — Emergency Contract Pause.
    PauseContract,
    /// Runbook §1 — resume normal operation after a pause.
    UnpauseContract,
    /// Runbook §3 — Archived Vault Recovery (`restore_vault`).
    RestoreVault,
}

impl DrStep {
    /// Every step here mutates on-chain state, so all of them require a
    /// confirmation token before executing.
    fn is_destructive(self) -> bool {
        true
    }
}

/// `POST /admin/dr/actions` request body.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestDrActionRequest {
    pub step: DrStep,
    /// Required for `RestoreVault`; ignored otherwise.
    pub vault_id: Option<u64>,
    /// Operator requesting the action, recorded for the audit log.
    pub requested_by: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestDrActionResponse {
    pub step: DrStep,
    pub confirmation_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DrActionResult {
    pub step: DrStep,
    pub success: bool,
    pub output: String,
    pub executed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingAction {
    pub(crate) step: DrStep,
    pub(crate) vault_id: Option<u64>,
    pub(crate) requested_by: String,
    pub(crate) expires_at: DateTime<Utc>,
}

type PendingActionStore = Arc<Mutex<HashMap<String, PendingAction>>>;

#[derive(Clone)]
pub struct DrAutomationState {
    pub(crate) pending: PendingActionStore,
}

impl DrAutomationState {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for DrAutomationState {
    fn default() -> Self {
        Self::new()
    }
}

/// `POST /admin/dr/actions` — phase 1: request a destructive DR step. Always
/// returns a confirmation token that must be replayed to
/// `POST /admin/dr/actions/:token/confirm` within `CONFIRMATION_TTL_MINUTES`
/// for the step to actually execute.
pub async fn request_dr_action(
    State(state): State<Arc<DrAutomationState>>,
    Json(body): Json<RequestDrActionRequest>,
) -> Result<Json<RequestDrActionResponse>, (StatusCode, String)> {
    if matches!(body.step, DrStep::RestoreVault) && body.vault_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "vault_id is required for restore_vault".to_string(),
        ));
    }

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(CONFIRMATION_TTL_MINUTES);

    state.pending.lock().unwrap().insert(
        token.clone(),
        PendingAction {
            step: body.step,
            vault_id: body.vault_id,
            requested_by: body.requested_by,
            expires_at,
        },
    );

    tracing::warn!(step = ?body.step, "DR automation step requested, awaiting confirmation");

    Ok(Json(RequestDrActionResponse {
        step: body.step,
        confirmation_token: token,
        expires_at,
    }))
}

/// `POST /admin/dr/actions/:token/confirm` — phase 2: execute a previously
/// requested destructive DR step, provided its confirmation token hasn't
/// expired. Tokens are single-use: they're removed as soon as they're read,
/// whether or not the underlying command succeeds.
pub async fn confirm_dr_action(
    State(state): State<Arc<DrAutomationState>>,
    Path(token): Path<String>,
) -> Result<Json<DrActionResult>, (StatusCode, String)> {
    let pending = state.pending.lock().unwrap().remove(&token);

    let pending = match pending {
        Some(p) if p.expires_at > Utc::now() => p,
        Some(_) => {
            return Err((
                StatusCode::GONE,
                "confirmation token expired; request the action again".to_string(),
            ))
        }
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                "unknown or already-used confirmation token".to_string(),
            ))
        }
    };

    let result = execute_step(pending.step, pending.vault_id);

    tracing::warn!(
        step = ?pending.step,
        requested_by = %pending.requested_by,
        vault_id = ?pending.vault_id,
        success = result.success,
        "DR automation step executed"
    );

    Ok(Json(result))
}

/// Runs the `stellar contract invoke` command for `step`, mirroring the
/// commands documented in `docs/disaster-recovery-runbook.md`. Contract id,
/// network, and signing identity are read from the same environment
/// variables the runbook's manual commands reference
/// (`CONTRACT_TTL_VAULT`, `STELLAR_NETWORK`, `DEPLOYER_IDENTITY`).
fn execute_step(step: DrStep, vault_id: Option<u64>) -> DrActionResult {
    let executed_at = Utc::now();

    debug_assert!(step.is_destructive());

    let args: Vec<String> = match step {
        DrStep::PauseContract => vec!["pause".to_string()],
        DrStep::UnpauseContract => vec!["unpause".to_string()],
        DrStep::RestoreVault => vec![
            "restore_vault".to_string(),
            "--vault_id".to_string(),
            vault_id.unwrap_or_default().to_string(),
        ],
    };

    let contract_id = std::env::var("CONTRACT_TTL_VAULT").unwrap_or_default();
    let network = std::env::var("STELLAR_NETWORK").unwrap_or_default();
    let source = std::env::var("DEPLOYER_IDENTITY").unwrap_or_default();

    let output = Command::new("stellar")
        .arg("contract")
        .arg("invoke")
        .arg("--id")
        .arg(&contract_id)
        .arg("--network")
        .arg(&network)
        .arg("--source")
        .arg(&source)
        .arg("--")
        .args(&args)
        .output();

    match output {
        Ok(out) if out.status.success() => DrActionResult {
            step,
            success: true,
            output: String::from_utf8_lossy(&out.stdout).to_string(),
            executed_at,
        },
        Ok(out) => DrActionResult {
            step,
            success: false,
            output: String::from_utf8_lossy(&out.stderr).to_string(),
            executed_at,
        },
        Err(e) => DrActionResult {
            step,
            success: false,
            output: format!("failed to invoke stellar CLI: {e}"),
            executed_at,
        },
    }
}


// ── RTO / RPO definitions (#595) ──────────────────────────────────────────────

/// Recovery Time Objective (RTO): maximum acceptable time for service restoration.
/// Recovery Point Objective (RPO): maximum acceptable data loss window.
///
/// These numbers are a contract between engineering and stakeholders — they
/// should be reviewed annually and after any DR drill that exposes gaps.
#[derive(Debug, Clone, Serialize)]
pub struct RtoRpoTargets {
    /// RTO for a P0 (critical) incident — contract exploit or active fund loss.
    pub p0_rto_minutes: u32,
    /// RPO for a P0 incident: maximum tolerable state rollback.
    pub p0_rpo_minutes: u32,
    /// RTO for a P1 (high) incident — contract frozen.
    pub p1_rto_minutes: u32,
    pub p1_rpo_minutes: u32,
    /// RTO for a P2 (medium) incident — degraded functionality.
    pub p2_rto_minutes: u32,
    pub p2_rpo_minutes: u32,
    /// RTO for a P3 (low) incident — minor monitoring alert.
    pub p3_rto_minutes: u32,
    pub p3_rpo_minutes: u32,
    /// Date these targets were last reviewed (ISO-8601 date string).
    pub last_reviewed: String,
}

impl RtoRpoTargets {
    /// Returns the project's current RTO/RPO targets.
    ///
    /// P0: immediate response (<15 min RTO / 0 RPO — on-chain state is
    ///     deterministic, but off-chain DB backups have a 5-minute window).
    /// P1: < 1 h RTO / 5 min RPO
    /// P2: < 4 h RTO / 30 min RPO
    /// P3: < 24 h RTO / 60 min RPO
    pub fn current() -> Self {
        RtoRpoTargets {
            p0_rto_minutes: 15,
            p0_rpo_minutes: 0,
            p1_rto_minutes: 60,
            p1_rpo_minutes: 5,
            p2_rto_minutes: 240,
            p2_rpo_minutes: 30,
            p3_rto_minutes: 1440,
            p3_rpo_minutes: 60,
            last_reviewed: "2026-09-26".to_string(),
        }
    }
}

// ── DR testing schedule (#595) ────────────────────────────────────────────────

/// Cadence at which a DR test must be performed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DrTestCadence {
    Weekly,
    Monthly,
    Quarterly,
    Annually,
}

/// A scheduled DR test entry.
#[derive(Debug, Clone, Serialize)]
pub struct DrTestEntry {
    pub id: String,
    /// Human-readable name for this test.
    pub name: String,
    /// What this test validates.
    pub description: String,
    pub cadence: DrTestCadence,
    /// The DR step exercised by this test.
    pub step: DrStep,
    /// Owner or on-call rotation responsible for running this test.
    pub owner: String,
    /// Date of the last successful run (ISO-8601 date string), if known.
    pub last_run: Option<String>,
    /// Date the next run is due (ISO-8601 date string).
    pub next_due: String,
}

/// Returns the project's DR testing schedule.
///
/// All tests should be run against the testnet environment unless otherwise
/// noted. Results should be filed in the incident log with the `dr-drill`
/// tag even when no issues are found, to maintain a complete audit trail.
pub fn dr_test_schedule() -> Vec<DrTestEntry> {
    vec![
        DrTestEntry {
            id: "dr-test-001".to_string(),
            name: "Contract pause/unpause drill".to_string(),
            description: "Confirm that PauseContract and UnpauseContract steps execute \
                          within the RTO target on testnet and that the contract is \
                          unreachable while paused."
                .to_string(),
            cadence: DrTestCadence::Monthly,
            step: DrStep::PauseContract,
            owner: "on-call-operator".to_string(),
            last_run: None,
            next_due: "2026-10-26".to_string(),
        },
        DrTestEntry {
            id: "dr-test-002".to_string(),
            name: "Archived vault restore drill".to_string(),
            description: "Create a test vault on testnet with a short TTL, let it expire \
                          to archive state, then trigger RestoreVault via the API and \
                          verify the vault is accessible again."
                .to_string(),
            cadence: DrTestCadence::Quarterly,
            step: DrStep::RestoreVault,
            owner: "on-call-operator".to_string(),
            last_run: None,
            next_due: "2026-12-26".to_string(),
        },
        DrTestEntry {
            id: "dr-test-003".to_string(),
            name: "Database backup restore verification".to_string(),
            description: "Restore the latest off-chain database backup to a staging \
                          environment and verify data integrity against the most recent \
                          snapshot. Validates the RPO target."
                .to_string(),
            cadence: DrTestCadence::Monthly,
            step: DrStep::UnpauseContract, // closest analogue; this is manual
            owner: "sre-team".to_string(),
            last_run: None,
            next_due: "2026-10-26".to_string(),
        },
        DrTestEntry {
            id: "dr-test-004".to_string(),
            name: "Admin key rotation simulation".to_string(),
            description: "Simulate admin key compromise by rotating keys in a testnet \
                          deployment and confirming the new admin key has sole authority. \
                          Validates the key-rotation runbook section."
                .to_string(),
            cadence: DrTestCadence::Annually,
            step: DrStep::PauseContract, // key rotation runs manually outside this API
            owner: "security-team".to_string(),
            last_run: None,
            next_due: "2027-09-26".to_string(),
        },
    ]
}

// ── Incident response playbooks (#595) ────────────────────────────────────────

/// Severity classification for a playbook.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PlaybookSeverity {
    P0,
    P1,
    P2,
    P3,
}

/// A single step in a response playbook.
#[derive(Debug, Clone, Serialize)]
pub struct PlaybookStep {
    pub order: u32,
    pub action: String,
    /// True if this step can be automated via the DR API.
    pub automated: bool,
    /// The DR step to call if `automated` is true.
    pub dr_step: Option<DrStep>,
}

/// A complete incident response playbook for a specific scenario.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentPlaybook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: PlaybookSeverity,
    /// Trigger conditions that indicate this playbook should be activated.
    pub triggers: Vec<String>,
    pub steps: Vec<PlaybookStep>,
    /// Escalation contacts if the playbook does not resolve the incident.
    pub escalation_contacts: Vec<String>,
    /// References to related runbook sections.
    pub runbook_refs: Vec<String>,
}

/// Returns all defined incident response playbooks.
///
/// Playbooks mirror the sections in `docs/disaster-recovery-runbook.md` but
/// are encoded as structured data so they can be rendered in monitoring UIs,
/// included in PagerDuty annotations, or used to drive automated response
/// tooling.
pub fn incident_playbooks() -> Vec<IncidentPlaybook> {
    vec![
        IncidentPlaybook {
            id: "playbook-001".to_string(),
            name: "Contract exploit / active fund loss".to_string(),
            description: "Immediate response to a detected smart-contract exploit \
                          or active unauthorised fund movement."
                .to_string(),
            severity: PlaybookSeverity::P0,
            triggers: vec![
                "Unauthorised 'trigger_release' call detected".to_string(),
                "Unexpected XLM transfer from contract address".to_string(),
                "Security scanner alert: contract invariant violated".to_string(),
            ],
            steps: vec![
                PlaybookStep {
                    order: 1,
                    action: "Page on-call operator immediately via incident channel".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 2,
                    action: "Request contract pause via POST /admin/dr/actions (step: pause_contract) and confirm within 5 minutes".to_string(),
                    automated: true,
                    dr_step: Some(DrStep::PauseContract),
                },
                PlaybookStep {
                    order: 3,
                    action: "Capture on-chain state: run 'stellar contract invoke ... get_vault' for all affected vaults".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 4,
                    action: "Notify security team and Stellar SDF if ledger-level intervention is needed".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 5,
                    action: "Post user communication using the 'Unplanned Outage' template from the runbook".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 6,
                    action: "After root-cause is confirmed fixed, unpause contract via POST /admin/dr/actions (step: unpause_contract)".to_string(),
                    automated: true,
                    dr_step: Some(DrStep::UnpauseContract),
                },
            ],
            escalation_contacts: vec![
                "security@ethos-protocol.example.com".to_string(),
                "https://stellar.org/developers".to_string(),
            ],
            runbook_refs: vec![
                "disaster-recovery-runbook.md §1".to_string(),
                "disaster-recovery-runbook.md §6".to_string(),
            ],
        },
        IncidentPlaybook {
            id: "playbook-002".to_string(),
            name: "Contract frozen / vaults inaccessible".to_string(),
            description: "Vault operations are reverting or the contract is unresponsive \
                          but there is no evidence of active fund loss."
                .to_string(),
            severity: PlaybookSeverity::P1,
            triggers: vec![
                "All 'check_in' calls returning error for > 5 minutes".to_string(),
                "Health endpoint returning 503".to_string(),
                "Contract 'is_paused' returning unexpected true".to_string(),
            ],
            steps: vec![
                PlaybookStep {
                    order: 1,
                    action: "Confirm contract pause state via 'stellar contract invoke ... is_paused'".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 2,
                    action: "If paused unexpectedly, investigate who triggered the pause (audit log)".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 3,
                    action: "If safe to resume, unpause via POST /admin/dr/actions (step: unpause_contract)".to_string(),
                    automated: true,
                    dr_step: Some(DrStep::UnpauseContract),
                },
                PlaybookStep {
                    order: 4,
                    action: "Verify vault operations resume normally on testnet before mainnet".to_string(),
                    automated: false,
                    dr_step: None,
                },
            ],
            escalation_contacts: vec![
                "on-call-operator (internal channel)".to_string(),
            ],
            runbook_refs: vec![
                "disaster-recovery-runbook.md §1".to_string(),
            ],
        },
        IncidentPlaybook {
            id: "playbook-003".to_string(),
            name: "Archived vault recovery".to_string(),
            description: "A vault's Soroban persistent entry has expired (TTL lapsed) \
                          and needs to be restored before trigger_release can proceed."
                .to_string(),
            severity: PlaybookSeverity::P2,
            triggers: vec![
                "trigger_release returning 'vault archived' error".to_string(),
                "get_archived_vault_info returning Some(ArchivedVaultInfo)".to_string(),
            ],
            steps: vec![
                PlaybookStep {
                    order: 1,
                    action: "Confirm archival via 'stellar contract invoke ... get_archived_vault_info --vault_id <ID>'".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 2,
                    action: "Restore vault via POST /admin/dr/actions (step: restore_vault, vault_id: <ID>)".to_string(),
                    automated: true,
                    dr_step: Some(DrStep::RestoreVault),
                },
                PlaybookStep {
                    order: 3,
                    action: "Verify restoration via 'stellar contract invoke ... get_vault --vault_id <ID>'".to_string(),
                    automated: false,
                    dr_step: None,
                },
            ],
            escalation_contacts: vec![
                "on-call-operator (internal channel)".to_string(),
            ],
            runbook_refs: vec![
                "disaster-recovery-runbook.md §3".to_string(),
            ],
        },
        IncidentPlaybook {
            id: "playbook-004".to_string(),
            name: "Admin key compromise".to_string(),
            description: "The admin signing key is suspected to be compromised. \
                          Time-sensitive: rotate before an attacker exploits admin authority."
                .to_string(),
            severity: PlaybookSeverity::P0,
            triggers: vec![
                "Unexpected admin-signed transaction in ledger history".to_string(),
                "Admin key material exposed in logs or public repository".to_string(),
            ],
            steps: vec![
                PlaybookStep {
                    order: 1,
                    action: "Immediately pause contract to prevent admin-signed exploit".to_string(),
                    automated: true,
                    dr_step: Some(DrStep::PauseContract),
                },
                PlaybookStep {
                    order: 2,
                    action: "Propose new admin: 'stellar contract invoke ... propose_admin --new_admin <address>'".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 3,
                    action: "Accept admin with new key: 'stellar contract invoke ... accept_admin'".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 4,
                    action: "Revoke and rotate any related secrets (API keys, DB creds) via secret rotation module".to_string(),
                    automated: false,
                    dr_step: None,
                },
                PlaybookStep {
                    order: 5,
                    action: "Post-incident review within 72 hours per runbook §8".to_string(),
                    automated: false,
                    dr_step: None,
                },
            ],
            escalation_contacts: vec![
                "security@ethos-protocol.example.com".to_string(),
                "External auditor (contract-specific contact)".to_string(),
            ],
            runbook_refs: vec![
                "disaster-recovery-runbook.md §5".to_string(),
                "disaster-recovery-runbook.md §8".to_string(),
            ],
        },
    ]
}

// ── HTTP handlers (#595) ──────────────────────────────────────────────────────

/// `GET /admin/dr/rto-rpo` — return current RTO/RPO targets.
pub async fn get_rto_rpo() -> Json<RtoRpoTargets> {
    Json(RtoRpoTargets::current())
}

/// `GET /admin/dr/test-schedule` — return the DR testing schedule.
pub async fn get_dr_test_schedule() -> Json<Vec<DrTestEntry>> {
    Json(dr_test_schedule())
}

/// `GET /admin/dr/playbooks` — list all incident response playbooks.
pub async fn list_playbooks() -> Json<Vec<IncidentPlaybook>> {
    Json(incident_playbooks())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RTO/RPO tests ─────────────────────────────────────────────────────

    #[test]
    fn rto_rpo_p0_is_most_aggressive() {
        let targets = RtoRpoTargets::current();
        // P0 must be faster than P1, which must be faster than P2, etc.
        assert!(targets.p0_rto_minutes < targets.p1_rto_minutes);
        assert!(targets.p1_rto_minutes < targets.p2_rto_minutes);
        assert!(targets.p2_rto_minutes < targets.p3_rto_minutes);
    }

    #[test]
    fn rto_rpo_p0_rpo_is_zero() {
        // On-chain state is deterministic so P0 RPO should be zero.
        let targets = RtoRpoTargets::current();
        assert_eq!(targets.p0_rpo_minutes, 0);
    }

    #[test]
    fn rto_rpo_all_fields_positive_or_zero() {
        let t = RtoRpoTargets::current();
        assert!(t.p0_rto_minutes > 0);
        assert!(t.p1_rto_minutes > 0);
        assert!(t.p1_rpo_minutes > 0);
        assert!(t.p2_rto_minutes > 0);
        assert!(t.p2_rpo_minutes > 0);
        assert!(t.p3_rto_minutes > 0);
        assert!(t.p3_rpo_minutes > 0);
    }

    #[test]
    fn rto_rpo_last_reviewed_is_set() {
        let targets = RtoRpoTargets::current();
        assert!(!targets.last_reviewed.is_empty());
    }

    // ── DR test schedule tests ────────────────────────────────────────────

    #[test]
    fn dr_test_schedule_is_non_empty() {
        let schedule = dr_test_schedule();
        assert!(!schedule.is_empty(), "DR test schedule must not be empty");
    }

    #[test]
    fn dr_test_schedule_all_entries_have_unique_ids() {
        let schedule = dr_test_schedule();
        let mut ids: Vec<&str> = schedule.iter().map(|e| e.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), schedule.len(), "all DR test IDs must be unique");
    }

    #[test]
    fn dr_test_schedule_all_entries_have_names_and_owners() {
        for entry in dr_test_schedule() {
            assert!(
                !entry.name.is_empty(),
                "DR test '{}' has empty name",
                entry.id
            );
            assert!(
                !entry.owner.is_empty(),
                "DR test '{}' has empty owner",
                entry.id
            );
            assert!(
                !entry.next_due.is_empty(),
                "DR test '{}' has empty next_due",
                entry.id
            );
        }
    }

    #[test]
    fn dr_test_schedule_includes_pause_and_restore() {
        let schedule = dr_test_schedule();
        let has_pause = schedule.iter().any(|e| e.step == DrStep::PauseContract);
        let has_restore = schedule.iter().any(|e| e.step == DrStep::RestoreVault);
        assert!(has_pause, "schedule must include a PauseContract drill");
        assert!(has_restore, "schedule must include a RestoreVault drill");
    }

    // ── Playbook tests ────────────────────────────────────────────────────

    #[test]
    fn playbooks_are_non_empty() {
        assert!(!incident_playbooks().is_empty());
    }

    #[test]
    fn playbooks_all_have_unique_ids() {
        let playbooks = incident_playbooks();
        let mut ids: Vec<&str> = playbooks.iter().map(|p| p.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), playbooks.len(), "all playbook IDs must be unique");
    }

    #[test]
    fn playbooks_all_have_at_least_one_step() {
        for playbook in incident_playbooks() {
            assert!(
                !playbook.steps.is_empty(),
                "playbook '{}' has no steps",
                playbook.id
            );
        }
    }

    #[test]
    fn playbooks_steps_are_ordered_consecutively() {
        for playbook in incident_playbooks() {
            let orders: Vec<u32> = playbook.steps.iter().map(|s| s.order).collect();
            for (i, &order) in orders.iter().enumerate() {
                assert_eq!(
                    order,
                    (i + 1) as u32,
                    "playbook '{}' step orders must start at 1 and be consecutive",
                    playbook.id
                );
            }
        }
    }

    #[test]
    fn automated_playbook_steps_have_dr_step() {
        for playbook in incident_playbooks() {
            for step in &playbook.steps {
                if step.automated {
                    assert!(
                        step.dr_step.is_some(),
                        "playbook '{}' step {} is automated but has no dr_step",
                        playbook.id,
                        step.order
                    );
                }
            }
        }
    }

    #[test]
    fn playbooks_p0_includes_pause_step() {
        let p0_playbooks: Vec<_> = incident_playbooks()
            .into_iter()
            .filter(|p| p.severity == PlaybookSeverity::P0)
            .collect();
        assert!(!p0_playbooks.is_empty(), "at least one P0 playbook expected");

        for playbook in &p0_playbooks {
            let has_pause = playbook
                .steps
                .iter()
                .any(|s| s.dr_step == Some(DrStep::PauseContract));
            assert!(
                has_pause,
                "P0 playbook '{}' must include a PauseContract step",
                playbook.id
            );
        }
    }

    #[test]
    fn playbooks_all_have_escalation_contacts() {
        for playbook in incident_playbooks() {
            assert!(
                !playbook.escalation_contacts.is_empty(),
                "playbook '{}' has no escalation contacts",
                playbook.id
            );
        }
    }

    #[test]
    fn playbooks_all_have_runbook_refs() {
        for playbook in incident_playbooks() {
            assert!(
                !playbook.runbook_refs.is_empty(),
                "playbook '{}' has no runbook_refs",
                playbook.id
            );
        }
    }

    // ── DrAutomationState token lifecycle tests ───────────────────────────

    #[tokio::test]
    async fn request_dr_action_returns_token() {
        let state = Arc::new(DrAutomationState::new());
        let req = RequestDrActionRequest {
            step: DrStep::PauseContract,
            vault_id: None,
            requested_by: "tester".to_string(),
        };
        let result = request_dr_action(State(Arc::clone(&state)), Json(req))
            .await
            .unwrap()
            .0;
        assert!(!result.confirmation_token.is_empty());
        assert!(result.expires_at > Utc::now());
    }

    #[tokio::test]
    async fn restore_vault_requires_vault_id() {
        let state = Arc::new(DrAutomationState::new());
        let req = RequestDrActionRequest {
            step: DrStep::RestoreVault,
            vault_id: None, // missing — should fail
            requested_by: "tester".to_string(),
        };
        let result = request_dr_action(State(Arc::clone(&state)), Json(req)).await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn confirm_dr_action_rejects_unknown_token() {
        let state = Arc::new(DrAutomationState::new());
        let result =
            confirm_dr_action(State(Arc::clone(&state)), Path("nonexistent-token".to_string()))
                .await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn confirm_dr_action_rejects_expired_token() {
        let state = Arc::new(DrAutomationState::new());
        // Manually insert an already-expired pending action
        let token = "expired-token".to_string();
        state.pending.lock().unwrap().insert(
            token.clone(),
            PendingAction {
                step: DrStep::PauseContract,
                vault_id: None,
                requested_by: "tester".to_string(),
                expires_at: Utc::now() - Duration::minutes(10),
            },
        );

        let result = confirm_dr_action(State(Arc::clone(&state)), Path(token)).await;
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::GONE);
    }
}

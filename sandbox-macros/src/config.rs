//! sandbox.toml parser — typed configuration for PERK Sandbox.
//!
//! Parses the developer's `sandbox.toml` into strongly-typed Rust structs used
//! by the proc macros at compile time to generate safety wrappers.
//!
//! Reference: SPEC.md §3.1-3.7, §6.2, §7, §9

use serde::Deserialize;
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════
// Top-Level Config
// ═══════════════════════════════════════════════════════════════════════════

/// Root configuration parsed from `sandbox.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Circuit breaker configuration (§6.2).
    pub circuit_breakers: Option<CircuitBreakerConfig>,

    /// Re-entrancy handling mode (§7).
    pub reentrancy: Option<ReentrancyConfig>,

    /// Rate limit configuration.
    pub rate_limits: Option<RateLimitConfig>,

    /// Recovery / emergency bypass configuration (§9).
    pub recovery: Option<RecoveryConfig>,

    /// Named public keys (admin, cranker, guardians).
    pub keys: Option<KeysConfig>,

    /// Off-chain alert / watcher configuration.
    pub alerts: Option<AlertsConfig>,

    /// Account field declarations for snapshot field resolution (§4).
    /// Maps account name → account config with field layout information.
    pub accounts: Option<HashMap<String, AccountConfig>>,

    /// Oracle pre-check configuration.
    pub oracle: Option<OracleConfig>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Circuit Breakers (§6.2)
// ═══════════════════════════════════════════════════════════════════════════

/// Circuit breaker top-level config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Master enable flag.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Scope: `"global"` (default) or `"per_market"`.
    #[serde(default = "default_scope")]
    pub scope: CircuitBreakerScope,

    /// Account path for per-market PDA derivation. Required when scope = per_market.
    pub market_account: Option<String>,

    /// Instruction category → list of instruction names.
    #[serde(default)]
    pub categories: HashMap<String, Vec<String>>,

    /// TVL cliff breaker with per-category budgets.
    pub tvl_cliff: Option<TvlCliffConfig>,

    /// Global aggregate breaker (required when scope = per_market, §8.6).
    pub global_aggregate: Option<GlobalAggregateConfig>,

    /// Rapid-event counters (e.g. rapid_liquidations, rapid_withdrawals).
    /// Keyed by arbitrary breaker name.
    #[serde(flatten)]
    pub custom_breakers: HashMap<String, serde::de::IgnoredAny>,
}

/// Circuit breaker scope.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerScope {
    Global,
    PerMarket,
}

/// TVL cliff breaker configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TvlCliffConfig {
    /// Account field path to track (e.g. `"market.vault_balance"`).
    pub track_field: String,

    /// Window size in slots.
    pub window_slots: u64,

    /// Wall-clock backup window in seconds (dual-window, §6.4).
    pub window_seconds: Option<u64>,

    /// Action on trigger: `"reject_current"`, `"pause"`, `"close_only"`.
    #[serde(default = "default_action")]
    pub action: BreakerAction,

    /// Track explicit high-water mark (§6.3).
    #[serde(default)]
    pub high_water_mark: bool,

    /// Per-category budgets. At least one required when circuit_breakers enabled.
    #[serde(default)]
    pub budgets: HashMap<String, BudgetEntry>,

    /// Exempt instructions that bypass this breaker entirely.
    pub exempt: Option<ExemptConfig>,
}

/// A single budget entry for a circuit breaker category.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetEntry {
    /// Maximum allowed decrease as a percentage.
    pub max_decrease_pct: u64,
}

/// Instructions exempt from a breaker.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExemptConfig {
    /// Instruction names that are exempt.
    #[serde(default)]
    pub instructions: Vec<String>,
}

/// Global aggregate circuit breaker (§8.6).
/// Read-only aggregation — no global PDA write-lock.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalAggregateConfig {
    /// Must be true when scope = per_market.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Field to track across all markets.
    pub track_field: String,

    /// Protocol-wide max decrease percentage per transaction.
    pub max_decrease_pct: u64,

    /// Action on trigger.
    #[serde(default = "default_action")]
    pub action: BreakerAction,
}

/// Action taken when a circuit breaker fires.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerAction {
    RejectCurrent,
    Pause,
    CloseOnly,
    PauseLiquidations,
}

// ═══════════════════════════════════════════════════════════════════════════
// Re-Entrancy (§7)
// ═══════════════════════════════════════════════════════════════════════════

/// Re-entrancy handling configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReentrancyConfig {
    /// Mode: `"reject"` | `"guard"` (default) | `"full"`.
    #[serde(default = "default_reentrancy_mode")]
    pub mode: ReentrancyMode,
}

/// Re-entrancy mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReentrancyMode {
    /// Block all self-CPI.
    Reject,
    /// Inner calls run pre-checks + breakers only; outer runs full post-checks.
    Guard,
    /// Every call runs everything (risk of false positives).
    Full,
}

// ═══════════════════════════════════════════════════════════════════════════
// Rate Limits
// ═══════════════════════════════════════════════════════════════════════════

/// Rate limit configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Global rate limit (all callers combined).
    pub global: Option<RateLimitEntry>,

    /// Per-signer rate limit.
    pub per_signer: Option<RateLimitEntry>,
}

/// A single rate limit entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitEntry {
    /// Window size in slots.
    pub window_slots: u64,

    /// Maximum number of calls within the window.
    pub max_count: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Oracle Pre-Check
// ═══════════════════════════════════════════════════════════════════════════

/// Oracle pre-check configuration.
/// When present, validates oracle freshness on every instruction.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleConfig {
    /// Byte offset of the price field (u64, 8 bytes).
    pub price_offset: usize,

    /// Byte offset of the last-update slot field (u64, 8 bytes).
    pub slot_offset: usize,

    /// Byte offset of the last-update timestamp (i64, 8 bytes). Optional.
    pub timestamp_offset: Option<usize>,

    /// Maximum staleness in slots.
    pub max_staleness_slots: u64,

    /// Maximum price deviation in bps from last-known price. Optional.
    pub max_deviation_bps: Option<u64>,

    /// Expected owner program pubkey (base58). Strongly recommended.
    pub expected_owner: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Recovery / Emergency Bypass (§9)
// ═══════════════════════════════════════════════════════════════════════════

/// Recovery configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConfig {
    /// Emergency bypass settings.
    pub emergency_bypass: Option<EmergencyBypassConfig>,

    /// Guardian rotation settings.
    pub guardian_rotation: Option<GuardianRotationConfig>,

    /// Unpause settings.
    pub unpause: Option<UnpauseConfig>,
}

/// Emergency bypass configuration (§9.1-9.2).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyBypassConfig {
    /// Enable emergency bypass capability.
    #[serde(default)]
    pub enabled: bool,

    /// Guardian key names (references into `[keys]`).
    pub signers: Vec<String>,

    /// M-of-N threshold for activation.
    pub threshold: u32,

    /// Cooldown between activations (in slots).
    #[serde(default = "default_cooldown_slots")]
    pub cooldown_slots: u64,

    /// Auto-revert duration (in slots). Default ~30min.
    #[serde(default = "default_max_duration_slots")]
    pub max_duration_slots: u64,
}

/// Guardian rotation configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianRotationConfig {
    /// Who can propose a rotation (key name from `[keys]`).
    pub proposer: String,

    /// Timelock duration in slots before rotation takes effect.
    #[serde(default = "default_timelock_slots")]
    pub timelock_slots: u64,
}

/// Unpause configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnpauseConfig {
    /// Type: `"multisig"` or `"single"`.
    #[serde(rename = "type")]
    pub unpause_type: String,

    /// Signer key names.
    pub signers: Vec<String>,

    /// M-of-N threshold.
    pub threshold: u32,

    /// Cooldown in slots.
    #[serde(default = "default_unpause_cooldown")]
    pub cooldown_slots: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Keys
// ═══════════════════════════════════════════════════════════════════════════

/// Named keys configuration — maps logical names to base58 pubkeys.
///
/// Used by `#[authority(cranker)]` and `recovery.emergency_bypass.signers`.
pub type KeysConfig = HashMap<String, String>;

// ═══════════════════════════════════════════════════════════════════════════
// Account Field Declarations (§4 — Snapshot Field Resolution)
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for a single account type used in snapshot field resolution.
///
/// Declared in `sandbox.toml` under `[accounts.<name>]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// The Rust struct type name (e.g., "Market", "UserPosition").
    #[serde(rename = "type")]
    pub account_type: String,

    /// Optional 8-byte Anchor discriminator.
    pub discriminator: Option<Vec<u8>>,

    /// Field declarations mapping field name → field config.
    #[serde(default)]
    pub fields: HashMap<String, FieldConfig>,
}

/// Configuration for a single field within an account.
///
/// Supports two strategies:
/// - **Fixed offset (Strategy A):** `offset = N` — compile-time known byte offset.
/// - **Borsh prefix (Strategy B):** `after = [...]` — preceding variable-length types.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldConfig {
    /// The primitive type name: "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "bool", "Pubkey".
    #[serde(rename = "type")]
    pub field_type: String,

    /// Strategy A: fixed byte offset from start of account data (including discriminator).
    pub offset: Option<usize>,

    /// Strategy B: list of preceding variable-length type descriptors.
    /// Each string describes a Borsh-serialized type to skip over at runtime.
    /// Examples: "Option<Pubkey>", "Vec<u64>", "String", "u64", "[u8; 32]".
    pub after: Option<Vec<String>>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Alerts
// ═══════════════════════════════════════════════════════════════════════════

/// Off-chain alert configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertsConfig {
    /// Named alert rules (e.g. `watcher_breaker`).
    #[serde(flatten)]
    pub rules: HashMap<String, AlertRule>,
}

/// A single alert rule for the off-chain watcher.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertRule {
    /// Trigger condition (human-readable, parsed by watcher).
    pub trigger: String,

    /// Action to take. Must NOT be `"auto_pause"` (griefing vector, §6.5).
    pub action: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Default value functions
// ═══════════════════════════════════════════════════════════════════════════

fn default_true() -> bool {
    true
}

fn default_scope() -> CircuitBreakerScope {
    CircuitBreakerScope::Global
}

fn default_action() -> BreakerAction {
    BreakerAction::RejectCurrent
}

fn default_reentrancy_mode() -> ReentrancyMode {
    ReentrancyMode::Guard
}

fn default_cooldown_slots() -> u64 {
    600
}

fn default_max_duration_slots() -> u64 {
    4500 // ~30 minutes at 400ms/slot
}

fn default_timelock_slots() -> u64 {
    7200 // ~48 minutes
}

fn default_unpause_cooldown() -> u64 {
    300
}

// ═══════════════════════════════════════════════════════════════════════════
// Parsing + Validation
// ═══════════════════════════════════════════════════════════════════════════

/// Parse a TOML string into a validated `SandboxConfig`.
pub fn parse_config(toml_str: &str) -> Result<SandboxConfig, String> {
    let config: SandboxConfig =
        toml::from_str(toml_str).map_err(|e| format!("Failed to parse sandbox.toml: {e}"))?;

    validate_config(&config)?;
    Ok(config)
}

/// Load and parse a `sandbox.toml` file from disk.
pub fn load_config(path: &str) -> Result<SandboxConfig, String> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read {path}: {e}"))?;
    parse_config(&contents)
}

/// Validate cross-field constraints that serde alone can't enforce.
fn validate_config(config: &SandboxConfig) -> Result<(), String> {
    if let Some(cb) = &config.circuit_breakers {
        validate_circuit_breakers(cb)?;
    }

    if let Some(recovery) = &config.recovery {
        validate_recovery(recovery, &config.keys)?;
    }

    // Validate alert actions aren't auto_pause (§6.5 — griefing vector)
    if let Some(alerts) = &config.alerts {
        for (name, rule) in &alerts.rules {
            if rule.action.contains("auto_pause") {
                return Err(format!(
                    "Alert rule '{name}' uses auto_pause which is forbidden (griefing vector, §6.5). \
                     Use notify_guardians_to_pause instead."
                ));
            }
        }
    }

    Ok(())
}

/// Validate circuit breaker configuration.
fn validate_circuit_breakers(cb: &CircuitBreakerConfig) -> Result<(), String> {
    if !cb.enabled {
        return Ok(());
    }

    // §8.5: per_market requires market_account
    if cb.scope == CircuitBreakerScope::PerMarket {
        if cb.market_account.is_none() {
            return Err(
                "circuit_breakers.scope = \"per_market\" requires market_account to be set"
                    .to_string(),
            );
        }

        // §8.6: per_market requires global_aggregate enabled
        match &cb.global_aggregate {
            None => {
                return Err(
                    "circuit_breakers.scope = \"per_market\" requires \
                     [circuit_breakers.global_aggregate] with enabled = true (§8.6)"
                        .to_string(),
                );
            }
            Some(ga) if !ga.enabled => {
                return Err(
                    "circuit_breakers.global_aggregate.enabled must be true \
                     when scope = \"per_market\" (§8.6)"
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    // Validation: at least one category budget must exist when enabled
    if let Some(tvl) = &cb.tvl_cliff {
        if tvl.budgets.is_empty() {
            return Err(
                "circuit_breakers.tvl_cliff requires at least one budget entry \
                 (e.g. default = { max_decrease_pct = 10 })"
                    .to_string(),
            );
        }
    }

    Ok(())
}

/// Validate recovery configuration.
fn validate_recovery(recovery: &RecoveryConfig, keys: &Option<KeysConfig>) -> Result<(), String> {
    if let Some(bypass) = &recovery.emergency_bypass {
        if !bypass.enabled {
            return Ok(());
        }

        if bypass.signers.is_empty() {
            return Err(
                "recovery.emergency_bypass.signers must not be empty when enabled".to_string(),
            );
        }

        if bypass.threshold == 0 {
            return Err(
                "recovery.emergency_bypass.threshold must be >= 1".to_string(),
            );
        }

        if bypass.threshold as usize > bypass.signers.len() {
            return Err(format!(
                "recovery.emergency_bypass.threshold ({}) exceeds number of signers ({})",
                bypass.threshold,
                bypass.signers.len()
            ));
        }

        // Validate signer names reference keys that exist
        if let Some(keys_map) = keys {
            for signer in &bypass.signers {
                if !keys_map.contains_key(signer) {
                    return Err(format!(
                        "recovery.emergency_bypass.signers references unknown key '{signer}'. \
                         Add it to [keys]."
                    ));
                }
            }
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid config — everything optional.
    #[test]
    fn parse_empty_config() {
        let config = parse_config("").unwrap();
        assert!(config.circuit_breakers.is_none());
        assert!(config.reentrancy.is_none());
        assert!(config.rate_limits.is_none());
        assert!(config.recovery.is_none());
        assert!(config.keys.is_none());
        assert!(config.alerts.is_none());
    }

    /// Full circuit breaker config from spec §6.2.
    #[test]
    fn parse_full_circuit_breaker_config() {
        let toml = r#"
[circuit_breakers]
enabled = true
scope = "global"

[circuit_breakers.categories]
withdrawal = ["close_position", "withdraw"]
liquidation = ["liquidate"]
deposit = ["deposit", "open_position"]

[circuit_breakers.tvl_cliff]
track_field = "market.vault_balance"
window_slots = 1500
window_seconds = 600
action = "reject_current"
high_water_mark = true

[circuit_breakers.tvl_cliff.budgets]
withdrawal = { max_decrease_pct = 15 }
liquidation = { max_decrease_pct = 25 }
default = { max_decrease_pct = 10 }

[circuit_breakers.tvl_cliff.exempt]
instructions = ["liquidate"]

[circuit_breakers.global_aggregate]
enabled = true
track_field = "market.vault_balance"
max_decrease_pct = 25
action = "reject_current"
"#;
        let config = parse_config(toml).unwrap();
        let cb = config.circuit_breakers.unwrap();
        assert!(cb.enabled);
        assert_eq!(cb.scope, CircuitBreakerScope::Global);
        assert_eq!(cb.categories.len(), 3);
        assert_eq!(
            cb.categories["withdrawal"],
            vec!["close_position", "withdraw"]
        );

        let tvl = cb.tvl_cliff.unwrap();
        assert_eq!(tvl.track_field, "market.vault_balance");
        assert_eq!(tvl.window_slots, 1500);
        assert_eq!(tvl.window_seconds, Some(600));
        assert_eq!(tvl.action, BreakerAction::RejectCurrent);
        assert!(tvl.high_water_mark);
        assert_eq!(tvl.budgets.len(), 3);
        assert_eq!(tvl.budgets["withdrawal"].max_decrease_pct, 15);
        assert_eq!(tvl.budgets["liquidation"].max_decrease_pct, 25);
        assert_eq!(tvl.budgets["default"].max_decrease_pct, 10);

        let exempt = tvl.exempt.unwrap();
        assert_eq!(exempt.instructions, vec!["liquidate"]);

        let ga = cb.global_aggregate.unwrap();
        assert!(ga.enabled);
        assert_eq!(ga.max_decrease_pct, 25);
    }

    /// Reentrancy config (§7).
    #[test]
    fn parse_reentrancy_config() {
        let toml = r#"
[reentrancy]
mode = "guard"
"#;
        let config = parse_config(toml).unwrap();
        let re = config.reentrancy.unwrap();
        assert_eq!(re.mode, ReentrancyMode::Guard);
    }

    #[test]
    fn parse_reentrancy_reject() {
        let config = parse_config("[reentrancy]\nmode = \"reject\"").unwrap();
        assert_eq!(
            config.reentrancy.unwrap().mode,
            ReentrancyMode::Reject
        );
    }

    #[test]
    fn parse_reentrancy_full() {
        let config = parse_config("[reentrancy]\nmode = \"full\"").unwrap();
        assert_eq!(
            config.reentrancy.unwrap().mode,
            ReentrancyMode::Full
        );
    }

    /// Reentrancy defaults to guard mode.
    #[test]
    fn reentrancy_defaults_to_guard() {
        let config = parse_config("[reentrancy]").unwrap();
        assert_eq!(
            config.reentrancy.unwrap().mode,
            ReentrancyMode::Guard
        );
    }

    /// Rate limit config.
    #[test]
    fn parse_rate_limits() {
        let toml = r#"
[rate_limits]
global = { window_slots = 150, max_count = 100 }
per_signer = { window_slots = 50, max_count = 10 }
"#;
        let config = parse_config(toml).unwrap();
        let rl = config.rate_limits.unwrap();
        let global = rl.global.unwrap();
        assert_eq!(global.window_slots, 150);
        assert_eq!(global.max_count, 100);
        let per = rl.per_signer.unwrap();
        assert_eq!(per.window_slots, 50);
        assert_eq!(per.max_count, 10);
    }

    /// Recovery / emergency bypass config (§9).
    #[test]
    fn parse_recovery_config() {
        let toml = r#"
[keys]
guardian_1 = "G1_PUBKEY_BASE58"
guardian_2 = "G2_PUBKEY_BASE58"

[recovery.emergency_bypass]
enabled = true
signers = ["guardian_1", "guardian_2"]
threshold = 2
cooldown_slots = 600
max_duration_slots = 4500
"#;
        let config = parse_config(toml).unwrap();
        let bypass = config.recovery.unwrap().emergency_bypass.unwrap();
        assert!(bypass.enabled);
        assert_eq!(bypass.signers, vec!["guardian_1", "guardian_2"]);
        assert_eq!(bypass.threshold, 2);
        assert_eq!(bypass.cooldown_slots, 600);
        assert_eq!(bypass.max_duration_slots, 4500);
    }

    /// Keys config.
    #[test]
    fn parse_keys() {
        let toml = r#"
[keys]
admin = "ADMIN_PUBKEY_BASE58"
cranker = "CRANKER_PUBKEY_BASE58"
guardian_1 = "G1_PUBKEY_BASE58"
"#;
        let config = parse_config(toml).unwrap();
        let keys = config.keys.unwrap();
        assert_eq!(keys["admin"], "ADMIN_PUBKEY_BASE58");
        assert_eq!(keys["cranker"], "CRANKER_PUBKEY_BASE58");
        assert_eq!(keys["guardian_1"], "G1_PUBKEY_BASE58");
    }

    // ── Validation tests ──

    /// per_market scope requires market_account.
    #[test]
    fn validate_per_market_requires_market_account() {
        let toml = r#"
[circuit_breakers]
enabled = true
scope = "per_market"

[circuit_breakers.global_aggregate]
enabled = true
track_field = "market.vault_balance"
max_decrease_pct = 25
action = "reject_current"
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.contains("market_account"), "got: {err}");
    }

    /// per_market scope requires global_aggregate enabled (§8.6).
    #[test]
    fn validate_per_market_requires_global_aggregate() {
        let toml = r#"
[circuit_breakers]
enabled = true
scope = "per_market"
market_account = "ctx.accounts.market"
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.contains("global_aggregate"), "got: {err}");
    }

    /// per_market with global_aggregate disabled is an error.
    #[test]
    fn validate_per_market_global_aggregate_must_be_enabled() {
        let toml = r#"
[circuit_breakers]
enabled = true
scope = "per_market"
market_account = "ctx.accounts.market"

[circuit_breakers.global_aggregate]
enabled = false
track_field = "market.vault_balance"
max_decrease_pct = 25
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.contains("enabled must be true"), "got: {err}");
    }

    /// tvl_cliff requires at least one budget.
    #[test]
    fn validate_tvl_cliff_requires_budgets() {
        let toml = r#"
[circuit_breakers]
enabled = true

[circuit_breakers.tvl_cliff]
track_field = "market.vault_balance"
window_slots = 1500
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.contains("at least one budget"), "got: {err}");
    }

    /// Emergency bypass threshold can't exceed signer count.
    #[test]
    fn validate_bypass_threshold_exceeds_signers() {
        let toml = r#"
[keys]
guardian_1 = "G1"

[recovery.emergency_bypass]
enabled = true
signers = ["guardian_1"]
threshold = 5
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.contains("exceeds number of signers"), "got: {err}");
    }

    /// Emergency bypass signer must exist in [keys].
    #[test]
    fn validate_bypass_signer_references_keys() {
        let toml = r#"
[keys]
guardian_1 = "G1"

[recovery.emergency_bypass]
enabled = true
signers = ["guardian_1", "unknown_guardian"]
threshold = 1
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.contains("unknown key 'unknown_guardian'"), "got: {err}");
    }

    /// Alert actions must not be auto_pause (§6.5).
    #[test]
    fn validate_alert_auto_pause_forbidden() {
        let toml = r#"
[alerts.watcher_breaker]
trigger = "5 invariant_violation events in 300 seconds"
action = "auto_pause"
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.contains("auto_pause"), "got: {err}");
    }

    /// Disabled circuit breakers skip validation.
    #[test]
    fn disabled_circuit_breakers_skip_validation() {
        let toml = r#"
[circuit_breakers]
enabled = false
scope = "per_market"
"#;
        // Should not error — validation skipped when disabled
        parse_config(toml).unwrap();
    }

    /// Disabled emergency bypass skips signer validation.
    #[test]
    fn disabled_bypass_skips_validation() {
        let toml = r#"
[recovery.emergency_bypass]
enabled = false
signers = []
threshold = 0
"#;
        parse_config(toml).unwrap();
    }

    /// Default values are applied correctly.
    #[test]
    fn defaults_applied() {
        let toml = r#"
[circuit_breakers]

[circuit_breakers.tvl_cliff]
track_field = "market.vault_balance"
window_slots = 1500

[circuit_breakers.tvl_cliff.budgets]
default = { max_decrease_pct = 10 }
"#;
        let config = parse_config(toml).unwrap();
        let cb = config.circuit_breakers.unwrap();
        assert!(cb.enabled); // default_true
        assert_eq!(cb.scope, CircuitBreakerScope::Global); // default

        let tvl = cb.tvl_cliff.unwrap();
        assert_eq!(tvl.action, BreakerAction::RejectCurrent); // default
        assert!(!tvl.high_water_mark); // serde default false
    }

    /// Full realistic config combining everything.
    #[test]
    fn parse_full_realistic_config() {
        let toml = r#"
[keys]
admin = "ADMIN_PUBKEY_BASE58"
cranker = "CRANKER_PUBKEY_BASE58"
guardian_1 = "G1_PUBKEY_BASE58"
guardian_2 = "G2_PUBKEY_BASE58"

[reentrancy]
mode = "guard"

[circuit_breakers]
enabled = true
scope = "per_market"
market_account = "ctx.accounts.market"

[circuit_breakers.categories]
withdrawal = ["close_position", "withdraw"]
liquidation = ["liquidate"]

[circuit_breakers.tvl_cliff]
track_field = "market.vault_balance"
window_slots = 1500
window_seconds = 600
action = "reject_current"
high_water_mark = true

[circuit_breakers.tvl_cliff.budgets]
withdrawal = { max_decrease_pct = 15 }
liquidation = { max_decrease_pct = 25 }
default = { max_decrease_pct = 10 }

[circuit_breakers.global_aggregate]
enabled = true
track_field = "market.vault_balance"
max_decrease_pct = 25
action = "reject_current"

[rate_limits]
global = { window_slots = 150, max_count = 100 }
per_signer = { window_slots = 50, max_count = 10 }

[recovery.emergency_bypass]
enabled = true
signers = ["guardian_1", "guardian_2"]
threshold = 2
cooldown_slots = 600
max_duration_slots = 4500

[alerts.watcher_breaker]
trigger = "5 invariant_violation events in 300 seconds"
action = "notify_guardians_to_pause"
"#;
        let config = parse_config(toml).unwrap();
        assert!(config.circuit_breakers.is_some());
        assert!(config.reentrancy.is_some());
        assert!(config.rate_limits.is_some());
        assert!(config.recovery.is_some());
        assert!(config.keys.is_some());
        assert!(config.alerts.is_some());

        let cb = config.circuit_breakers.unwrap();
        assert_eq!(cb.scope, CircuitBreakerScope::PerMarket);
        assert!(cb.global_aggregate.unwrap().enabled);
    }

    /// Invalid TOML syntax produces a clear error.
    #[test]
    fn invalid_toml_syntax() {
        let err = parse_config("this is not valid toml [[[").unwrap_err();
        assert!(err.contains("Failed to parse"), "got: {err}");
    }

    /// Unknown top-level key is rejected (deny_unknown_fields).
    #[test]
    fn unknown_top_level_key_rejected() {
        let err = parse_config("bogus_section = true").unwrap_err();
        assert!(err.contains("Failed to parse"), "got: {err}");
    }

    /// Emergency bypass threshold = 0 is rejected.
    #[test]
    fn validate_bypass_threshold_zero() {
        let toml = r#"
[keys]
g1 = "G1"

[recovery.emergency_bypass]
enabled = true
signers = ["g1"]
threshold = 0
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.contains("threshold must be >= 1"), "got: {err}");
    }

    /// Emergency bypass with empty signers is rejected.
    #[test]
    fn validate_bypass_empty_signers() {
        let toml = r#"
[recovery.emergency_bypass]
enabled = true
signers = []
threshold = 1
"#;
        let err = parse_config(toml).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }
}

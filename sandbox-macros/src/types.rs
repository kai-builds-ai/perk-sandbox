//! types.rs — Shared types for the PERK Sandbox macro crate.
//!
//! Single source of truth for types used across multiple modules.
//! All other modules import from here instead of defining their own.

// ═══════════════════════════════════════════════════════════════════════════
// Invariant Types (canonical — 18 built-in + conditional + named)
// ═══════════════════════════════════════════════════════════════════════════

/// Direction for `monotonic` invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonotonicDirection {
    Increasing,
    Decreasing,
}

/// All invariant types supported by the sandbox.
#[derive(Debug, Clone)]
pub enum InvariantType {
    /// `gte(lhs = "a.x", rhs = "a.y")` — field A >= field B after ix
    Gte { lhs: String, rhs: String },
    /// `lte(lhs = "a.x", rhs = "a.y")` — field A <= field B
    Lte { lhs: String, rhs: String },
    /// `eq(lhs = "a.x", rhs = "a.y")` — field A == field B
    Eq { lhs: String, rhs: String },
    /// `immutable(field = "a.x")` — field unchanged
    Immutable { field: String },
    /// `non_negative(field = "a.x")` — field >= 0 (signed types)
    NonNegative { field: String },
    /// `max_decrease(field = "a.x", pct = 10)` — decrease by at most X%
    MaxDecrease { field: String, pct: u8 },
    /// `max_increase(field = "a.x", pct = 50, max_absolute = 1_000_000)`
    MaxIncrease {
        field: String,
        pct: u8,
        max_absolute: Option<u64>,
    },
    /// `delta_bound(field = "a.x", max = 1000)` — abs(before - after) <= max
    DeltaBound { field: String, max: u64 },
    /// `conserve(field = "a.x")` — sum unchanged across account type
    Conserve { field: String },
    /// `supply_conservation(mint = "token_mint")` — mint supply == sum balances
    SupplyConservation { mint: String },
    /// `lamport_conservation` — sum of lamport deltas == 0
    LamportConservation,
    /// `payout_bounded(outflow = "a.x", formula = "expr")` — outflow <= f(state)
    PayoutBounded { outflow: String, formula: String },
    /// `aggregate_gte(field = "a.x", aggregate = "a.y")` — sum across type >= field
    AggregateGte { field: String, aggregate: String },
    /// `account_guard` — no unauthorized account create/close
    AccountGuard,
    /// `custom(check = "my_fn", cu_budget = 50_000)` — developer-provided check
    Custom { check_fn: String, cu_budget: u32 },
    /// `tx_cumulative_decrease(field = "a.x", max_pct = 15)` — cross-ix cumulative check
    TxCumulativeDecrease { field: String, max_pct: u8 },
    /// `when(condition = "expr", inner_invariant)` — conditional invariant
    When {
        condition: String,
        inner: Box<InvariantType>,
    },
    /// `monotonic(field = "a.x", direction = "increasing")` — field only moves one way
    Monotonic {
        field: String,
        direction: MonotonicDirection,
    },
    /// Named reference to a `sandbox_invariant!` definition
    Named(String),
}

// ═══════════════════════════════════════════════════════════════════════════
// Bound Constraints
// ═══════════════════════════════════════════════════════════════════════════

/// Comparison operator for a bound constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundOp {
    /// `>=`
    Gte,
    /// `>`
    Gt,
    /// `<=`
    Lte,
    /// `<`
    Lt,
    /// `==`
    Eq,
    /// `!=`
    Neq,
}

impl BoundOp {
    /// Returns the Rust operator token string for diagnostics.
    pub fn as_str(&self) -> &'static str {
        match self {
            BoundOp::Gte => ">=",
            BoundOp::Gt => ">",
            BoundOp::Lte => "<=",
            BoundOp::Lt => "<",
            BoundOp::Eq => "==",
            BoundOp::Neq => "!=",
        }
    }
}

/// A single bound constraint: `field op value`.
#[derive(Debug, Clone)]
pub struct BoundConstraint {
    /// Name of the instruction argument (e.g., "leverage", "collateral").
    pub field_name: String,
    /// Comparison operator.
    pub op: BoundOp,
    /// Literal value to compare against. Stored as i128 to support both
    /// u64 and i64 ranges without loss.
    pub value: i128,
}

// ═══════════════════════════════════════════════════════════════════════════
// Instruction Categories
// ═══════════════════════════════════════════════════════════════════════════

/// Instruction category for circuit breaker routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionCategory {
    Withdrawal,
    Liquidation,
    Deposit,
    Default,
}

impl InstructionCategory {
    /// Returns the variant name as a string for codegen.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::Withdrawal => "Withdrawal",
            Self::Liquidation => "Liquidation",
            Self::Deposit => "Deposit",
            Self::Default => "Default",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Authority Requirements
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed authority requirement from a `#[authority(...)]` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityRequirement {
    /// First signer in the transaction. `#[authority(user)]`
    User,
    /// Must be a specific pubkey resolved from `[keys]` config.
    /// `#[authority(signer = "ADMIN_PUBKEY")]`
    Signer(String),
    /// Any of these pubkeys. `#[authority(any_of = ["ADMIN_1", "ADMIN_2"])]`
    AnyOf(Vec<String>),
    /// Owner of a specific account field. `#[authority(owner_of = "ctx.accounts.position")]`
    OwnerOf(String),
    /// Named role from `[keys]` config. `#[authority(cranker)]`
    Role(String),
}

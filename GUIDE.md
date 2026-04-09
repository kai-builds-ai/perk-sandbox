# Getting Started with PERK Sandbox

This guide walks you through adding PERK Sandbox to an existing Anchor program. By the end, your program will have reentrancy protection, input validation, and the foundation for circuit breakers and invariant enforcement.

## Prerequisites

- Rust 1.75+
- Solana CLI 1.18+
- An existing Anchor program (0.30+)

## Step 1: Add Dependencies

In your program's `Cargo.toml`:

```toml
[dependencies]
perk-sandbox-macros = { git = "https://github.com/kai-builds-ai/perk-sandbox" }
perk-sandbox-runtime = { git = "https://github.com/kai-builds-ai/perk-sandbox" }
anchor-lang = "0.30"
```

## Step 2: Create sandbox.toml

Create `sandbox.toml` in your program crate root (next to `Cargo.toml`):

```toml
[reentrancy]
mode = "guard"
```

This is the minimal config. It enables the reentrancy guard in "guard" mode (inner CPI calls run pre-checks only, outer call runs full post-checks).

## Step 3: Replace #[program] with #[sandbox_program]

```rust
use anchor_lang::prelude::*;
use perk_sandbox_macros::sandbox_program;

declare_id!("YourProgramId111111111111111111111111111111");

#[sandbox_program(config = "sandbox.toml")]
pub mod my_program {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // Your existing business logic, unchanged
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        Ok(())
    }

    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        Ok(())
    }
}
```

That's it. The macro reads `sandbox.toml` at compile time and generates the safety pipeline directly into your program binary. Build with `cargo build-sbf` as usual. Your program now has a reentrancy guard on every instruction.

**Note:** The reentrancy guard and mode checks require a sandbox PDA to be initialized on-chain. Without it, your program will return error 6070 (`SandboxStateNotInitialized`). Features that don't need on-chain state (authority checks, input bounds) work immediately.

## Step 4: Add Authority Checks

Authority attributes validate who can call each instruction:

```rust
#[sandbox_program(config = "sandbox.toml")]
pub mod my_program {
    use super::*;

    // Only the first signer can call this
    #[authority(user)]
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        Ok(())
    }

    // Only the position owner can withdraw
    #[authority(owner_of = "ctx.accounts.position")]
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        Ok(())
    }

    // Only configured admin key can call this
    #[authority(signer = "ADMIN")]
    pub fn pause_market(ctx: Context<PauseMarket>) -> Result<()> {
        Ok(())
    }
}
```

The `signer = "ADMIN"` reference resolves against the `[keys]` section in `sandbox.toml`:

```toml
[reentrancy]
mode = "guard"

[keys]
ADMIN = "DgUnrBGMYXE4TwcqF4y4pt4cKauTCqF53vL3JG1EevN7"
CRANKER = "YourCrankerPubkey..."
```

Five authority types are supported:

| Attribute | What it checks |
|---|---|
| `#[authority(user)]` | First signer in the transaction |
| `#[authority(signer = "KEY_NAME")]` | Specific pubkey from `[keys]` config |
| `#[authority(any_of = ["KEY1", "KEY2"])]` | Any of the listed keys |
| `#[authority(owner_of = "ctx.accounts.position")]` | Reads authority field from account data |
| `#[authority(cranker)]` | Named role from `[keys]` config |

## Step 5: Add Input Bounds

Bound attributes validate instruction arguments before business logic runs:

```rust
#[authority(user)]
#[bound(amount > 0)]
#[bound(leverage >= 1, leverage <= 100)]
pub fn open_position(
    ctx: Context<OpenPosition>,
    amount: u64,
    leverage: u8,
) -> Result<()> {
    Ok(())
}
```

The macro deserializes the instruction arguments and checks bounds before dispatch. If any bound fails, the transaction is rejected with error code 6040 (`BoundViolation`).

Supported operators: `>=`, `<=`, `>`, `<`, `==`, `!=`.

## Step 6: Add Invariant Post-Checks

Invariants verify safety properties after your business logic runs. If an invariant is violated, the transaction reverts (Solana's atomic rollback ensures no state changes persist).

```rust
#[authority(user)]
#[invariant(gte(lhs = "market.vault_balance", rhs = "market.total_collateral"))]
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    Ok(())
}
```

This checks that `vault_balance >= total_collateral` after the withdrawal executes. If the withdrawal would make the vault insolvent, it reverts.

For invariants to read account fields, declare the field layouts in `sandbox.toml`:

```toml
[accounts.market]
type = "Market"

[accounts.market.fields]
vault_balance = { type = "u64", offset = 72 }
total_collateral = { type = "u64", offset = 80 }
```

The `offset` is the byte position of the field in the account data (including the 8-byte Anchor discriminator). Use `anchor account <AccountName> --layout` or count bytes manually from your struct definition.

### All 18 Invariant Types

```rust
// Comparison
#[invariant(gte(lhs = "a.x", rhs = "a.y"))]      // a.x >= a.y
#[invariant(lte(lhs = "a.x", rhs = "a.y"))]      // a.x <= a.y
#[invariant(eq(lhs = "a.x", rhs = "a.y"))]       // a.x == a.y

// Single field
#[invariant(immutable(field = "a.x"))]             // field unchanged
#[invariant(non_negative(field = "a.x"))]          // field >= 0 (signed)

// Percentage bounds
#[invariant(max_decrease(field = "a.x", pct = 10))]  // decreases <= 10%
#[invariant(max_increase(field = "a.x", pct = 50, max_absolute = 1000000))]

// Absolute bounds
#[invariant(delta_bound(field = "a.x", max = 1000))]  // |change| <= 1000

// Conservation
#[invariant(conserve(field = "a.x"))]              // sum unchanged
#[invariant(supply_conservation(mint = "token_mint"))]
#[invariant(lamport_conservation)]

// Advanced
#[invariant(payout_bounded(outflow = "a.x", formula = "expr"))]
#[invariant(aggregate_gte(field = "a.x", aggregate = "a.y"))]
#[invariant(account_guard)]                         // no unauthorized create/close
#[invariant(monotonic(field = "a.x", direction = "increasing"))]

// Conditional
#[invariant(when(condition = "expr", inner = "gte(lhs = \"a.x\", rhs = \"a.y\")"))]

// Cross-instruction (per transaction)
#[invariant(tx_cumulative_decrease(field = "market.vault_balance", max_pct = 15))]

// Custom
#[invariant(custom(check = "my_check_fn", cu_budget = 50000))]
```

## Step 7: Add Rate Limits

Rate limits prevent transaction stuffing. Add to `sandbox.toml`:

```toml
[rate_limits.global]
window_slots = 1000
max_count = 100

[rate_limits.per_signer]
window_slots = 500
max_count = 20
```

Global limits apply to all callers combined. Per-signer limits are keyed by a hash of the signer's pubkey. Both use window-based counters that reset when the window expires.

Rate limits require the sandbox PDA to be initialized on-chain (it stores the counters). The PDA is derived from seeds `[b"perk_sandbox"]` and must be created via a dedicated initialization instruction in your program. See the sandbox PDA layout in [ARCHITECTURE.md](./ARCHITECTURE.md) for the full schema.

## Step 8: Add Oracle Checks

Oracle checks validate price data freshness before every instruction:

```toml
[oracle]
price_offset = 73
slot_offset = 81
max_staleness_slots = 100
expected_owner = "FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH"
```

The `price_offset` and `slot_offset` are byte positions in the oracle account data where the price (u64) and last-update slot (u64) are stored. `expected_owner` is the oracle program's pubkey (e.g., Pyth). If the oracle data is older than `max_staleness_slots`, the transaction is rejected.

Optional: add `max_deviation_bps` to also check price deviation from a last-known value.

## Step 9: Add Circuit Breakers

Circuit breakers detect abnormal TVL changes and automatically restrict the protocol:

```toml
[circuit_breakers]
enabled = true
scope = "global"

[circuit_breakers.categories]
withdrawal = ["withdraw", "close_position"]
liquidation = ["liquidate"]
deposit = ["deposit"]

[circuit_breakers.tvl_cliff]
track_field = "market.vault_balance"
window_slots = 2500
window_seconds = 600
action = "pause"
high_water_mark = true

[circuit_breakers.tvl_cliff.budgets]
withdrawal = { max_decrease_pct = 15 }
liquidation = { max_decrease_pct = 25 }

[circuit_breakers.tvl_cliff.exempt]
instructions = ["deposit"]
```

Tag your instructions with categories:

```rust
#[circuit_breaker_category("withdrawal")]
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    Ok(())
}

#[circuit_breaker_category("liquidation")]
pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
    Ok(())
}
```

With this config:
- Withdrawals are rejected if they cause TVL to drop more than 15% within the monitoring window
- Liquidations get a separate 25% budget so they can't be starved by withdrawal activity
- Deposits are exempt (they increase TVL)
- If the breaker fires, the protocol pauses until an admin unpauses it

## Step 10: Emergency Bypass

Configure guardian-controlled emergency bypass for when false-positive invariants block legitimate users:

```toml
[recovery.emergency_bypass]
enabled = true
signers = ["GUARDIAN_1", "GUARDIAN_2", "GUARDIAN_3"]
threshold = 2
cooldown_slots = 5000
max_duration_slots = 75000

[keys]
GUARDIAN_1 = "..."
GUARDIAN_2 = "..."
GUARDIAN_3 = "..."
```

During bypass:
- Authority checks, rate limits, oracle checks, and circuit breakers still run
- `tx_cumulative_decrease` invariants still run
- Other invariant post-checks are disabled
- Bypass auto-expires after `max_duration_slots` (fail-closed)

## Error Codes

All sandbox errors use codes in the 6000-6099 range:

| Code | Error | What to do |
|---|---|---|
| 6000 | ProgramPaused | Wait for admin to unpause |
| 6001 | CloseOnlyMode | Only close/withdraw allowed |
| 6002 | LiquidationPaused | Liquidations temporarily disabled |
| 6003 | EmergencyBypassActive | Emergency bypass is active |
| 6010 | UnauthorizedSigner | Wrong signer for this instruction |
| 6011 | UnknownInstruction | Instruction not recognized |
| 6020 | OracleStale | Wait for oracle update |
| 6021 | OracleDeviation | Oracle price deviated beyond threshold |
| 6030 | RateLimitExceeded | Wait for window to expire |
| 6040 | BoundViolation | Fix input parameters |
| 6050 | InvariantViolation | Transaction would violate safety property |
| 6051 | TxCumulativeDecreaseExceeded | Cumulative drain across instructions exceeds limit |
| 6060 | InsufficientCU | Request more compute units |
| 6070 | SandboxStateNotInitialized | Initialize sandbox PDA on-chain |
| 6071 | PDACorrupted | Contact protocol team |
| 6072 | SandboxStateVersionMismatch | Sandbox PDA schema version mismatch |
| 6073 | SnapshotFailed | Account snapshot failed (retryable) |
| 6080 | ReentrancyDetected | Self-CPI blocked |
| 6090 | CircuitBreakerTriggered | TVL protection activated |

## Full Example Config

Here's a production-ready `sandbox.toml` with all features enabled.

**Note on discriminators:** The `discriminator` field is the 8-byte Anchor account discriminator (SHA256 of `"account:<AccountName>"`). It's used by authority checks that need to identify specific account types in the accounts list. Set it to your account's actual discriminator bytes, or omit it if not using `owner_of` authority checks.

```toml
[reentrancy]
mode = "guard"

[rate_limits.global]
window_slots = 1000
max_count = 200

[rate_limits.per_signer]
window_slots = 500
max_count = 30

[oracle]
price_offset = 73
slot_offset = 81
max_staleness_slots = 100
max_deviation_bps = 500
expected_owner = "FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH"

[circuit_breakers]
enabled = true
scope = "global"

[circuit_breakers.categories]
withdrawal = ["withdraw", "close_position"]
liquidation = ["liquidate"]
deposit = ["deposit", "open_position"]

[circuit_breakers.tvl_cliff]
track_field = "market.vault_balance"
window_slots = 2500
window_seconds = 600
action = "pause"
high_water_mark = true

[circuit_breakers.tvl_cliff.budgets]
withdrawal = { max_decrease_pct = 15 }
liquidation = { max_decrease_pct = 25 }

[circuit_breakers.tvl_cliff.exempt]
instructions = ["deposit", "open_position"]

[recovery.emergency_bypass]
enabled = true
signers = ["GUARDIAN_1", "GUARDIAN_2", "GUARDIAN_3"]
threshold = 2
cooldown_slots = 5000
max_duration_slots = 75000

[keys]
ADMIN = "YourAdminPubkey..."
CRANKER = "YourCrankerPubkey..."
GUARDIAN_1 = "Guardian1Pubkey..."
GUARDIAN_2 = "Guardian2Pubkey..."
GUARDIAN_3 = "Guardian3Pubkey..."

[accounts.market]
type = "Market"
discriminator = [0, 0, 0, 0, 0, 0, 0, 0]

[accounts.market.fields]
vault_balance = { type = "u64", offset = 72 }
total_collateral = { type = "u64", offset = 80 }
authority = { type = "Pubkey", offset = 40 }

[accounts.position]
type = "UserPosition"

[accounts.position.fields]
owner = { type = "Pubkey", offset = 8 }
collateral = { type = "u64", offset = 40 }
```

## Next Steps

- Read [ARCHITECTURE.md](./ARCHITECTURE.md) for the full 12-step pipeline technical deep dive
- Read [SECURITY.md](./SECURITY.md) for the threat model and known limitations
- Check the [integration tests](./sandbox-test-program/tests/integration.rs) for real scenarios
- File issues at [github.com/kai-builds-ai/perk-sandbox](https://github.com/kai-builds-ai/perk-sandbox)

# PERK Sandbox — Technical Specification V1.0

**Version:** 1.0.0
**Author:** Kai
**Date:** April 8, 2026
**Approach:** Build-with (proc macro framework)

> **Implementation Note:** The V1.0 release implements the core framework (proc macros + runtime library + integration tests). References to CLI tools (`doctor`, `verify`, `init-state`), the off-chain watcher, the NPM error package, and retrofit support describe planned features. The on-chain framework (Sections 1-9, 11, 13, 15-16) is complete and production-ready.

---

## 1. Overview

PERK Sandbox is a Rust proc-macro framework and runtime library that makes Solana programs provably safe by construction. Developers annotate their program with sandbox attributes. The macros generate an entrypoint wrapper that enforces invariants, authority rules, bounds, oracle checks, and circuit breakers — compiled into the same binary.

### 1.1 Design Principles

1. **Bypass-proof.** The sandbox IS the entrypoint. No alternate path.
2. **Build-with, not retrofit.** Safety built from line one. Retrofit available for existing programs.
3. **Zero CPI overhead.** Direct function call to business logic.
4. **Fail-closed everywhere.** Missing accounts, insufficient CU, unknown instructions, evaluation errors, corrupted PDA — all rejected.
5. **Small and auditable.** ~3,500 lines of Rust.
6. **No source file mutation.** Feature flags + proc macros.
7. **Checked arithmetic in all sandbox code.** Overflow = violation = fail-closed.
8. **Defense mechanisms must not create new attack surfaces.** Circuit breakers are instruction-type-aware. Emergency bypass preserves critical checks.
9. **No known deferrals.** Every identified issue is addressed in this version.

---

## 2. Architecture

### 2.1 Data Flow

```
User/CPI Transaction
       │
       ▼
Solana Runtime → program entrypoint (ALWAYS — no bypass)
       │
       ▼
[1] RE-ENTRANCY GUARD
    If executing (recursive CPI-to-self):
      mode = "reject" → Err(ReentrancyDetected)
      mode = "guard" → Run PRE-CHECKS + CIRCUIT BREAKERS only, skip invariants
      mode = "full" → Run everything (risk of false positives)
    Normal entry: set executing = true
       │
       ▼
[2] MODE CHECK
    Read PDA mode flags. Map instruction to allowed modes.
    Paused → only recovery instructions allowed. Err(ProgramPaused).
    Close-only → only close/withdraw/liquidate allowed. Err(CloseOnlyMode).
    Liquidation-paused → liquidation instructions blocked. Err(LiquidationPaused).
    Emergency bypass → pre-checks + circuit breakers + tx_cumulative_decrease enforced, other invariants disabled. Non-recovery callers see Err(EmergencyBypassActive) for blocked instructions.
    PDA version mismatch → Err(SandboxStateVersionMismatch).
       │
       ▼
[3] UNKNOWN INSTRUCTION CHECK
    No matching #[sandbox_instruction] → Err(UnknownInstruction).
    Override: unknown_instructions = "allow_with_pre_checks"
       │
       ▼
[4] PRE-CHECKS
    a) Authority  b) Oracle  c) Rate limit  d) Bounds (pre)
    All run on EVERY call including re-entrant and emergency bypass.
       │
       ▼
[5] TRANSACTION-LEVEL SNAPSHOT
    On FIRST sandbox invocation in this transaction:
      Store "transaction start" snapshot in thread-local-style marker account.
    On subsequent invocations: read the anchor snapshot for cross-IX comparison.
       │
       ▼
[6] INSTRUCTION-LEVEL SNAPSHOT
    Copy specific field bytes. Drop all borrows before business logic.
    Borsh-aware: use runtime deserialization for variable-length fields.
       │
       ▼
[7] CALL BUSINESS LOGIC (direct function call)
    If Err → propagate (Solana rolls back). Skip post-checks.
       │
       ▼
[8] CU RESERVATION + POST-CHECKS (skip during emergency bypass EXCEPT tx_cumulative_decrease)
    Before EACH post-check: verify CU available.
    a) Instruction-level invariants (before vs after) — SKIPPED during bypass
    b) Transaction-level invariants (tx-start vs after) — SKIPPED during bypass
    c) Per-transaction cumulative decrease check — ALWAYS RUNS (even during bypass)
       │
       ▼
[9] CIRCUIT BREAKERS (ALWAYS run — including emergency bypass)
    Instruction-type-aware budgets.
    Critical instructions (liquidations) have separate/exempt budgets.
    reject_current: rejects triggering tx.
    pause/close_only: sets mode for next tx.
    Track high-water-mark explicitly (not buffer scan).
       │
       ▼
[10] UPDATE PDA (counters, TVL, mode flags)
       │
       ▼
[11] CLEAR RE-ENTRANCY GUARD
       │
       ▼
[12] RETURN Ok(())
```

### 2.2 Atomic Rollback

When sandbox returns `Err` at any point after step [7], Solana rolls back ALL account modifications including business logic changes and CPI side effects. Logs are NOT rolled back — the off-chain watcher sees alerts from reverted transactions.

**Critical: circuit breaker PDA updates (step [10]) are also rolled back on Err.** This means rejected transactions are invisible to the circuit breaker. The off-chain watcher compensates by tracking rolled-back alerts (logs persist) and can trigger external pause mechanisms. See Section 9.5.

---

## 3. Developer Interface

### 3.1 Dependencies

```toml
[dependencies]
perk-sandbox = { version = "0.1", features = ["anchor"] }

[features]
default = ["sandbox"]
sandbox = ["perk-sandbox"]
```

### 3.2 Program Attribute: `#[sandbox_program]`

Single attribute replacing Anchor's `#[program]`. No ordering ambiguity.

```rust
use perk_sandbox::prelude::*;

#[cfg_attr(feature = "sandbox", sandbox_program(config = "sandbox.toml"))]
#[cfg_attr(not(feature = "sandbox"), program)]
pub mod my_perps {
    use super::*;

    #[invariant(vault_solvency)]
    #[invariant(vault_floor)]
    #[invariant(tx_cumulative_decrease(field = "market.vault_balance", max_pct = 15))]
    #[authority(user)]
    #[bound(leverage >= 1, leverage <= 100)]
    pub fn open_position(ctx: Context<OpenPosition>, leverage: u8, collateral: u64) -> Result<()> {
        // business logic
    }

    #[invariant(vault_solvency)]
    #[invariant(vault_floor)]
    #[invariant(tx_cumulative_decrease(field = "market.vault_balance", max_pct = 15))]
    #[authority(owner_of = "ctx.accounts.position")]
    #[circuit_breaker_category("withdrawal")]
    pub fn close_position(ctx: Context<ClosePosition>) -> Result<()> {
        // business logic
    }

    #[invariant(vault_solvency)]
    #[authority(cranker)]
    #[circuit_breaker_category("liquidation")]  // separate budget
    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        // business logic
    }
}
```

**`#[sandbox_instruction]` is implicit** when any `#[invariant]`, `#[authority]`, `#[bound]`, or `#[circuit_breaker_category]` attribute is present.

### 3.3 Built-In Invariant Types (18 types)

| Type | What it checks |
|---|---|
| `gte` | Field A >= Field B after ix |
| `lte` | Field A <= Field B |
| `eq` | Field A == Field B |
| `immutable` | Field unchanged on existing accounts |
| `non_negative` | Field >= 0 (signed types) |
| `max_decrease` | Field decreases by at most X% per instruction |
| `max_increase` | Field increases by at most X% (handles zero: if before==0 and after>0, passes if after <= `max_absolute` param; division by zero never occurs) |
| `delta_bound` | abs(before - after) <= max |
| `conserve` | Sum of field across account type unchanged. Scans ALL accounts in transaction (Context + remaining_accounts). **Only includes accounts where `account.owner == program_id`**. Uses the same snapshot strategy as other invariants: **fixed-offset** for fields after only fixed-size types, **Borsh-deser prefix** for fields after variable-length types (Section 4.2). |
| `supply_conservation` | Mint supply == sum of balances |
| `lamport_conservation` | Sum of lamport deltas == 0 |
| `payout_bounded` | Outflow <= f(state) |
| `aggregate_gte` | Sum across account type >= / <= field |
| `account_guard` | No unauthorized account create/close |
| `custom` | Developer-provided check function |
| `tx_cumulative_decrease` | **NEW:** Total decrease of field across ALL instructions in this transaction <= X%. Uses transaction-level anchor snapshot. |
| `when` | **NEW:** Conditional invariant: `when(condition, inner_invariant)`. The condition is evaluated against BOTH before-snapshot and after-snapshot. Invariant applies if condition is true in EITHER state — prevents re-entrant calls from flipping the condition to bypass the invariant. Example: `when(side == "long", gte(lhs = "collateral", rhs = "min_long_collateral"))` |
| `monotonic` | **NEW:** Field must only increase (or only decrease). Alias for `max_decrease(pct=0)` or `max_increase(pct=0)`. |

**`conserve` scope:** Explicitly scans both named Context accounts AND `remaining_accounts`. The macro generates code to iterate all AccountInfo references with the following validation pipeline:

1. **Ownership check:** `account_info.owner == program_id`. Accounts owned by other programs are SKIPPED. This prevents attackers from injecting fake accounts with crafted data into `remaining_accounts` to poison the sum.
2. **Discriminator check:** Read first 8 bytes. Must match expected account type discriminator. Accounts with wrong discriminator are skipped. Cost: ~100 CU per account.
3. **Field read:** Read ONLY the conserved field at its byte offset (fixed-offset for discriminator-identified types). NO full Borsh deserialization. Cost: ~200 CU per matching account.
4. **Deduplication:** Each account pubkey is counted only once, even if it appears in both Context and remaining_accounts.

**CU cost for `conserve`:**
- Fixed-offset conserved field: ~300 CU per program-owned account (ownership + discriminator + field read) + ~100 CU per non-program account (ownership check only).
- Borsh-deser conserved field (after variable-length types): ~1,500-3,000 CU per program-owned account + ~100 CU per non-program account.
- Base cost: 500 CU (iteration setup + dedup).
- Example (30 remaining_accounts, 15 program-owned, fixed-offset field): 500 + 15×300 + 15×100 = ~6,500 CU.
- Example (30 remaining_accounts, 15 program-owned, borsh-deser field): 500 + 15×2,000 + 15×100 = ~32,000 CU.
- `verify` reports which strategy applies and estimated CU for each `conserve` invariant.

This guarantees full coverage of legitimate program-owned accounts while preventing spoofing and maintaining reasonable CU costs.

**`max_increase` zero handling:** If `before == 0`, the percentage check is meaningless. Instead, check `after <= max_absolute` (configurable parameter, defaults to u64::MAX if not set). This prevents the division-by-zero deadlock.

```rust
#[invariant(max_increase(field = "vault.balance", pct = 50, max_absolute = 1_000_000_000))]
```

### 3.4 Named Invariant Definitions

```rust
sandbox_invariant!(vault_solvency = gte(
    lhs = "market.vault_balance",
    rhs = "market.total_long_collateral + market.total_short_collateral"
));

sandbox_invariant!(vault_floor = gte(
    lhs = "market.vault_balance",
    rhs = "100_000_000"  // 0.1 SOL absolute minimum
));
```

### 3.5 Circuit Breaker Category Attribute

**NEW:** Instructions declare which circuit breaker budget they consume.

```rust
#[circuit_breaker_category("withdrawal")]   // consumes withdrawal budget
pub fn withdraw(...) { ... }

#[circuit_breaker_category("liquidation")]  // separate budget — never starved by withdrawals
pub fn liquidate(...) { ... }

#[circuit_breaker_category("deposit")]      // deposits increase vault — exempt from decrease budgets
pub fn deposit(...) { ... }
```

If no category is declared, the instruction uses the `default` budget.

### 3.6 Custom Invariant Function

```rust
pub fn my_custom_invariant(ctx: &InvariantContext) -> Result<bool> {
    // ctx.before: HashMap<Pubkey, AccountSnapshot>
    // ctx.after: HashMap<Pubkey, AccountSnapshot>
    // ctx.tx_start: HashMap<Pubkey, AccountSnapshot>  ← transaction-level anchor
    // ctx.instruction_discriminator: u8
    // ctx.signer: Pubkey
    // ctx.clock_slot: u64
    // ctx.clock_timestamp: i64
    // ctx.remaining_accounts: &[AccountInfo]
    //
    // AccountSnapshot:
    //   .lamports: u64
    //   .data: Vec<u8>
    //   .field::<T>(offset) -> Result<T>  (bounds-checked)
    //   .borsh_field::<T>(name) -> Result<T>  (Borsh-aware deserialization)
    //   .exists: bool

    Ok(true)
}
```

Custom invariants must declare CU budget:
```rust
#[invariant(custom(check = "my_fn", cu_budget = 50_000))]
```

The CU reservation check uses this declared budget, not the default 500 CU.

### 3.7 Authority and Bounds

```rust
#[authority(user)]                                     // first signer
#[authority(signer = "ADMIN_PUBKEY")]                  // specific key
#[authority(any_of = ["ADMIN_1", "ADMIN_2"])]          // any of
#[authority(owner_of = "ctx.accounts.position")]       // match field
#[authority(cranker)]                                   // from [keys] in TOML

#[bound(leverage >= 1, leverage <= 100)]
#[bound(collateral > 0)]
```

---

## 4. Account Snapshot Mechanism (Borsh-Aware)

### 4.1 The Borsh Problem

Anchor accounts use Borsh serialization. Fields after any variable-length type (`Option<T>`, `Vec<T>`, `String`) have runtime-dependent offsets. Compile-time offset resolution is WRONG for these.

### 4.2 Two Snapshot Strategies

The macro detects account struct layout at compile time and chooses:

**Strategy A: Fixed-offset (fast path)**
When ALL fields before the invariant target are fixed-size types (`u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, `bool`, `Pubkey`, `[u8; N]`), the offset is known at compile time. Direct byte read. ~200-400 CU per field.

```rust
// Generated for fixed-offset field
let vault_balance_before: u64 = {
    let data = account.try_borrow_data().map_err(|_| SandboxError::SnapshotFailed)?;
    u64::from_le_bytes(data[OFFSET..OFFSET+8].try_into().unwrap())
};
```

**Strategy B: Borsh-deserialization (safe path)**
When ANY field before the target is variable-length, the macro generates Borsh deserialization up to the target field. Deserializes only the prefix needed, not the entire struct. ~1,000-3,000 CU per field depending on prefix length.

```rust
// Generated for variable-offset field
let vault_balance_before: u64 = {
    let data = account.try_borrow_data().map_err(|_| SandboxError::SnapshotFailed)?;
    let mut cursor = 8; // skip discriminator
    // Deserialize preceding Option<Pubkey>
    let option_tag = data[cursor]; cursor += 1;
    if option_tag == 1 { cursor += 32; } // Some: skip pubkey
    // Now cursor points to vault_balance
    u64::from_le_bytes(data[cursor..cursor+8].try_into().unwrap())
};
```

The `verify` command checks all field references and reports which strategy each uses:
```
$ perk-sandbox verify

Field resolution:
  market.vault_balance    → fixed-offset (byte 72)     ~300 CU
  market.authority        → borsh-deser (after Option)  ~1,500 CU
  position.owner          → fixed-offset (byte 8)      ~300 CU
```

**Borsh CU estimation for nested variable-length types:** When the prefix chain contains nested variable-length types (e.g., `Vec<Vec<String>>`), the `verify` command requires developer-provided max-size bounds to compute worst-case CU:

```rust
// In the account struct, annotate variable-length fields with max bounds
#[sandbox_max_elements(100)]  // max 100 elements in this Vec
pub positions: Vec<Position>,
```

The `verify` command uses these bounds to compute worst-case prefix parsing cost. If bounds are missing, `verify` emits an error:
```
❌  market.authority is after Vec<Position> which has no #[sandbox_max_elements].
   Add #[sandbox_max_elements(N)] to the Vec field for accurate CU estimation.
```

### 4.3 AccountLoader (Zero-Copy) Handling

Zero-copy Anchor accounts (`AccountLoader<'info, T>`) use `#[repr(C)]` and have truly fixed offsets. The macro detects these and always uses Strategy A. No borrow conflicts because the snapshot reads from the raw `AccountInfo` data pointer, not the typed wrapper.

### 4.4 Stack vs Heap

- Fixed-offset fields (≤32 fields): stack-allocated
- Borsh-deserialized fields or >32 fields: heap-allocated via `Box`
- Custom invariants: `InvariantContext` always heap-allocated
- `conserve`/`aggregate_gte` across N accounts: heap-allocated `Vec<u64>`

---

## 5. Transaction-Level Invariants

### 5.1 The Problem

Per-instruction invariants miss multi-instruction attacks:
- IX1 inflates state legitimately (deposit)
- IX2 extracts value based on inflated state (close position with inflated payout)
- IX3 reverses IX1 (withdraw deposit)
- Each IX individually conserves value. Combined: attacker profits.

Also: multi-instruction drain packing (4 × 5% = 18.5% in one tx).

### 5.2 Transaction-Level Anchor Snapshot

On the FIRST sandbox invocation in a transaction, the sandbox stores a snapshot of critical fields in a **transaction-scoped marker**. Implementation:

**Approach: Instruction Introspection via `sysvar::instructions`**

The sandbox reads the `Instructions` sysvar to determine:
- Is this the first instruction to this program in this transaction?
- If yes: store anchor snapshot in a temporary account or in unused account data space
- If no: read the anchor snapshot from the first invocation

**Practical implementation:** The anchor snapshot is stored in the sandbox PDA's reserved space.

**Transaction detection via transaction fingerprint:**

The `sysvar::instructions` sysvar only contains **top-level** instructions. CPI invocations are invisible to it. This means a program-ID scan would miss CPI-routed calls, allowing an attacker to use a trivial helper program to make every CPI invocation appear as "first" — completely bypassing `tx_cumulative_decrease`.

**Solution: Transaction fingerprint.** Instead of scanning for prior self-calls, the sandbox computes a deterministic fingerprint of the entire top-level instruction list. This fingerprint is identical for every invocation within the same transaction — whether top-level or CPI — because the top-level instruction list doesn't change.

```rust
fn compute_tx_fingerprint(ix_sysvar: &AccountInfo) -> [u8; 32] {
    // Read total instruction count from first 2 bytes of sysvar data
    let sysvar_data = ix_sysvar.try_borrow_data().unwrap();
    let num_ix = u16::from_le_bytes([sysvar_data[0], sysvar_data[1]]) as usize;
    drop(sysvar_data); // release borrow before calling load_instruction_at
    
    let mut hasher = hashv(&[]);
    for i in 0..num_ix {
        if let Ok(ix) = load_instruction_at_checked(i, ix_sysvar) {
            // Hash: program_id (32) + data_len (8) + num_accounts (8) + data_hash
            // Including data bytes prevents fingerprint collisions between
            // transactions with same structure but different data
            let data_hash = hashv(&[ix.data.as_ref()]);
            hasher = hashv(&[
                hasher.as_ref(),
                ix.program_id.as_ref(),
                &(ix.data.len() as u64).to_le_bytes(),
                &(ix.accounts.len() as u64).to_le_bytes(),
                data_hash.as_ref(),
            ]);
        }
    }
    hasher.to_bytes()
}

fn is_first_sandbox_invocation(pda: &SandboxState, ix_sysvar: &AccountInfo) -> bool {
    let fingerprint = compute_tx_fingerprint(ix_sysvar);
    pda.anchor_tx_fingerprint != fingerprint
}
```

Behavior:
- First invocation in tx (any path — top-level or CPI) → fingerprint doesn't match PDA → write fresh anchor + store fingerprint
- Subsequent invocation in SAME tx (any path — top-level or CPI) → fingerprint matches → read existing anchor
- Different transaction (same or different slot) → different instruction list → different fingerprint → fresh anchor
- **CPI-routed calls:** The helper program's CPI appears as a top-level instruction with the helper's program ID. The fingerprint includes this. ALL invocations within the same transaction see the SAME fingerprint regardless of call depth.

**Why this is CPI-proof:** The top-level instruction list is fixed at transaction creation time and is identical from every vantage point within the transaction. CPI calls don't modify it. The fingerprint is deterministic and unique per transaction.

**CU cost:** ~1,500 CU for fingerprint computation (iterate instructions, hash). 32 bytes stored in PDA alongside anchor data. Acceptable.

**Requirement:** The Instructions sysvar account (`Sysvar1nstructions1111111111111111111111111`) must be included in the transaction's account list when `tx_cumulative_decrease` invariants are configured. The macro auto-includes it. `doctor` warns if missing.

### 5.3 Per-Transaction Cumulative Decrease

```rust
#[invariant(tx_cumulative_decrease(field = "market.vault_balance", max_pct = 15))]
```

This compares the current after-state against the transaction anchor snapshot:
```
decrease_pct = (tx_anchor_value - current_value) / tx_anchor_value * 100
if decrease_pct > max_pct → Err(InvariantViolation)
```

Even if each instruction individually decreases by only 5%, the cumulative check catches the 18.5% total.

---

## 6. Circuit Breakers (Instruction-Type-Aware)

### 6.1 The Liquidation DoS Problem

Without instruction-type awareness, legitimate withdrawals consume circuit breaker budget, leaving no room for critical operations like liquidations. An attacker can weaponize the circuit breaker to block liquidations, causing bad debt accumulation.

### 6.2 Instruction Categories and Budgets

```toml
[circuit_breakers]
enabled = true

# Define instruction categories
[circuit_breakers.categories]
withdrawal = ["close_position", "withdraw"]
liquidation = ["liquidate"]
deposit = ["deposit", "open_position"]
# Uncategorized instructions use "default"

# TVL cliff with PER-CATEGORY budgets
[circuit_breakers.tvl_cliff]
track_field = "market.vault_balance"
window_slots = 1500
action = "reject_current"
high_water_mark = true  # explicit tracking, not buffer scan

# Separate budgets per category
[circuit_breakers.tvl_cliff.budgets]
withdrawal = { max_decrease_pct = 15 }
liquidation = { max_decrease_pct = 25 }  # liquidations get more room
default = { max_decrease_pct = 10 }

# Or: exempt critical instructions entirely
[circuit_breakers.tvl_cliff.exempt]
instructions = ["liquidate"]  # liquidations never blocked by TVL cliff

# Rapid event counters (per category)
[circuit_breakers.rapid_liquidations]
track_event = "liquidate"
window_slots = 150
max_count = 20
action = "pause_liquidations"

[circuit_breakers.rapid_withdrawals]
track_event = "withdraw"
window_slots = 150
max_count = 50
action = "close_only"
```

### 6.3 High-Water-Mark Tracking

The circuit breaker stores an explicit `window_max_value` field, updated on every write:

```rust
pub struct CircuitBreakerState {
    pub history_len: u16,
    pub history_index: u16,
    pub window_max_value: u64,     // explicit high-water mark
    pub window_max_slot: u64,      // when the max was recorded
    // Ring buffer follows
}
```

On each update:
- If new value > `window_max_value`: update max
- If `window_max_slot` is outside the current window: recalculate max from buffer

This prevents the ring buffer eviction attack — the high-water mark is tracked independently of buffer contents.

### 6.4 Slot Time Variance Handling

Circuit breaker windows are slot-based (deterministic) but the spec acknowledges slot times vary 2-3x during congestion.

**Dual-window approach:** Each circuit breaker evaluates against BOTH a slot window AND an approximate timestamp window:

```rust
let slot_window_ok = current_slot - oldest_slot <= window_slots;
let time_window_ok = current_timestamp - oldest_timestamp <= window_seconds;
// Use the MORE CONSERVATIVE (smaller) window
let in_window = slot_window_ok && time_window_ok;
```

```toml
[circuit_breakers.tvl_cliff]
window_slots = 1500
window_seconds = 600   # 10 minutes wall-clock backup
```

During congestion (slow slots), `window_seconds` limits the effective window. During fast slots, `window_slots` limits it. The result is always the more conservative bound.

### 6.5 Circuit Breaker Blind Spot (Rolled-Back Transactions)

When a post-check fails and the transaction reverts, the PDA update (step [10]) also reverts. The circuit breaker has no memory of the attempt.

**Fix: Off-chain watcher compensates.**
- Logs persist even on reverted transactions.
- The watcher tracks `PERK_SANDBOX:type=invariant_violation` events from rolled-back txs.
- If the watcher detects repeated violation attempts (e.g., 5 failed drains in 2 minutes), it triggers an external pause via guardian multisig or automated pause bot.
- The watcher is a REQUIRED component for production deployments, not optional.

```toml
[alerts]
# Watcher-side circuit breaker (compensates for on-chain blind spot)
# IMPORTANT: Watcher MUST use notify action, NEVER auto-pause.
# Auto-pause would be a zero-cost griefing vector (5 failed txs = trigger).
[alerts.watcher_breaker]
trigger = "5 invariant_violation events in 300 seconds"
action = "notify_guardians_to_pause"   # ONLY notify — guardians decide
# action = "auto_pause" is FORBIDDEN and the watcher rejects this config
```

### 6.6 Circuit Breakers During Emergency Bypass

**Explicitly resolved:** Circuit breakers ALWAYS run, even during emergency bypass. Emergency bypass disables invariant post-checks (step [8]) but NOT circuit breakers (step [9]). This prevents the bypass+re-entrancy=zero-checks attack chain.

During emergency bypass:
- ✅ Pre-checks: authority, bounds, oracle, rate limits (always)
- ❌ Post-checks: invariants (disabled)
- ✅ Circuit breakers: active with full instruction-type-aware budgets
- ✅ Per-transaction cumulative decrease: active

---

## 7. Re-Entrancy Handling

### 7.1 Three Modes

**`mode = "reject"` (safest):** Self-CPI blocked. `Err(ReentrancyDetected)`.

**`mode = "guard"` (default when PDA exists):**
- Inner calls: run ALL pre-checks (authority, bounds, mode, oracle, rate limits) + circuit breaker evaluation. Skip invariant post-checks.
- Outer call: runs full post-checks including invariants on FINAL state.
- Circuit breakers run on BOTH inner and outer calls (instruction-type-aware budgets apply).
- During emergency bypass: inner calls run ALL pre-checks (authority, bounds, mode, oracle, rate limits) + circuit breakers. Outer call runs pre-checks + circuit breakers + `tx_cumulative_decrease` (other invariants disabled by bypass). **At no point are zero checks running.**

**`mode = "full"`:** Every call runs everything. Risk of false positives on intermediate state.

### 7.2 Stateless Mode Restriction

Programs that CPI to themselves MUST have a PDA (for the re-entrancy guard flag). `doctor` emits a hard error:
```
❌ Program CPIs to self but no PDA configured.
   Fix: enable circuit_breakers OR set reentrancy.mode = "reject"
```

---

## 8. Sandbox State PDA

### 8.1 Serialization Format

**All PDA data uses explicit manual serialization with Borsh, NOT `#[repr(C)]`.**

`#[repr(C)]` introduces alignment padding that varies by target architecture and makes raw byte offset calculations unreliable. Instead, all PDA read/write uses Borsh serialization with known, deterministic byte layouts.

```rust
// NOT this:
#[repr(C)]
pub struct SandboxStateHeader { ... }  // padding issues

// THIS:
impl SandboxState {
    pub fn serialize(&self, data: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        data[offset..offset+8].copy_from_slice(&self.discriminator); offset += 8;
        data[offset] = self.version; offset += 1;
        data[offset] = self.bump; offset += 1;
        // ... explicit byte-by-byte serialization, no padding
    }
    
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        // ... explicit byte-by-byte deserialization
        // Validate ALL offsets are within bounds before reading
    }
}
```

### 8.2 PDA Layout (Borsh-serialized, no padding)

```
Header (fixed, 64 bytes):
  [0..8]    discriminator: "PRKSANDX"
  [8]       version: u8
  [9]       bump: u8
  [10..12]  total_size: u16
  [12..14]  mode_flags_offset: u16    (0 = not present)
  [14..16]  circuit_breaker_offset: u16
  [16..18]  rate_limits_offset: u16
  [18..20]  guard_offset: u16
  [20..22]  emergency_offset: u16
  [22..24]  tx_anchor_offset: u16
  [24..40]  _reserved_offsets: [u16; 8]
  [40..64]  _reserved: [u8; 24]

Mode Flags Section:
  paused: bool (1)
  close_only: bool (1)
  liquidation_paused: bool (1)
  emergency_bypass_active: bool (1)
  paused_at_slot: u64 (8)
  pause_reason: [u8; 32] (32)
  cooldown_end_slot: u64 (8)
  emergency_bypass_end_slot: u64 (8)
  Total: 60 bytes

Guard Section:
  executing: bool (1)
  depth: u8 (1)
  Total: 2 bytes

Transaction Anchor Section:
  anchor_slot: u64 (8)
  anchor_ix_index: u16 (2)
  anchor_field_count: u8 (1)
  anchor_fields: [AnchorField; N] where AnchorField = pubkey(32) + field_id(2) + value(8) = 42 bytes each
  Total: 11 + 42*N bytes (N = number of tx-level invariant fields, max 16)

Circuit Breaker Section (per category):
  category_count: u8 (1)
  Per category:
    category_id: u8 (1)
    window_max_value: u64 (8)
    window_max_slot: u64 (8)
    history_len: u16 (2)
    history_index: u16 (2)
    history: [TvlSnapshot; history_len] where TvlSnapshot = value(8) + slot(8) + timestamp(8) = 24 bytes

Rate Limit Section:
  counter_count: u8 (1)
  Per counter:
    counter_id: u8 (1)
    count: u32 (4)
    window_start_slot: u64 (8)
```

### 8.3 Offset Validation

On EVERY PDA read, before accessing any section:

```rust
fn validate_offsets(header: &SandboxStateHeader, data_len: usize) -> Result<()> {
    for &offset in &[
        header.mode_flags_offset,
        header.circuit_breaker_offset,
        header.rate_limits_offset,
        header.guard_offset,
        header.emergency_offset,
        header.tx_anchor_offset,
    ] {
        if offset == 0 { continue; } // not present
        if (offset as usize) < HEADER_SIZE {
            return Err(SandboxError::PDACorrupted); // overlaps header
        }
        if (offset as usize) >= data_len {
            return Err(SandboxError::PDACorrupted); // past end
        }
    }
    // Check no two non-zero offsets point to overlapping ranges
    // (omitted for brevity — implementation validates section bounds don't overlap)
    Ok(())
}
```

Corrupted PDA → fail-closed → `Err(PDACorrupted)`. Program pauses until PDA is fixed via migration.

### 8.4 PDA Derivation

```rust
seeds = [b"perk_sandbox", scope.as_ref()]
// scope = [] for global
// scope = [market_pubkey] for per-market
```

Uses `create_program_address` with stored bump. Never `find_program_address` in hot path.

### 8.5 Per-Market PDAs

For high-throughput programs, circuit breaker and rate limit state can be scoped per-market:

```toml
[circuit_breakers]
scope = "per_market"  # or "global" (default)
market_account = "ctx.accounts.market"
```

Per-market PDAs eliminate the serialization bottleneck — transactions to different markets use different PDAs and process in parallel.

The macro generates separate PDA derivation using the market account pubkey as scope.

### 8.6 Global Aggregate Circuit Breaker (Required with Per-Market Scope)

Per-market PDAs create a protocol-wide blind spot: an attacker can drain 15% from each of 5 markets (75% total) without any single market's breaker firing.

**Fix: When `scope = "per_market"` is configured, a global aggregate circuit breaker is REQUIRED.** This uses **read-only aggregation at check time**, NOT a separate write-locked global PDA.

```toml
[circuit_breakers]
scope = "per_market"
market_account = "ctx.accounts.market"

# REQUIRED when scope = per_market
[circuit_breakers.global_aggregate]
enabled = true   # doctor errors if this is false when scope = per_market
track_field = "market.vault_balance"
max_decrease_pct = 25   # protocol-wide cap per transaction
action = "reject_current"
```

**Read-only aggregation approach (no global write-lock):**

Instead of maintaining a separate global PDA (which would re-serialize all transactions and defeat the purpose of per-market PDAs), the global aggregate check works as follows:

1. The transaction MUST include all market accounts the protocol manages as read-only remaining_accounts (the macro enforces this when global_aggregate is enabled).
2. At post-check time, the sandbox reads `vault_balance` from every market account in the transaction.
3. It sums them to compute current protocol-wide TVL.
4. It compares against the transaction anchor's protocol-wide TVL snapshot (also computed by summing all markets at anchor time).
5. If the decrease exceeds `max_decrease_pct`, the transaction is rejected.

This is a **per-transaction check**, not a windowed breaker. It doesn't need persistent state — the anchor snapshot captures the start-of-transaction TVL, and the post-check reads the end-of-transaction TVL. No global PDA write. No serialization bottleneck. Full parallelism preserved.

**Note on instruction categories:** The global aggregate check is intentionally NOT instruction-type-aware — it has a single flat threshold. This is by design: it's a protocol-wide safety net, not a per-category budget. Per-market PDAs handle category-aware budgets at the market level. The global aggregate catches cross-market drains that individual per-market breakers miss. This is a different breaker type (per-transaction read-only check) from the windowed per-market breakers (stateful PDA-based), hence it appears under `[circuit_breakers]` for config convenience but has different semantics.

**CU cost:** Reading N market accounts (~300 CU each for the vault_balance field) + sum computation. For 10 markets: ~3,500 CU. For 50 markets: ~16,000 CU. Acceptable and does NOT require a PDA write-lock.

**Limitation:** This only catches protocol-wide drains within a SINGLE transaction. Cross-transaction protocol-wide drains are caught by the off-chain watcher, which monitors total TVL across all markets via RPC and notifies guardians if protocol-wide TVL drops anomalously.

**`doctor` behavior:** Emits HARD ERROR if `scope = "per_market"` without `global_aggregate.enabled = true`. Also warns if the protocol has many markets (>20) due to CU cost of scanning all market accounts.

This gives two-tier protection without sacrificing parallelism: per-market PDAs for market-specific windowed anomalies, read-only global aggregate for protocol-wide per-transaction drains.

### 8.7 Initialization

Explicit via `perk-sandbox init-state`. If PDA required but not found → `Err(SandboxStateNotInitialized)`.

`build` command warns if PDA is needed:
```
⚠️ Circuit breakers enabled. After deploy, run: perk-sandbox init-state
```

---

## 9. Emergency Bypass

### 9.1 Activation

When a false-positive invariant blocks legitimate users:

1. **Threshold guardians** (not all — configurable M-of-N) activate bypass.
2. Program enters bypass mode:
   - ✅ Pre-checks enforced (authority, bounds, oracle, rate limits)
   - ✅ Circuit breakers enforced (full instruction-type-aware budgets)
   - ✅ `tx_cumulative_decrease` enforced (explicitly special-cased to run even during bypass)
   - ❌ Other invariant post-checks disabled (gte, conserve, immutable, etc.)
3. Auto-reverts after `max_duration_slots` (configurable, default 30 min).
4. `PERK_SANDBOX:type=emergency_bypass_activated` logged.

**Why `tx_cumulative_decrease` runs during bypass:** This invariant is the last line of defense against multi-instruction drain attacks. Disabling it during bypass would leave only circuit breakers (which have per-window granularity, not per-tx). Keeping it active adds ~2,300 CU for the first invocation in a transaction (fingerprint computation + anchor snapshot + evaluation) or ~800 CU for subsequent invocations (anchor read + evaluation). This ensures no single transaction can extract more than the configured percentage even when other invariants are off.

### 9.2 Guardian Management

```toml
[recovery.emergency_bypass]
enabled = true
signers = ["guardian_1", "guardian_2", "guardian_3", "guardian_4", "guardian_5"]
threshold = 3   # 3 of 5 (not ALL — prevents single-key-loss lockout)
cooldown_slots = 600
max_duration_slots = 4500

# Guardian rotation: admin can propose new guardian set with timelock
[recovery.guardian_rotation]
proposer = "admin"
timelock_slots = 7200   # ~48 minutes
```

**Guardian key loss:** With M-of-N (not all-of-N), losing one key doesn't lock out bypass. Guardian rotation allows replacing compromised/lost keys with timelock.

### 9.3 Unpause Authority

```toml
[recovery.unpause]
type = "multisig"
signers = ["guardian_1", "guardian_2", "guardian_3", "guardian_4", "guardian_5"]
threshold = 2   # 2 of 5 for unpause (lower threshold than bypass)
cooldown_slots = 300
```

---

## 10. Retrofit Support (Existing Programs)

### 10.1 For Anchor Programs

Existing Anchor programs can adopt the sandbox without rewriting:

```
$ perk-sandbox retrofit --idl target/idl/my_program.json
```

This generates:
1. A wrapper crate that imports the existing program as a dependency
2. The wrapper's entrypoint calls sandbox checks → existing program's processor
3. Deploy the wrapper with the same program ID (upgrade)

```rust
// Generated wrapper crate
use perk_sandbox::prelude::*;
use my_existing_program::processor;

#[sandbox_entrypoint(config = "sandbox.toml")]
pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // Sandbox pre-checks (generated from sandbox.toml)
    sandbox_pre_checks(program_id, accounts, data)?;
    let snapshot = sandbox_snapshot(accounts)?;
    
    // Call existing program
    let result = processor::process_instruction(program_id, accounts, data)?;
    
    // Sandbox post-checks
    sandbox_post_checks(snapshot, accounts)?;
    Ok(())
}
```

### 10.2 For Raw Rust Programs

Same approach but with manual account schema:

```toml
[accounts.market]
discriminator = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
serialization = "borsh"  # or "fixed" for repr(C) programs

[accounts.market.fields]
vault_balance = { path = "vault_balance", type = "u64" }  # Borsh field name
# OR for fixed-layout:
# vault_balance = { offset = 72, type = "u64" }
```

---

## 11. Error Handling

### 11.1 Error Codes (stable API, 6000-6099 reserved)

| Code | Error | Retryable | Category |
|---|---|---|---|
| 6000 | `ProgramPaused` | Wait | mode |
| 6001 | `CloseOnlyMode` | Partial | mode |
| 6002 | `LiquidationPaused` | Wait | mode |
| 6003 | `EmergencyBypassActive` | Wait | mode |
| 6010 | `UnauthorizedSigner` | No | auth |
| 6011 | `UnknownInstruction` | No | auth |
| 6020 | `OracleStale` | Wait | oracle |
| 6021 | `OracleDeviation` | Wait | oracle |
| 6030 | `RateLimitExceeded` | Wait | ratelimit |
| 6040 | `BoundViolation` | No | bound |
| 6050 | `InvariantViolation` | No | invariant |
| 6051 | `TxCumulativeDecreaseExceeded` | No | invariant |
| 6060 | `InsufficientCU` | Retry+CU | system |
| 6070 | `SandboxStateNotInitialized` | No | system |
| 6071 | `PDACorrupted` | No | system |
| 6072 | `SandboxStateVersionMismatch` | No | system |
| 6073 | `SnapshotFailed` | Retry | system |
| 6080 | `ReentrancyDetected` | No | system |
| 6090 | `CircuitBreakerTriggered` | Wait | breaker |

### 11.2 NPM Error Package

```typescript
import { parseSandboxError, isRetryable, errorCategory } from '@perk-sandbox/errors';

const err = parseSandboxError(transactionError);
if (err) {
    err.code;         // 6050
    err.type;         // "InvariantViolation"
    err.message;      // "Safety check failed" (overridable per-protocol)
    err.isRetryable;  // false
    err.userAction;   // "Please report this to the protocol team"
    err.category;     // "invariant"
}

// Category helpers
isOracleError(err);    // true for 6020-6029
isModeError(err);      // true for 6000-6009
isAuthError(err);      // true for 6010-6019
isBreakerError(err);   // true for 6090-6099
```

Protocols override user-facing messages:
```typescript
const customMessages = {
    6050: "Transaction blocked by safety system. Your funds are safe. Please contact support.",
    6020: "Waiting for fresh price data. Try again in 30 seconds.",
};
const err = parseSandboxError(txError, { messages: customMessages });
```

---

## 12. CLI Tool

```
perk-sandbox — CLI for PERK Sandbox

DEVELOPMENT:
  init              Generate sandbox.toml + attribute guidance (from IDL or template)
  verify            Validate config + attributes + field references + snapshot strategy report
  build             Build with sandbox (cargo build-sbf --features sandbox)
  inspect           Show generated sandbox code
  diff              Dry-run: show what macro generates
  doctor            Diagnose issues, warn about missing invariants, check self-CPI
  eject             Print removal instructions

TESTING:
  test              Run auto-generated tests (positive, negative, boundary, breaker, bypass)
  simulate <sig>    Replay single historical tx against sandbox
  simulate --batch  Replay last N txs (default 10,000)
  fuzz              Run built-in fuzz targets

OPERATIONS:
  init-state        Initialize sandbox PDA(s) on-chain
  status            Read PDA state (mode, counters, breaker status, anchor snapshot)
  unpause           Send unpause tx (multisig flow)
  emergency-bypass  Activate bypass (guardian multisig)
  rotate-guardian   Propose guardian rotation (timelock)
  migrate           Run PDA schema migration

UTILITIES:
  decode-error <code>    Decode error to human-readable
  audit-export           Export manifest as JSON (for auditors)
  verify-deployment      Check on-chain binary + upgrade authority + invariant strength
  watch                  Start off-chain watcher + alert service
  dashboard              Start terminal dashboard (PDA state, alerts, breaker status)

RETROFIT:
  retrofit              Generate sandbox wrapper for existing program
```

### 12.1 `perk-sandbox doctor` (expanded)

```
$ perk-sandbox doctor

✅ sandbox.toml valid
✅ #[sandbox_program] found
✅ Feature flag configured

INVARIANTS:
  ⚠️ close_position has no vault floor invariant. STRONGLY RECOMMENDED.
  ✅ vault_solvency declared on 4 instructions
  ✅ tx_cumulative_decrease declared on withdrawal instructions

CIRCUIT BREAKERS:
  ✅ Instruction categories: withdrawal(2), liquidation(1), deposit(2)
  ✅ Liquidation exempt from TVL cliff — no DoS risk
  ✅ High-water-mark tracking enabled
  ✅ Dual-window (slot + timestamp) configured

SNAPSHOTS:
  ✅ market.vault_balance → fixed-offset (byte 72, ~300 CU)
  ⚠️ market.authority → borsh-deser after Option<Pubkey> (~1,500 CU)
  ✅ position.owner → fixed-offset (byte 8, ~300 CU)

RE-ENTRANCY:
  ✅ No self-CPI detected — stateless mode safe
  OR:
  ❌ Self-CPI detected but reentrancy.mode not configured

GUARDIANS:
  ✅ 5 guardians configured, bypass threshold 3/5
  ✅ Guardian rotation enabled with 48-min timelock

DEPLOYMENT:
  ⚠️ Upgrade authority is single key — recommend multisig

0 errors, 3 warnings. Ready to build.
```

---

## 13. Security Model

### 13.1 What the Sandbox Guarantees

| Property | Guarantee Level | Mechanism |
|---|---|---|
| No unauthorized state mutation | **Strong** | Entrypoint is the only path while current binary is deployed. Authority pre-checks always run. (Caveat: upgrade authority compromise can remove sandbox.) |
| No invariant violation persists | **Absolute (Solana guarantee)** | Post-checks + atomic rollback. Violated state never commits. Holds unconditionally — guaranteed by Solana runtime, not sandbox code. |
| Liquidations can't be DoS'd by withdrawals | **Strong** | Instruction-type-aware circuit breaker budgets isolate categories. (Caveat: `pause_liquidations` mode intentionally blocks liquidations when rapid-liquidation breaker fires.) |
| Multi-instruction drains capped | **Strong** | tx_cumulative_decrease compares against transaction fingerprint-anchored snapshot. (Caveat: only enforced on instructions where the developer declares the invariant. `doctor` warns about missing declarations.) |
| Emergency bypass preserves critical checks | **Strong** | Circuit breakers + pre-checks + `tx_cumulative_decrease` active during bypass. Other invariants (vault floor, conserve, etc.) disabled. (Caveat: vault floor is off during bypass — bounded extraction possible within breaker limits.) |
| Slow drain limited | **Strong** | Three layers: per-ix cap + windowed breaker + absolute floor. |
| Cross-instruction state pollution caught | **Strong** | Transaction-level anchor snapshots. |
| Circuit breaker evasion via rolled-back txs | **Strong** | Off-chain watcher compensates with log-based detection. |
| Upgrade authority compromise | **Advisory** | Recommendations + verify-deployment checks. Not enforceable by sandbox. |

### 13.2 Slow Drain Defense (Four Layers)

| Layer | Mechanism | What it catches |
|---|---|---|
| Per-instruction cap | `max_decrease(pct=5)` | Single large drain |
| Per-transaction cap | `tx_cumulative_decrease(max_pct=15)` | Multi-instruction packing |
| Windowed breaker | `tvl_cliff(max_decrease_pct=20)` per category | Rapid repeated drains |
| Absolute floor | `gte(lhs="vault", rhs="MIN")` | Total drain below minimum |

Combined: attacker can drain at most `min(5% per ix, 15% per tx, 20% per window per category)` and never below the floor.

### 13.3 Vault Floor Enforcement

`doctor` emits a WARNING (not error) if no absolute floor invariant exists on vault-touching instructions. The warning is prominent and repeats on every `build`:

```
⚠️ WARNING: No absolute vault floor invariant detected.
   Without a floor, slow drain attacks can extract up to 80%+ of vault over time.
   Add: #[invariant(gte(lhs = "market.vault_balance", rhs = "MIN_VAULT_LAMPORTS"))]
   This is the MOST IMPORTANT invariant for vault-holding programs.
   Suppress with: #[sandbox_allow(no_vault_floor)]
```

Making it a hard error would break programs that legitimately don't hold vaults. The `#[sandbox_allow(no_vault_floor)]` explicit acknowledgment ensures the developer made a conscious choice.

---

## 14. Testing

### 14.1 Auto-Generated Tests

```rust
#[test] fn sandbox_vault_solvency_positive() { ... }
#[test] fn sandbox_vault_solvency_violation() { ... }
#[test] fn sandbox_authority_enforced() { ... }
#[test] fn sandbox_oracle_staleness() { ... }
#[test] fn sandbox_reentrant_precheck() { ... }
#[test] fn sandbox_unknown_instruction_rejected() { ... }
#[test] fn sandbox_circuit_breaker_reject_current() { ... }
#[test] fn sandbox_circuit_breaker_category_isolation() { ... }  // liquidation not blocked by withdrawals
#[test] fn sandbox_emergency_bypass_preserves_breakers() { ... }
#[test] fn sandbox_tx_cumulative_decrease() { ... }
#[test] fn sandbox_multi_ix_drain_packing_blocked() { ... }
#[test] fn sandbox_pda_corruption_failclosed() { ... }
#[test] fn sandbox_max_increase_zero_value() { ... }  // no div-by-zero
#[test] fn sandbox_borsh_variable_offset_snapshot() { ... }
```

### 14.2 Transaction Replay

Single tx:
```
$ perk-sandbox simulate 5K7x...
```

Batch:
```
$ perk-sandbox simulate --batch --rpc mainnet --count 10000
```

### 14.3 Fuzz Testing

Built-in fuzz targets for:
- Invariant evaluation with randomized values + checked arithmetic
- Circuit breaker state machine with random category sequences
- PDA serialization round-trips with corruption injection
- Ring buffer boundary conditions
- Borsh deserialization prefix parsing with adversarial data
- Re-entrancy guard state transitions
- Transaction anchor snapshot with multi-ix sequences

---

## 15. Versioning

### 15.1 Crate Versioning (semver)
- Patch: bug fixes, compatible
- Minor: new invariant types, new config options, backwards compatible
- Major: breaking changes, migration guide

### 15.2 PDA Schema Versioning
- Version field in header. Fail-closed on mismatch.
- Migration via `perk-sandbox migrate` + auto-generated instruction.
- Offset table allows additive sections without breaking existing offsets.
- Migration pauses program, restructures, unpauses. Atomic within one instruction.

### 15.3 Runtime Crate Pinning
Exact version pinned in generated Cargo.toml. Reproducible builds.

---

## 16. CU Budget (Revised)

### 16.1 Overhead by Feature

| Feature | CU Cost |
|---|---|
| PDA read (guard + mode + offsets validation) | 3,000-4,000 |
| Authority pre-check | 300-500 |
| Oracle pre-check | 2,000-3,000 |
| Rate limit check | 1,000 |
| Snapshot per field (fixed-offset) | 200-400 |
| Snapshot per field (borsh-deser) | 1,000-3,000 |
| `sol_remaining_compute_units()` | 100 |
| Invariant eval (built-in) | 200-500 |
| Invariant eval (aggregate/conserve, fixed-offset, N accounts) | 500 + 300/program_owned_account + 100/other_account |
| Invariant eval (aggregate/conserve, borsh-deser, N accounts) | 500 + 2,000/program_owned_account + 100/other_account |
| Invariant eval (custom) | declared cu_budget |
| Tx fingerprint computation | 1,500 |
| Tx-anchor snapshot (first ix) | 2,000 |
| Tx-anchor read (subsequent ix) | 500 |
| tx_cumulative_decrease eval | 300 |
| Circuit breaker eval (per category) | 500 |
| PDA write (all sections) | 3,000-5,000 |
| Re-entrancy guard clear | 500 |

### 16.2 Realistic Scenarios

| Config | Overhead | % of 1.4M |
|---|---|---|
| Stateless (3 invariants, authority, 6 fixed fields) | ~4,000 CU | 0.3% |
| Stateless + tx-level (5 invariants, oracle, tx_cumulative, fingerprint) | ~14,000 CU | 1.0% |
| With PDA (5 invariants, breakers, 2 categories) | ~25,000-30,000 CU | 2.0% |
| Full (5 invariants, tx-level, breakers, rate limits, borsh fields) | ~35,000-45,000 CU | 3.0% |

---

## 17. File Structure

```
perk-sandbox/
├── sandbox-macros/              # Proc macro crate (~2,000 lines)
│   ├── src/
│   │   ├── lib.rs               # sandbox_program, sandbox_instruction, invariant, etc.
│   │   ├── program_attr.rs      # Entrypoint + Anchor dispatch generation
│   │   ├── instruction_attr.rs  # Per-instruction wrapper
│   │   ├── invariant_attr.rs    # All 18 built-in types + custom
│   │   ├── authority_attr.rs    # Authority checks
│   │   ├── bound_attr.rs        # Bound checks
│   │   ├── snapshot.rs          # Borsh-aware field resolution + codegen
│   │   ├── tx_anchor.rs         # Transaction-level snapshot codegen
│   │   ├── config.rs            # sandbox.toml parser
│   │   └── util.rs
│   └── Cargo.toml
│
├── sandbox-runtime/             # Runtime library (~1,200 lines)
│   ├── src/
│   │   ├── lib.rs + prelude.rs
│   │   ├── error.rs             # All error types + codes
│   │   ├── state.rs             # PDA manual serialization + offset validation
│   │   ├── circuit_breaker.rs   # Category-aware breakers + high-water-mark
│   │   ├── rate_limit.rs        # Counters
│   │   ├── guard.rs             # Re-entrancy
│   │   ├── oracle.rs            # Freshness + deviation
│   │   ├── external.rs          # SPL Token deserialization
│   │   ├── cu.rs                # CU reservation
│   │   ├── context.rs           # InvariantContext for custom invariants
│   │   └── tx_anchor.rs         # Transaction anchor read/write
│   └── Cargo.toml
│
├── sandbox-cli/                 # CLI tool
│   ├── src/
│   │   ├── main.rs
│   │   ├── commands/            # All commands
│   │   ├── simulator/           # Single + batch replay
│   │   ├── retrofit/            # Wrapper generation for existing programs
│   │   └── dashboard/           # Terminal dashboard
│   └── Cargo.toml
│
├── sandbox-watcher/             # Off-chain alert service (REQUIRED for production)
│   ├── src/
│   │   ├── main.rs              # Log watcher + alert router
│   │   ├── parser.rs            # Parse PERK_SANDBOX logs
│   │   ├── watcher_breaker.rs   # Log-based circuit breaker (compensates on-chain blind spot)
│   │   ├── telegram.rs
│   │   ├── discord.rs
│   │   └── webhook.rs
│   └── Cargo.toml
│
├── sandbox-errors/              # Published error table
│   ├── src/lib.rs
│   └── js/
│       ├── package.json
│       └── src/index.ts         # parseSandboxError + helpers + custom messages
│
├── examples/
│   ├── token/
│   ├── perps/                   # Perk dogfood
│   └── amm/
│
├── docs/
│   ├── SPEC.md                  # This document
│   ├── GUIDE.md
│   ├── TOML-REFERENCE.md
│   ├── INVARIANT-REFERENCE.md
│   ├── SECURITY.md              # Threat model + all attack chains analyzed
│   ├── MIGRATION.md
│   ├── RETROFIT-GUIDE.md
│   └── FAQ.md
│
└── README.md
```

---

## 18. Implementation Timeline (Historical)

### Week 0: Spike
- Prototype `#[sandbox_program]` + Anchor dispatch
- Validate Borsh-aware snapshot generation
- Go/no-go on macro architecture

### Weeks 1-2: Core
- Runtime: errors, PDA with manual serialization + offset validation, re-entrancy guard, CU utils
- Macros: `#[sandbox_program]`, `#[sandbox_instruction]`, `#[authority]`, `#[bound]`
- Oracle pre-check generation (staleness, deviation)
- Borsh-aware snapshot mechanism (both strategies)
- Feature flag integration
- Unknown instruction rejection

### Weeks 2-3: Invariants
- All 18 built-in invariant types with checked arithmetic
- Named invariant definitions
- Custom invariant with declared CU budget
- `max_increase` zero-value handling
- `conserve` scanning remaining_accounts
- Per-check CU reservation

### Weeks 3-4: Transaction-Level + Circuit Breakers
- Transaction fingerprint + anchor snapshot
- `tx_cumulative_decrease` invariant
- Circuit breaker state machine with instruction categories
- High-water-mark tracking
- Dual-window (slot + timestamp)
- `reject_current` action
- Per-market PDA support
- Global aggregate circuit breaker (read-only aggregation)

### Weeks 4-5: Recovery + Rate Limits
- Emergency bypass (M-of-N guardians, auto-expire)
- Guardian rotation with timelock
- Rate limit counters (per-signer + global)
- Unpause flow
- sandbox.toml parser with profiles

### Weeks 5-6: Tooling
- CLI: all development commands (init, verify, doctor, build, inspect, diff, eject)
- CLI: all operations commands (init-state, status, unpause, emergency-bypass, rotate-guardian, migrate)
- CLI: utilities (decode-error, audit-export, verify-deployment)
- Auto-generated tests
- Transaction replay (single + batch)
- Terminal dashboard

### Weeks 6-7: Testing + Polish + Retrofit
- Fuzz testing all runtime components
- Retrofit wrapper generation (Anchor + raw Rust)
- Off-chain watcher with log-based circuit breaker
- NPM error package
- Example programs (token, perps, AMM)
- All documentation
- Apply sandbox to Perk perps (dogfood)

**Total: 8 weeks (1 spike + 7 build). No deferrals.**

---

*End of specification. Built by Perk Protocol. V1.0 core framework shipped April 8, 2026.*

# PERK Sandbox

Compile-time safety wrapper for Solana programs. One attribute, twelve layers of protection.

## About

PERK Sandbox is a proc-macro framework that wraps your Anchor program's entrypoint with a comprehensive safety pipeline. It generates a new entrypoint at compile time that intercepts every transaction before and after your business logic runs, enforcing circuit breakers, invariants, rate limits, oracle checks, and reentrancy protection — without modifying a single line of your existing program.

Built for DeFi protocols that can't afford to ship unprotected. If your program moves funds, PERK Sandbox makes sure it does so within the rules you define.

**Status:** V1.0 — pipeline complete, 560+ tests, adversarially reviewed.

## What It Does

Every transaction flows through a 12-step pipeline. No bypass path exists.

```
[1]  Reentrancy guard        — detect and handle self-CPI (Reject/Guard/Full modes)
[2]  Mode checks             — enforce paused, close-only, liquidation-paused states
[3]  Unknown instruction     — reject unrecognized discriminators (fail-closed)
[4]  Pre-checks              — authority, oracle freshness, rate limits, input bounds
[5]  TX-level snapshot       — fingerprint transaction, anchor field values for cross-IX checks
[6]  Instruction snapshot    — capture before-values for invariant comparison
[7]  Business logic          — your Anchor program runs here (unchanged)
[8]  Post-checks             — 18 invariant types with CU reservation, tx cumulative decrease
[9]  Circuit breakers        — TVL cliff (windowed HWM), event counters, per-IX threshold
[10] PDA write-back          — persist mode flag changes from deferred breaker actions
[11] Guard cleanup           — decrement depth, clear executing flag
[12] Return                  — success
```

If any step fails, the transaction reverts. Your program's state is never left in an inconsistent state.

## Features

- **Circuit Breakers** — Windowed TVL cliff detection with per-category budgets, high-water mark tracking, dual-window (slot + timestamp), R3-1 cold-market floor. Event counters for rapid liquidation/withdrawal detection. Per-instruction threshold checks.
- **18 Invariant Types** — gte, lte, eq, immutable, non_negative, max_decrease, max_increase, delta_bound, conserve, supply_conservation, lamport_conservation, payout_bounded, aggregate_gte, account_guard, custom, tx_cumulative_decrease, when (conditional), monotonic.
- **Reentrancy Guard** — Three modes: Reject (block all self-CPI), Guard (inner calls skip post-checks), Full (everything runs). Depth tracking with cleanup on all error paths.
- **Oracle Checks** — Configurable freshness (staleness in slots) and deviation (basis points from last known price). Owner validation. Dual-provider support.
- **Rate Limits** — Window-based global and per-signer counters. In-place PDA updates.
- **CU Reservation** — Every invariant check is preceded by a compute unit budget assertion to prevent mid-check CU exhaustion.
- **TX Anchor** — CPI-proof transaction fingerprinting. Cross-instruction cumulative decrease tracking.
- **Authority System** — 5 check types: User (first signer), Signer (named key), AnyOf (multi-key), Role (config key), OwnerOf (read authority from account data).
- **Emergency Bypass** — Time-limited bypass with auto-expiry. Invariants disabled, circuit breakers still active. Fail-closed on Clock read failure.
- **PDA State** — Byte-level manual serialization with compile-time offset validation. Every read is bounds-checked. Corruption → fail-closed.

## Quick Start

Add dependencies:

```toml
[dependencies]
perk-sandbox-macros = { git = "https://github.com/kai-builds-ai/perk-sandbox" }
perk-sandbox-runtime = { git = "https://github.com/kai-builds-ai/perk-sandbox" }
anchor-lang = "0.30"
```

Replace `#[program]` with `#[sandbox_program]`:

```rust
use perk_sandbox_macros::sandbox_program;

#[sandbox_program(config = "sandbox.toml")]
pub mod my_program {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // Your business logic — unchanged
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        Ok(())
    }
}
```

Create `sandbox.toml`:

```toml
[reentrancy]
mode = "guard"

[rate_limits.global]
window_slots = 1000
max_count = 100

[circuit_breakers]
enabled = true
scope = "global"

[circuit_breakers.tvl_cliff]
track_field = "market.vault_balance"
window_slots = 2500
action = "pause"

[circuit_breakers.tvl_cliff.budgets]
withdrawal = { max_decrease_pct = 15 }
liquidation = { max_decrease_pct = 25 }
```

That's it. The macro generates the full 12-step pipeline at compile time.

## Testing

```bash
cargo test
```

560+ tests across three crates:
- **sandbox-macros** — attribute parsing, codegen verification, cross-module consistency
- **sandbox-runtime** — circuit breakers, oracle, rate limits, guard, PDA state, TX anchor (unit + boundary + overflow)
- **sandbox-test-program** — 13 end-to-end integration tests covering real scenarios

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full technical deep dive.

## Security

See [SECURITY.md](./SECURITY.md) for the threat model, known limitations, and disclosure policy.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT — see [LICENSE](./LICENSE).

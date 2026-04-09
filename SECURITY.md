# Security

## Threat Model

PERK Sandbox protects against:

- **Vault drain attacks** — Circuit breakers detect abnormal TVL decreases within configurable windows and trigger automatic pause/close-only modes.
- **Oracle manipulation** — Freshness checks reject stale oracle data. Deviation checks reject price spikes beyond configured thresholds. Owner validation prevents fake oracle accounts.
- **Reentrancy via CPI** — Three-mode guard (Reject/Guard/Full) with depth tracking detects and handles self-CPI. Guard cleanup runs on all exit paths.
- **Transaction stuffing** — Rate limits (global and per-signer) with window-based counters prevent rapid-fire abuse.
- **Invariant violations** — 18 types of post-condition checks verify that business logic didn't violate declared safety properties.
- **Cumulative drain across instructions** — TX-level anchor snapshots detect drain split across multiple instructions in a single transaction.
- **Admin key compromise** — Emergency bypass has auto-expiry. Mode flags can only be SET by breakers, never cleared — clearing requires explicit admin action.

## Known Limitations

These are documented design decisions, not bugs:

**TVL field read uses first-match account selection.** The circuit breaker reads the tracked field from the first program-owned account (excluding the sandbox PDA) in the accounts array. If a protocol has multiple program-owned accounts, the breaker only monitors the first one found. Mitigation: Anchor's account constraints validate which accounts are present in each instruction type.

**Per-instruction threshold is per-instruction, not per-transaction.** An attacker can split a drain across multiple instructions in one transaction. The TVL cliff breaker catches cumulative drain via its high-water mark, which persists across instructions within a transaction.

**Windowed staircase.** An attacker can drain within-budget each window cycle. With a 15% budget, ~80% of TVL can be extracted over 10 window periods. This is inherent to windowed breakers. Mitigation: set shorter windows and tighter budgets.

**Signer hash collisions.** Per-signer rate limiting uses an 8-bit hash (256 buckets). Collisions are guaranteed with >20 distinct signers. Two signers sharing a bucket share a rate limit. Mitigation: global rate limits are the primary defense; per-signer is supplementary.

**Oracle without expected_owner is bypassable.** If `expected_owner` is not set in `sandbox.toml`, the oracle check doesn't validate account ownership. An attacker could pass a fake account with manipulated data. Always set `expected_owner`.

## Fail-Closed Design

Every error path in PERK Sandbox rejects the transaction. There is no degraded-operation mode:

- Arithmetic overflow → `CircuitBreakerTriggered` or `MathOverflow`
- PDA corruption → `PDACorrupted`
- Bounds check failure → `PDACorrupted`
- Oracle stale → `OracleStale`
- Rate limit exceeded → `RateLimitExceeded`
- Invariant violated → `InvariantViolation`
- Unknown instruction → `UnknownInstruction`
- Reentrancy in Reject mode → `ReentrancyDetected`
- Empty oracle owner allowlist → `OracleStale` (fail-closed, not fail-open)
- `Clock::get()` failure for emergency bypass → `u64::MAX` slot → bypass treated as expired

## Config Validation

The proc macro enforces configuration correctness at compile time:

- `max_decrease_pct = 0` → compile error (would block all transactions)
- `max_decrease_pct > 100` → compile error (nonsensical percentage)
- Event counter `max_count = 0` → compile error (would DoS on first event)
- Uncategorized instructions get `max_decrease_bps = 0` (fail-closed) with a runtime warning log

## Audit History

V1.0 underwent multiple rounds of adversarial review covering exploit vectors, economic attacks, spec compliance, boundary conditions, borrow discipline, and error path completeness. All critical and high-severity findings were resolved before release.

## Responsible Disclosure

If you find a vulnerability, please report it privately:

- Email: nebula7458@proton.me
- Do NOT open a public issue for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a timeline for fix within 7 days.

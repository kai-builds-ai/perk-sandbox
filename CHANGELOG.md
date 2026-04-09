# Changelog

## V1.0.0 — 2026-04-08

Initial release. Complete 12-step safety pipeline for Solana programs.

### Pipeline
- Reentrancy guard with 3 modes (Reject, Guard, Full)
- Mode checks (paused, close-only, liquidation-paused) with deferred action support
- Unknown instruction rejection (fail-closed)
- Authority pre-checks (5 types: User, Signer, AnyOf, Role, OwnerOf)
- Oracle freshness and deviation pre-checks
- Rate limits (global + per-signer, window-based)
- Input bound pre-checks with argument deserialization
- Instruction-level before/after snapshots (2 strategies: fixed offset, Borsh prefix)
- TX-level anchor snapshots with CPI-proof fingerprinting
- 18 invariant types with CU reservation
- TX cumulative decrease (cross-instruction, always runs including during bypass)
- Circuit breakers: TVL cliff (windowed HWM), event counters, per-instruction threshold
- PDA write-back with guard-safe closure pattern
- Emergency bypass with auto-expiry

### Runtime
- Byte-level PDA serialization with compile-time offset validation
- Checked arithmetic throughout (no unchecked operations on untrusted data)
- SPL Token and Token-2022 account deserialization
- 560+ tests (unit, boundary, integration)

### Config
- Full `sandbox.toml` parser with typed structs
- Compile-time validation for config footguns (max_pct=0, max_count=0)

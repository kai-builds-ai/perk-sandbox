# Contributing

Thanks for your interest in PERK Sandbox. Here's how to contribute.

## Code Standards

- `#![forbid(unsafe_code)]` — no unsafe Rust anywhere in the runtime.
- All arithmetic on untrusted values must use `checked_add`, `checked_sub`, `checked_mul`, `checked_div`, or `saturating_*` variants. No bare `+`, `-`, `*`, `/` on values derived from PDA data or instruction arguments.
- All PDA byte access must be bounds-checked before indexing. Use `data.get(offset..end).ok_or(SandboxError::PDACorrupted)?` or validate `offset + size <= data.len()` before raw indexing.
- No `unwrap()` or `expect()` on values derived from untrusted input. Use `ok_or()`, `map_err()`, or `unwrap_or()` with safe defaults.
- Every error path must be fail-closed. If in doubt, reject the transaction.

## Testing Requirements

Every change must include tests:

- **Unit tests** — in the module's `#[cfg(test)] mod tests` block. Cover the happy path, error paths, and boundary conditions.
- **Integration tests** — in `sandbox-test-program/tests/integration.rs` for end-to-end scenarios that exercise multiple runtime modules together.
- Run `cargo test` from the workspace root. All tests must pass.

## Pull Request Process

1. Fork the repo and create a feature branch.
2. Write your code following the standards above.
3. Add tests. If you fix a bug, add a test that would have caught it.
4. Run `cargo test` — all 560+ tests must pass.
5. Run `cargo clippy` — no warnings.
6. Open a PR with a clear description of what changed and why.

## What We're Looking For

Good first contributions:
- Additional boundary-condition tests for existing modules
- Documentation improvements
- New invariant types
- Config validation improvements (compile-time checks for footguns)

Larger contributions (discuss in an issue first):
- New circuit breaker types
- Multi-account TVL tracking
- Per-instruction oracle check attributes
- On-chain PDA migration tooling

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

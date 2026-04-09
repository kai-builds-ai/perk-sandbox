//! CU Budget Management (Spec §16)
//!
//! Provides `assert_cu_available` to check remaining compute units before
//! running post-checks. Feature-gated: only functional on `target_os = "solana"`.
//! No-op on native (tests).
//!
//! **No logging in this module** — CU is precious.

use solana_program::program_error::ProgramError;

use crate::error::SandboxError;

/// Assert that at least `needed` compute units are available.
///
/// On Solana: calls `sol_remaining_compute_units()` syscall.
/// If `remaining < needed`, returns `Err(SandboxError::InsufficientCU)`.
///
/// # CU cost
/// The syscall itself costs ~100 CU (Spec §16.1).
///
/// # No logging
/// This function deliberately does NOT log — every CU counts when you're
/// checking whether you have enough CU.
#[cfg(target_os = "solana")]
#[inline]
pub fn assert_cu_available(needed: u64) -> Result<(), ProgramError> {
    let remaining = solana_program::compute_units::sol_remaining_compute_units();
    if remaining < needed {
        return Err(SandboxError::InsufficientCU.into());
    }
    Ok(())
}

/// No-op on native targets (tests, CLI tools).
/// Always returns `Ok(())`.
#[cfg(not(target_os = "solana"))]
#[inline]
pub fn assert_cu_available(_needed: u64) -> Result<(), ProgramError> {
    // SandboxError::InsufficientCU is used in the Solana cfg above.
    // Suppress unused warning here since this is the no-op path.
    let _ = SandboxError::InsufficientCU;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_cu_available_noop() {
        // On native, this is always Ok.
        assert!(assert_cu_available(0).is_ok());
        assert!(assert_cu_available(1_000_000).is_ok());
        assert!(assert_cu_available(u64::MAX).is_ok());
    }
}

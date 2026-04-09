//! Re-entrancy guard for PERK Sandbox.
//!
//! Three modes (Section 7 of the spec):
//! - **Reject**: Block all self-CPI. Safest.
//! - **Guard**: Inner calls run pre-checks + circuit breakers, skip invariant post-checks.
//! - **Full**: Everything runs on every call (risk of false positives on intermediate state).

use crate::error::SandboxError;
use solana_program::program_error::ProgramError;

// ── Guard section byte offsets within the PDA guard section ──
// guard_offset + 0 = executing: bool (1 byte)
// guard_offset + 1 = depth: u8 (1 byte)
const GUARD_EXECUTING_OFFSET: usize = 0;
const GUARD_DEPTH_OFFSET: usize = 1;

/// Minimum size of the guard section in the PDA.
pub const GUARD_SECTION_SIZE: usize = 2;

/// Re-entrancy mode configured per-program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReentrancyMode {
    /// Block all self-CPI. Returns `Err(ReentrancyDetected)`.
    Reject,
    /// Inner calls run pre-checks + breakers, skip invariant post-checks.
    /// Outer call runs full checks on final state.
    Guard,
    /// Every call runs everything. Risk of false positives.
    Full,
}

/// Result of a re-entrancy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReentrancyAction {
    /// First (non-reentrant) entry. Run full pipeline.
    Normal,
    /// Re-entrant call in Guard mode. Run pre-checks + breakers, skip invariant post-checks.
    InnerCall,
    /// Re-entrant call that should be blocked (Reject mode). Caller should return error.
    Blocked,
}

// ── Helpers: bounds-checked reads/writes on the guard section slice ──

fn read_executing(guard_data: &[u8]) -> Result<bool, ProgramError> {
    if guard_data.len() < GUARD_SECTION_SIZE {
        return Err(SandboxError::PDACorrupted.into());
    }
    Ok(guard_data[GUARD_EXECUTING_OFFSET] != 0)
}

pub fn read_depth(guard_data: &[u8]) -> Result<u8, ProgramError> {
    if guard_data.len() < GUARD_SECTION_SIZE {
        return Err(SandboxError::PDACorrupted.into());
    }
    Ok(guard_data[GUARD_DEPTH_OFFSET])
}

/// Check re-entrancy status and decide what the caller should do.
///
/// `guard_data` is a mutable slice pointing to the guard section of the PDA.
/// The caller is responsible for extracting this from the PDA at the correct offset.
///
/// Returns:
/// - `Normal` on first entry (not currently executing).
/// - `InnerCall` when re-entering in `Guard` or `Full` mode.
/// - `Blocked` when re-entering in `Reject` mode (caller should return `ReentrancyDetected`).
pub fn check_reentrancy(
    guard_data: &[u8],
    mode: ReentrancyMode,
) -> Result<ReentrancyAction, ProgramError> {
    let executing = read_executing(guard_data)?;

    if !executing {
        return Ok(ReentrancyAction::Normal);
    }

    // We are in a re-entrant call.
    match mode {
        ReentrancyMode::Reject => Ok(ReentrancyAction::Blocked),
        ReentrancyMode::Guard => Ok(ReentrancyAction::InnerCall),
        ReentrancyMode::Full => {
            // Full mode: treat inner calls like normal — everything runs.
            // We still return InnerCall so the caller knows depth > 0,
            // but the caller should run full checks.
            Ok(ReentrancyAction::InnerCall)
        }
    }
}

/// Set the executing flag to `true`. Called on first entry.
pub fn set_executing(guard_data: &mut [u8]) -> Result<(), ProgramError> {
    if guard_data.len() < GUARD_SECTION_SIZE {
        return Err(SandboxError::PDACorrupted.into());
    }
    guard_data[GUARD_EXECUTING_OFFSET] = 1;
    Ok(())
}

/// Clear the executing flag. Called when the outermost call completes.
pub fn clear_executing(guard_data: &mut [u8]) -> Result<(), ProgramError> {
    if guard_data.len() < GUARD_SECTION_SIZE {
        return Err(SandboxError::PDACorrupted.into());
    }
    guard_data[GUARD_EXECUTING_OFFSET] = 0;
    Ok(())
}

/// Increment the call depth. Returns the new depth.
/// Uses checked arithmetic — returns `PDACorrupted` on overflow (depth > 255 is pathological).
pub fn increment_depth(guard_data: &mut [u8]) -> Result<u8, ProgramError> {
    if guard_data.len() < GUARD_SECTION_SIZE {
        return Err(SandboxError::PDACorrupted.into());
    }
    let current = guard_data[GUARD_DEPTH_OFFSET];
    let new_depth = current
        .checked_add(1)
        .ok_or(SandboxError::PDACorrupted)?;
    guard_data[GUARD_DEPTH_OFFSET] = new_depth;
    Ok(new_depth)
}

/// Decrement the call depth. Returns the new depth.
/// Returns `PDACorrupted` on underflow.
pub fn decrement_depth(guard_data: &mut [u8]) -> Result<u8, ProgramError> {
    if guard_data.len() < GUARD_SECTION_SIZE {
        return Err(SandboxError::PDACorrupted.into());
    }
    let current = guard_data[GUARD_DEPTH_OFFSET];
    let new_depth = current
        .checked_sub(1)
        .ok_or(SandboxError::PDACorrupted)?;
    guard_data[GUARD_DEPTH_OFFSET] = new_depth;
    Ok(new_depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_guard() -> [u8; GUARD_SECTION_SIZE] {
        [0u8; GUARD_SECTION_SIZE]
    }

    #[test]
    fn test_normal_entry() {
        let data = fresh_guard();
        let action = check_reentrancy(&data, ReentrancyMode::Guard).unwrap();
        assert_eq!(action, ReentrancyAction::Normal);
    }

    #[test]
    fn test_set_and_clear_executing() {
        let mut data = fresh_guard();

        set_executing(&mut data).unwrap();
        assert!(read_executing(&data).unwrap());

        clear_executing(&mut data).unwrap();
        assert!(!read_executing(&data).unwrap());
    }

    #[test]
    fn test_reject_mode_blocks() {
        let mut data = fresh_guard();
        set_executing(&mut data).unwrap();

        let action = check_reentrancy(&data, ReentrancyMode::Reject).unwrap();
        assert_eq!(action, ReentrancyAction::Blocked);
    }

    #[test]
    fn test_guard_mode_inner_call() {
        let mut data = fresh_guard();
        set_executing(&mut data).unwrap();

        let action = check_reentrancy(&data, ReentrancyMode::Guard).unwrap();
        assert_eq!(action, ReentrancyAction::InnerCall);
    }

    #[test]
    fn test_full_mode_inner_call() {
        let mut data = fresh_guard();
        set_executing(&mut data).unwrap();

        let action = check_reentrancy(&data, ReentrancyMode::Full).unwrap();
        assert_eq!(action, ReentrancyAction::InnerCall);
    }

    #[test]
    fn test_depth_increment_decrement() {
        let mut data = fresh_guard();
        assert_eq!(read_depth(&data).unwrap(), 0);

        let d = increment_depth(&mut data).unwrap();
        assert_eq!(d, 1);

        let d = increment_depth(&mut data).unwrap();
        assert_eq!(d, 2);

        let d = decrement_depth(&mut data).unwrap();
        assert_eq!(d, 1);

        let d = decrement_depth(&mut data).unwrap();
        assert_eq!(d, 0);
    }

    #[test]
    fn test_depth_underflow() {
        let mut data = fresh_guard();
        let result = decrement_depth(&mut data);
        assert!(result.is_err());
    }

    #[test]
    fn test_depth_overflow() {
        let mut data = fresh_guard();
        data[GUARD_DEPTH_OFFSET] = 255;
        let result = increment_depth(&mut data);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_data_too_small() {
        let data: [u8; 0] = [];
        assert!(check_reentrancy(&data, ReentrancyMode::Guard).is_err());

        let mut small = [0u8; 1];
        assert!(set_executing(&mut small).is_err());
    }

    #[test]
    fn test_full_lifecycle() {
        let mut data = fresh_guard();

        // First entry
        let action = check_reentrancy(&data, ReentrancyMode::Guard).unwrap();
        assert_eq!(action, ReentrancyAction::Normal);
        set_executing(&mut data).unwrap();
        let depth = increment_depth(&mut data).unwrap();
        assert_eq!(depth, 1);

        // Re-entrant call
        let action = check_reentrancy(&data, ReentrancyMode::Guard).unwrap();
        assert_eq!(action, ReentrancyAction::InnerCall);
        let depth = increment_depth(&mut data).unwrap();
        assert_eq!(depth, 2);

        // Inner call returns
        let depth = decrement_depth(&mut data).unwrap();
        assert_eq!(depth, 1);

        // Outer call returns
        let depth = decrement_depth(&mut data).unwrap();
        assert_eq!(depth, 0);
        clear_executing(&mut data).unwrap();

        // Back to normal
        let action = check_reentrancy(&data, ReentrancyMode::Guard).unwrap();
        assert_eq!(action, ReentrancyAction::Normal);
    }
}

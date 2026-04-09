//! Oracle freshness and deviation checks for PERK Sandbox.
//!
//! Generic oracle reading — supports configurable byte offsets so different
//! oracle providers (Pyth, Switchboard, custom) work without code changes.

use crate::error::SandboxError;
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

/// Configuration for reading an oracle account with a specific layout.
#[derive(Debug, Clone, Copy)]
pub struct OracleLayout {
    /// Byte offset where the price (u64 or i64) is stored.
    pub price_offset: usize,
    /// Number of bytes for the price field (must be 8 for u64/i64).
    pub price_size: usize,
    /// Byte offset where the last-update slot (u64) is stored.
    pub slot_offset: usize,
    /// Byte offset where the last-update timestamp (i64) is stored.
    /// Set to `None` if the oracle doesn't provide a timestamp.
    pub timestamp_offset: Option<usize>,
}

/// A price reading from an oracle account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleReading {
    pub price: u64,
    pub last_slot: u64,
    pub last_timestamp: Option<i64>,
}

/// Validate that an oracle account is owned by a known oracle program.
/// Call this before `read_oracle` when the oracle is passed via remaining_accounts.
///
/// Known oracle programs:
/// - Pyth: `FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH` (devnet)
/// - Switchboard V2: `SW1TCH7qEPTdLsDHRgPuMQjbQxKdH2aBStViMFnt64f`
pub fn validate_oracle_owner(
    oracle_account: &AccountInfo,
    allowed_owners: &[Pubkey],
) -> Result<(), ProgramError> {
    if allowed_owners.is_empty() {
        // Fail-closed: empty allowlist means no oracle is trusted
        return Err(SandboxError::OracleStale.into());
    }
    for owner in allowed_owners {
        if oracle_account.owner == owner {
            return Ok(());
        }
    }
    Err(SandboxError::OracleStale.into())
}

/// Read price and timing data from an oracle account using the given layout.
///
/// All reads are bounds-checked against actual account data length.
///
/// # Security
/// Callers SHOULD provide `expected_owner` to validate the oracle account
/// is owned by a known oracle program. Without this check, an attacker
/// could pass a fake account with manipulated price/slot data.
pub fn read_oracle(
    oracle_account: &AccountInfo,
    layout: &OracleLayout,
    expected_owner: Option<&Pubkey>,
) -> Result<OracleReading, ProgramError> {
    // Validate oracle account ownership
    if let Some(owner) = expected_owner {
        if oracle_account.owner != owner {
            return Err(SandboxError::OracleStale.into());
        }
    }
    if layout.price_size != 8 {
        return Err(SandboxError::OracleStale.into());
    }

    let data = oracle_account
        .try_borrow_data()
        .map_err(|_| ProgramError::from(SandboxError::OracleStale))?;
    let data_len = data.len();

    // Bounds check for price
    let price_end = layout
        .price_offset
        .checked_add(8)
        .ok_or(SandboxError::OracleStale)?;
    if price_end > data_len {
        return Err(SandboxError::OracleStale.into());
    }

    // Bounds check for slot
    let slot_end = layout
        .slot_offset
        .checked_add(8)
        .ok_or(SandboxError::OracleStale)?;
    if slot_end > data_len {
        return Err(SandboxError::OracleStale.into());
    }

    let price = u64::from_le_bytes(
        data[layout.price_offset..price_end]
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::OracleStale))?,
    );

    let last_slot = u64::from_le_bytes(
        data[layout.slot_offset..slot_end]
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::OracleStale))?,
    );

    let last_timestamp = if let Some(ts_offset) = layout.timestamp_offset {
        let ts_end = ts_offset
            .checked_add(8)
            .ok_or(SandboxError::OracleStale)?;
        if ts_end > data_len {
            return Err(SandboxError::OracleStale.into());
        }
        Some(i64::from_le_bytes(
            data[ts_offset..ts_end]
                .try_into()
                .map_err(|_| ProgramError::from(SandboxError::OracleStale))?,
        ))
    } else {
        None
    };

    Ok(OracleReading {
        price,
        last_slot,
        last_timestamp,
    })
}

/// Check that the oracle's last update slot is within `max_staleness_slots` of `current_slot`.
///
/// Returns `Err(OracleStale)` if the oracle data is too old.
pub fn check_oracle_freshness(
    oracle_account: &AccountInfo,
    layout: &OracleLayout,
    max_staleness_slots: u64,
    current_slot: u64,
    expected_owner: Option<&Pubkey>,
) -> Result<(), ProgramError> {
    let reading = read_oracle(oracle_account, layout, expected_owner)?;

    // Checked subtraction: if oracle slot is somehow in the future, staleness = 0
    let staleness = current_slot.saturating_sub(reading.last_slot);

    if staleness > max_staleness_slots {
        return Err(SandboxError::OracleStale.into());
    }

    Ok(())
}

/// Check that the oracle price hasn't deviated too far from a last-known price.
///
/// `max_deviation_bps` is in basis points (1 bps = 0.01%).
/// Returns `Err(OracleDeviation)` if the deviation exceeds the limit.
///
/// Uses checked arithmetic throughout.
pub fn check_oracle_deviation(
    oracle_account: &AccountInfo,
    layout: &OracleLayout,
    max_deviation_bps: u64,
    last_known_price: u64,
    expected_owner: Option<&Pubkey>,
) -> Result<(), ProgramError> {
    let reading = read_oracle(oracle_account, layout, expected_owner)?;

    // Avoid division by zero
    if last_known_price == 0 {
        // If last known price is 0 and current price is also 0, no deviation.
        // If last known price is 0 and current price > 0, that's infinite deviation.
        if reading.price == 0 {
            return Ok(());
        }
        return Err(SandboxError::OracleDeviation.into());
    }

    // deviation = abs(current - last_known) * 10_000 / last_known
    let diff = if reading.price >= last_known_price {
        reading
            .price
            .checked_sub(last_known_price)
            .ok_or(SandboxError::OracleDeviation)?
    } else {
        last_known_price
            .checked_sub(reading.price)
            .ok_or(SandboxError::OracleDeviation)?
    };

    // diff * 10_000 could overflow u64 for very large prices.
    // Use u128 for intermediate calculation.
    let deviation_bps = (diff as u128)
        .checked_mul(10_000)
        .ok_or(SandboxError::OracleDeviation)?
        .checked_div(last_known_price as u128)
        .ok_or(SandboxError::OracleDeviation)?;

    if deviation_bps > max_deviation_bps as u128 {
        return Err(SandboxError::OracleDeviation.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::{clock::Epoch, system_program};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Build a fake oracle AccountInfo with price at `price_offset` and slot at `slot_offset`.
    fn make_oracle_account(
        price: u64,
        slot: u64,
        timestamp: Option<i64>,
        layout: &OracleLayout,
    ) -> (Pubkey, u64, Vec<u8>, Pubkey) {
        let data_size = 256; // big enough
        let mut data = vec![0u8; data_size];

        data[layout.price_offset..layout.price_offset + 8]
            .copy_from_slice(&price.to_le_bytes());
        data[layout.slot_offset..layout.slot_offset + 8]
            .copy_from_slice(&slot.to_le_bytes());
        if let (Some(ts_off), Some(ts)) = (layout.timestamp_offset, timestamp) {
            data[ts_off..ts_off + 8].copy_from_slice(&ts.to_le_bytes());
        }

        let key = Pubkey::new_unique();
        let owner = system_program::id();
        (key, 0, data, owner)
    }

    fn make_account_info<'a>(
        key: &'a Pubkey,
        lamports: &'a mut u64,
        data: &'a mut [u8],
        owner: &'a Pubkey,
    ) -> AccountInfo<'a> {
        AccountInfo::new(
            key,
            false,
            false,
            lamports,
            data,
            owner,
            false,
            Epoch::default(),
        )
    }

    fn default_layout() -> OracleLayout {
        OracleLayout {
            price_offset: 16,
            price_size: 8,
            slot_offset: 24,
            timestamp_offset: Some(32),
        }
    }

    #[test]
    fn test_read_oracle_basic() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(42_000_000, 100, Some(1_700_000_000), &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let reading = read_oracle(&info, &layout, None).unwrap();
        assert_eq!(reading.price, 42_000_000);
        assert_eq!(reading.last_slot, 100);
        assert_eq!(reading.last_timestamp, Some(1_700_000_000));
    }

    #[test]
    fn test_freshness_ok() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(1_000, 95, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let result = check_oracle_freshness(&info, &layout, 10, 100, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_freshness_stale() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(1_000, 80, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let result = check_oracle_freshness(&info, &layout, 10, 100, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_deviation_ok() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(10_100, 100, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        // 1% deviation = 100 bps. Allow 200 bps.
        let result = check_oracle_deviation(&info, &layout, 200, 10_000, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deviation_exceeded() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(10_500, 100, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        // 5% deviation = 500 bps. Allow only 200 bps.
        let result = check_oracle_deviation(&info, &layout, 200, 10_000, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_deviation_zero_last_known() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(100, 100, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        // last_known = 0, current > 0 → deviation error
        let result = check_oracle_deviation(&info, &layout, 500, 0, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_deviation_both_zero() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(0, 100, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let result = check_oracle_deviation(&info, &layout, 500, 0, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_data_too_small() {
        let layout = OracleLayout {
            price_offset: 250,
            price_size: 8,
            slot_offset: 260,
            timestamp_offset: None,
        };
        let key = Pubkey::new_unique();
        let owner = system_program::id();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 10]; // way too small
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let result = read_oracle(&info, &layout, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_oracle_wrong_owner_rejected() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(42_000_000, 100, Some(1_700_000_000), &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let wrong_owner = Pubkey::new_unique();
        let result = read_oracle(&info, &layout, Some(&wrong_owner));
        assert!(result.is_err(), "oracle with wrong owner should be rejected");
    }

    #[test]
    fn test_read_oracle_correct_owner_accepted() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(42_000_000, 100, Some(1_700_000_000), &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        // The owner is system_program::id() from make_oracle_account
        let result = read_oracle(&info, &layout, Some(&owner));
        assert!(result.is_ok(), "oracle with correct owner should be accepted");
    }

    #[test]
    fn test_validate_oracle_owner_empty_allowlist() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(1_000, 100, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        // Empty allowlist = fail-closed
        assert!(validate_oracle_owner(&info, &[]).is_err());
    }

    #[test]
    fn test_validate_oracle_owner_not_in_allowlist() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(1_000, 100, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let allowed = vec![Pubkey::new_unique(), Pubkey::new_unique()];
        assert!(validate_oracle_owner(&info, &allowed).is_err());
    }

    #[test]
    fn test_validate_oracle_owner_in_allowlist() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(1_000, 100, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let allowed = vec![Pubkey::new_unique(), owner];
        assert!(validate_oracle_owner(&info, &allowed).is_ok());
    }

    #[test]
    fn test_freshness_with_wrong_owner_rejected() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(1_000, 95, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let wrong_owner = Pubkey::new_unique();
        let result = check_oracle_freshness(&info, &layout, 10, 100, Some(&wrong_owner));
        assert!(result.is_err(), "freshness check should fail when owner doesn't match");
    }

    #[test]
    fn test_deviation_with_wrong_owner_rejected() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(10_100, 100, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let wrong_owner = Pubkey::new_unique();
        let result = check_oracle_deviation(&info, &layout, 200, 10_000, Some(&wrong_owner));
        assert!(result.is_err(), "deviation check should fail when owner doesn't match");
    }

    #[test]
    fn test_freshness_with_correct_owner_passes() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(1_000, 95, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        let result = check_oracle_freshness(&info, &layout, 10, 100, Some(&owner));
        assert!(result.is_ok(), "freshness check should pass with correct owner");
    }

    #[test]
    fn test_validate_oracle_owner_empty_fails_closed() {
        let layout = default_layout();
        let (key, mut lamports, mut data, owner) =
            make_oracle_account(1_000, 100, None, &layout);
        let info = make_account_info(&key, &mut lamports, &mut data, &owner);

        // Empty allowlist must now fail-closed
        let result = validate_oracle_owner(&info, &[]);
        assert!(result.is_err(), "empty allowlist should fail-closed");
    }
}

//! Transaction-level invariant support: fingerprinting, anchor snapshots,
//! and cumulative decrease checks.
//!
//! Section 5 of the PERK Sandbox spec.

use solana_program::{
    hash::hashv,
    instruction::Instruction,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::error::SandboxError;

// ── PDA layout constants ────────────────────────────────────────────────────
//
// The caller passes the TransactionAnchor *section* of PDA data.
// Layout within that section:
//
//   [0..32]   fingerprint          32 bytes
//   [32]      field_count          1 byte   (max 16)
//   [33..33+count*FIELD_SIZE]      anchor fields
//
// Each anchor field (42 bytes):
//   [0..32]   account pubkey       32 bytes
//   [32..34]  reserved / field_id  2 bytes  (u16 LE, currently 0)
//   [34..42]  value                8 bytes  (u64 LE)

/// Byte size of the fingerprint.
pub const FINGERPRINT_LEN: usize = 32;
/// Offset of field_count within the anchor section.
const FIELD_COUNT_OFFSET: usize = FINGERPRINT_LEN; // 32
/// Offset where field entries begin.
const FIELDS_START: usize = FIELD_COUNT_OFFSET + 1; // 33
/// Bytes per anchor field entry.
pub const FIELD_SIZE: usize = 42;
/// Maximum number of anchor fields.
pub const MAX_ANCHOR_FIELDS: usize = 16;
/// Minimum PDA section size required (fingerprint + count + max fields).
pub const ANCHOR_SECTION_SIZE: usize = FIELDS_START + MAX_ANCHOR_FIELDS * FIELD_SIZE; // 705

// ── 1. Transaction fingerprint ──────────────────────────────────────────────

/// Pure hash logic: deterministic fingerprint from a list of instructions.
///
/// CPI-proof because the top-level instruction list is fixed at transaction
/// creation time and identical from every vantage point within the tx.
pub fn compute_tx_fingerprint_from_instructions(instructions: &[Instruction]) -> [u8; 32] {
    let mut running = hashv(&[]);
    for ix in instructions {
        let data_hash = hashv(&[&ix.data]);
        running = hashv(&[
            running.as_ref(),
            ix.program_id.as_ref(),
            &(ix.data.len() as u64).to_le_bytes(),
            &(ix.accounts.len() as u64).to_le_bytes(),
            data_hash.as_ref(),
        ]);
    }
    running.to_bytes()
}

/// Compute fingerprint by reading the Instructions sysvar raw data.
///
/// The first 2 bytes of the sysvar data encode the instruction count as
/// `u16` little-endian.  For each index we call
/// `load_instruction_at_checked` (re-borrows internally).
///
/// # Errors
/// Returns `ProgramError::InvalidAccountData` if the sysvar data is too
/// short or an instruction cannot be loaded.
#[cfg(not(test))]
pub fn compute_tx_fingerprint(
    ix_sysvar: &solana_program::account_info::AccountInfo,
) -> Result<[u8; 32], ProgramError> {
    use solana_program::sysvar::instructions as ix_sysvar_mod;

    // Validate key
    if *ix_sysvar.key != ix_sysvar_mod::ID {
        return Err(ProgramError::InvalidArgument);
    }

    let data = ix_sysvar.try_borrow_data()?;
    if data.len() < 2 {
        return Err(ProgramError::InvalidAccountData);
    }
    let num_ix = u16::from_le_bytes([data[0], data[1]]) as usize;
    drop(data); // release borrow before load_instruction_at_checked

    let mut running = hashv(&[]);
    for i in 0..num_ix {
        let ix = ix_sysvar_mod::load_instruction_at_checked(i, ix_sysvar)?;
        let data_hash = hashv(&[&ix.data]);
        running = hashv(&[
            running.as_ref(),
            ix.program_id.as_ref(),
            &(ix.data.len() as u64).to_le_bytes(),
            &(ix.accounts.len() as u64).to_le_bytes(),
            data_hash.as_ref(),
        ]);
    }
    Ok(running.to_bytes())
}

// ── 2. First-invocation detection ───────────────────────────────────────────

/// Returns `true` when this is the first sandbox invocation in the current
/// transaction.  Compares the stored fingerprint in the PDA anchor section
/// against the freshly computed one.
///
/// - Different fingerprint → first invocation → `true`
/// - Same fingerprint      → subsequent       → `false`
pub fn is_first_sandbox_invocation(pda_data: &[u8], fingerprint: &[u8; 32]) -> bool {
    if pda_data.len() < FINGERPRINT_LEN {
        // No stored fingerprint ⇒ definitely first
        return true;
    }
    pda_data[..FINGERPRINT_LEN] != fingerprint[..]
}

// ── 3. Write anchor snapshot ────────────────────────────────────────────────

/// Store the transaction fingerprint and anchor field values in the
/// TransactionAnchor section of the PDA.
///
/// # Panics
/// Panics (via bounds check) if `pda_data` is too small or if more than
/// `MAX_ANCHOR_FIELDS` are supplied.
pub fn write_anchor_snapshot(
    pda_data: &mut [u8],
    fingerprint: &[u8; 32],
    fields: &[(Pubkey, u64)],
) {
    assert!(
        fields.len() <= MAX_ANCHOR_FIELDS,
        "too many anchor fields (max {})",
        MAX_ANCHOR_FIELDS
    );
    let required = FIELDS_START + fields.len() * FIELD_SIZE;
    assert!(
        pda_data.len() >= required,
        "PDA anchor section too small: need {} bytes, have {}",
        required,
        pda_data.len()
    );

    // Fingerprint
    pda_data[..FINGERPRINT_LEN].copy_from_slice(fingerprint);

    // Field count
    pda_data[FIELD_COUNT_OFFSET] = fields.len() as u8;

    // Fields
    for (i, (pubkey, value)) in fields.iter().enumerate() {
        let base = FIELDS_START + i * FIELD_SIZE;
        pda_data[base..base + 32].copy_from_slice(pubkey.as_ref());
        // reserved / field_id — zero for now
        pda_data[base + 32] = 0;
        pda_data[base + 33] = 0;
        pda_data[base + 34..base + 42].copy_from_slice(&value.to_le_bytes());
    }
}

// ── 3b. Write anchor fields only (preserve fingerprint) ───────────────────

/// Write anchor field values WITHOUT overwriting the fingerprint.
/// Used by the per-instruction wrapper after the main entrypoint
/// has already written the correct fingerprint.
pub fn write_anchor_fields_only(
    pda_data: &mut [u8],
    fields: &[(Pubkey, u64)],
) {
    assert!(
        fields.len() <= MAX_ANCHOR_FIELDS,
        "too many anchor fields (max {})",
        MAX_ANCHOR_FIELDS
    );
    let required = FIELDS_START + fields.len() * FIELD_SIZE;
    assert!(
        pda_data.len() >= required,
        "PDA anchor section too small: need {} bytes, have {}",
        required,
        pda_data.len()
    );
    pda_data[FIELD_COUNT_OFFSET] = fields.len() as u8;
    for (i, (pubkey, value)) in fields.iter().enumerate() {
        let base = FIELDS_START + i * FIELD_SIZE;
        pda_data[base..base + 32].copy_from_slice(pubkey.as_ref());
        pda_data[base + 32] = 0;
        pda_data[base + 33] = 0;
        pda_data[base + 34..base + 42].copy_from_slice(&value.to_le_bytes());
    }
}

// ── 4. Read anchor snapshot ─────────────────────────────────────────────────

/// Read stored anchor values from the TransactionAnchor section of the PDA.
///
/// # Errors
/// - `SandboxError::PDACorrupted` if data is too short or field count exceeds
///   `MAX_ANCHOR_FIELDS`.
pub fn read_anchor_snapshot(pda_data: &[u8]) -> Result<Vec<(Pubkey, u64)>, ProgramError> {
    if pda_data.len() < FIELDS_START {
        return Err(SandboxError::PDACorrupted.into());
    }
    let count = pda_data[FIELD_COUNT_OFFSET] as usize;
    if count > MAX_ANCHOR_FIELDS {
        return Err(SandboxError::PDACorrupted.into());
    }
    let required = FIELDS_START + count * FIELD_SIZE;
    if pda_data.len() < required {
        return Err(SandboxError::PDACorrupted.into());
    }

    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let base = FIELDS_START + i * FIELD_SIZE;
        let pubkey = Pubkey::from(<[u8; 32]>::try_from(&pda_data[base..base + 32]).unwrap());
        // skip 2 reserved bytes at base+32..base+34
        let value = u64::from_le_bytes(
            pda_data[base + 34..base + 42]
                .try_into()
                .map_err(|_| ProgramError::from(SandboxError::PDACorrupted))?,
        );
        result.push((pubkey, value));
    }
    Ok(result)
}

// ── 5. Cumulative decrease check ────────────────────────────────────────────

/// Check that the cumulative decrease from `anchor_value` to `current_value`
/// does not exceed `max_decrease_pct` percent.
///
/// - If `current_value >= anchor_value` (increase or unchanged): always passes.
/// - If `anchor_value == 0`: passes (cannot decrease from zero).
/// - Otherwise: `decrease_pct = (anchor - current) * 100 / anchor`.
///   Exceeding `max_decrease_pct` returns
///   `Err(SandboxError::TxCumulativeDecreaseExceeded)`.
///
/// All arithmetic is checked.
pub fn check_tx_cumulative_decrease(
    anchor_value: u64,
    current_value: u64,
    max_decrease_pct: u8,
) -> Result<(), ProgramError> {
    // Increase or unchanged — always OK
    if current_value >= anchor_value {
        return Ok(());
    }

    // anchor_value == 0 with current < anchor is impossible because
    // current_value >= 0 always (unsigned). But be defensive:
    if anchor_value == 0 {
        return Ok(());
    }

    // decrease = anchor_value - current_value  (safe: we checked current < anchor)
    let decrease = anchor_value
        .checked_sub(current_value)
        .ok_or(ProgramError::from(SandboxError::InvariantViolation))?;

    // Special case: max_pct == 0 means monotonic (no decrease allowed at all).
    // Any non-zero decrease fails — avoids integer truncation hiding small decreases.
    if max_decrease_pct == 0 && decrease > 0 {
        return Err(SandboxError::TxCumulativeDecreaseExceeded.into());
    }

    // Use comparison-based check to avoid integer truncation:
    // decrease * 100 > max_decrease_pct * anchor_value  (no division, no truncation)
    // Use u128 to handle overflow.
    let lhs = (decrease as u128)
        .checked_mul(100)
        .ok_or(ProgramError::from(SandboxError::InvariantViolation))?;
    let rhs = (max_decrease_pct as u128)
        .checked_mul(anchor_value as u128)
        .ok_or(ProgramError::from(SandboxError::InvariantViolation))?;

    if lhs > rhs {
        return Err(SandboxError::TxCumulativeDecreaseExceeded.into());
    }

    Ok(())
}

// ── 6. Read stored fingerprint (helper) ─────────────────────────────────────

/// Extract the stored fingerprint from PDA anchor section data.
/// Returns `None` if the data is too short.
pub fn read_stored_fingerprint(pda_data: &[u8]) -> Option<[u8; 32]> {
    if pda_data.len() < FINGERPRINT_LEN {
        return None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&pda_data[..FINGERPRINT_LEN]);
    Some(fp)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::instruction::AccountMeta;

    // ── Helpers ─────────────────────────────────────────────────────────

    fn make_instruction(program_id: Pubkey, data: &[u8], num_accounts: usize) -> Instruction {
        let accounts: Vec<AccountMeta> = (0..num_accounts)
            .map(|_| AccountMeta::new_readonly(Pubkey::new_unique(), false))
            .collect();
        Instruction {
            program_id,
            accounts,
            data: data.to_vec(),
        }
    }

    fn blank_anchor_section() -> Vec<u8> {
        vec![0u8; ANCHOR_SECTION_SIZE]
    }

    // ── Fingerprint tests ───────────────────────────────────────────────

    #[test]
    fn fingerprint_deterministic() {
        let pid = Pubkey::new_unique();
        let ixs = vec![
            make_instruction(pid, &[1, 2, 3], 2),
            make_instruction(pid, &[4, 5], 1),
        ];
        let fp1 = compute_tx_fingerprint_from_instructions(&ixs);
        let fp2 = compute_tx_fingerprint_from_instructions(&ixs);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    }

    #[test]
    fn fingerprint_differs_with_different_data() {
        let pid = Pubkey::new_unique();
        let ixs_a = vec![make_instruction(pid, &[1, 2, 3], 2)];
        let ixs_b = vec![make_instruction(pid, &[1, 2, 4], 2)];
        let fp_a = compute_tx_fingerprint_from_instructions(&ixs_a);
        let fp_b = compute_tx_fingerprint_from_instructions(&ixs_b);
        assert_ne!(fp_a, fp_b, "different instruction data → different fingerprint");
    }

    #[test]
    fn fingerprint_differs_with_different_program() {
        let ixs_a = vec![make_instruction(Pubkey::new_unique(), &[1], 1)];
        let ixs_b = vec![make_instruction(Pubkey::new_unique(), &[1], 1)];
        let fp_a = compute_tx_fingerprint_from_instructions(&ixs_a);
        let fp_b = compute_tx_fingerprint_from_instructions(&ixs_b);
        assert_ne!(fp_a, fp_b, "different program_id → different fingerprint");
    }

    #[test]
    fn fingerprint_differs_with_different_account_count() {
        let pid = Pubkey::new_unique();
        let ixs_a = vec![make_instruction(pid, &[1], 2)];
        let ixs_b = vec![make_instruction(pid, &[1], 3)];
        let fp_a = compute_tx_fingerprint_from_instructions(&ixs_a);
        let fp_b = compute_tx_fingerprint_from_instructions(&ixs_b);
        assert_ne!(fp_a, fp_b, "different account count → different fingerprint");
    }

    #[test]
    fn fingerprint_order_sensitive() {
        let pid = Pubkey::new_unique();
        let ix1 = make_instruction(pid, &[1], 1);
        let ix2 = make_instruction(pid, &[2], 1);
        let fp_a = compute_tx_fingerprint_from_instructions(&[ix1.clone(), ix2.clone()]);
        let fp_b = compute_tx_fingerprint_from_instructions(&[ix2, ix1]);
        assert_ne!(fp_a, fp_b, "instruction order matters");
    }

    #[test]
    fn fingerprint_empty_instructions() {
        let fp = compute_tx_fingerprint_from_instructions(&[]);
        // Should not panic — just returns hash of empty
        assert_eq!(fp.len(), 32);
    }

    // ── CPI-proof: same ix list = same fingerprint ──────────────────────

    #[test]
    fn fingerprint_cpi_proof_same_tx() {
        // Simulate: a tx with [helper_program_ix, our_program_ix]
        // Both top-level and CPI calls see the same instruction list.
        let helper = Pubkey::new_unique();
        let ours = Pubkey::new_unique();
        let ix_list = vec![
            make_instruction(helper, &[0xAA], 1),
            make_instruction(ours, &[0xBB, 0xCC], 3),
        ];
        // "top-level" invocation computes fingerprint
        let fp_toplevel = compute_tx_fingerprint_from_instructions(&ix_list);
        // "CPI" invocation sees the exact same top-level list
        let fp_cpi = compute_tx_fingerprint_from_instructions(&ix_list);
        assert_eq!(fp_toplevel, fp_cpi, "CPI-proof: same tx → same fingerprint");
    }

    #[test]
    fn fingerprint_cross_tx_differs() {
        // tx A has instructions [ix1, ix2], tx B has [ix1, ix3]
        let pid = Pubkey::new_unique();
        let ix1 = make_instruction(pid, &[1], 1);
        let ix2 = make_instruction(pid, &[2], 1);
        let ix3 = make_instruction(pid, &[3], 1);
        let fp_a = compute_tx_fingerprint_from_instructions(&[ix1.clone(), ix2]);
        let fp_b = compute_tx_fingerprint_from_instructions(&[ix1, ix3]);
        assert_ne!(fp_a, fp_b, "different transactions → different fingerprints");
    }

    // ── is_first_sandbox_invocation ─────────────────────────────────────

    #[test]
    fn first_invocation_on_fresh_pda() {
        let pda = blank_anchor_section();
        let fp = [0xABu8; 32];
        assert!(
            is_first_sandbox_invocation(&pda, &fp),
            "zeroed PDA ≠ non-zero fingerprint → first"
        );
    }

    #[test]
    fn first_invocation_different_fingerprint() {
        let mut pda = blank_anchor_section();
        let old_fp = [1u8; 32];
        let new_fp = [2u8; 32];
        pda[..32].copy_from_slice(&old_fp);
        assert!(
            is_first_sandbox_invocation(&pda, &new_fp),
            "different fingerprint → first invocation"
        );
    }

    #[test]
    fn subsequent_invocation_same_fingerprint() {
        let mut pda = blank_anchor_section();
        let fp = [0x42u8; 32];
        pda[..32].copy_from_slice(&fp);
        assert!(
            !is_first_sandbox_invocation(&pda, &fp),
            "same fingerprint → NOT first"
        );
    }

    #[test]
    fn first_invocation_short_pda() {
        let pda = vec![0u8; 10]; // too short to hold fingerprint
        let fp = [0u8; 32];
        assert!(
            is_first_sandbox_invocation(&pda, &fp),
            "short PDA → always first"
        );
    }

    // ── write / read anchor snapshot round-trip ─────────────────────────

    #[test]
    fn write_read_roundtrip_empty() {
        let mut pda = blank_anchor_section();
        let fp = [0xFFu8; 32];
        write_anchor_snapshot(&mut pda, &fp, &[]);
        assert_eq!(&pda[..32], &fp);
        let fields = read_anchor_snapshot(&pda).unwrap();
        assert!(fields.is_empty());
    }

    #[test]
    fn write_read_roundtrip_single() {
        let mut pda = blank_anchor_section();
        let fp = [0x11u8; 32];
        let pk = Pubkey::new_unique();
        let value = 1_000_000_000u64;
        write_anchor_snapshot(&mut pda, &fp, &[(pk, value)]);

        let fields = read_anchor_snapshot(&pda).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0], (pk, value));
    }

    #[test]
    fn write_read_roundtrip_max_fields() {
        let mut pda = blank_anchor_section();
        let fp = [0x22u8; 32];
        let fields_in: Vec<(Pubkey, u64)> = (0..MAX_ANCHOR_FIELDS)
            .map(|i| (Pubkey::new_unique(), (i as u64 + 1) * 100))
            .collect();
        write_anchor_snapshot(&mut pda, &fp, &fields_in);

        let fields_out = read_anchor_snapshot(&pda).unwrap();
        assert_eq!(fields_out, fields_in);
    }

    #[test]
    #[should_panic(expected = "too many anchor fields")]
    fn write_too_many_fields_panics() {
        let mut pda = vec![0u8; ANCHOR_SECTION_SIZE + FIELD_SIZE];
        let fp = [0u8; 32];
        let fields: Vec<(Pubkey, u64)> = (0..MAX_ANCHOR_FIELDS + 1)
            .map(|i| (Pubkey::new_unique(), i as u64))
            .collect();
        write_anchor_snapshot(&mut pda, &fp, &fields);
    }

    #[test]
    fn read_corrupted_count_too_large() {
        let mut pda = blank_anchor_section();
        pda[FIELD_COUNT_OFFSET] = MAX_ANCHOR_FIELDS as u8 + 1;
        assert!(read_anchor_snapshot(&pda).is_err());
    }

    #[test]
    fn read_truncated_pda() {
        let pda = vec![0u8; FIELDS_START - 1]; // too short for count byte
        assert!(read_anchor_snapshot(&pda).is_err());
    }

    // ── Same-tx detection integration ───────────────────────────────────

    #[test]
    fn same_tx_detection_flow() {
        let mut pda = blank_anchor_section();
        let pid = Pubkey::new_unique();
        let ixs = vec![make_instruction(pid, &[1, 2], 2)];
        let fp = compute_tx_fingerprint_from_instructions(&ixs);

        // First invocation: fingerprint differs from zeroed PDA
        assert!(is_first_sandbox_invocation(&pda, &fp));

        // Write anchor
        let pk = Pubkey::new_unique();
        write_anchor_snapshot(&mut pda, &fp, &[(pk, 500)]);

        // Second invocation in same tx: fingerprint matches
        assert!(!is_first_sandbox_invocation(&pda, &fp));

        // Read back anchor
        let fields = read_anchor_snapshot(&pda).unwrap();
        assert_eq!(fields, vec![(pk, 500)]);
    }

    #[test]
    fn cross_tx_resets_anchor() {
        let mut pda = blank_anchor_section();
        let pid = Pubkey::new_unique();

        // tx 1
        let ixs1 = vec![make_instruction(pid, &[1], 1)];
        let fp1 = compute_tx_fingerprint_from_instructions(&ixs1);
        assert!(is_first_sandbox_invocation(&pda, &fp1));
        write_anchor_snapshot(&mut pda, &fp1, &[(Pubkey::new_unique(), 100)]);
        assert!(!is_first_sandbox_invocation(&pda, &fp1));

        // tx 2 — different instructions
        let ixs2 = vec![make_instruction(pid, &[2], 1)];
        let fp2 = compute_tx_fingerprint_from_instructions(&ixs2);
        assert!(is_first_sandbox_invocation(&pda, &fp2));
    }

    // ── check_tx_cumulative_decrease ────────────────────────────────────

    #[test]
    fn decrease_zero_pct_passes() {
        // No change
        assert!(check_tx_cumulative_decrease(1000, 1000, 10).is_ok());
    }

    #[test]
    fn decrease_within_limit_passes() {
        // 10% decrease, limit 15%
        assert!(check_tx_cumulative_decrease(1000, 900, 15).is_ok());
    }

    #[test]
    fn decrease_exactly_at_limit_passes() {
        // 15% decrease, limit 15%
        assert!(check_tx_cumulative_decrease(1000, 850, 15).is_ok());
    }

    #[test]
    fn decrease_over_limit_fails() {
        // 16% decrease, limit 15%
        assert_eq!(
            check_tx_cumulative_decrease(1000, 840, 15),
            Err(SandboxError::TxCumulativeDecreaseExceeded.into())
        );
    }

    #[test]
    fn increase_always_passes() {
        // current > anchor
        assert!(check_tx_cumulative_decrease(1000, 2000, 0).is_ok());
    }

    #[test]
    fn anchor_zero_current_zero_passes() {
        assert!(check_tx_cumulative_decrease(0, 0, 10).is_ok());
    }

    #[test]
    fn anchor_zero_current_positive_passes() {
        // Increase from zero
        assert!(check_tx_cumulative_decrease(0, 500, 10).is_ok());
    }

    #[test]
    fn decrease_100_pct_with_limit_100_passes() {
        assert!(check_tx_cumulative_decrease(1000, 0, 100).is_ok());
    }

    #[test]
    fn decrease_100_pct_with_limit_99_fails() {
        assert_eq!(
            check_tx_cumulative_decrease(1000, 0, 99),
            Err(SandboxError::TxCumulativeDecreaseExceeded.into())
        );
    }

    #[test]
    fn decrease_max_pct_zero_any_decrease_fails() {
        // max_decrease_pct = 0 means NO decrease allowed
        assert_eq!(
            check_tx_cumulative_decrease(1000, 999, 0),
            Err(SandboxError::TxCumulativeDecreaseExceeded.into())
        );
    }

    #[test]
    fn decrease_boundary_rounding() {
        // 1 / 100 * 100 = 1 → max_pct = 1 should pass
        assert!(check_tx_cumulative_decrease(100, 99, 1).is_ok());
        // 2 / 100 * 100 = 2 → max_pct = 1 should fail
        assert!(check_tx_cumulative_decrease(100, 98, 1).is_err());
    }

    #[test]
    fn decrease_large_values_no_overflow() {
        // anchor near u64::MAX / 100 to avoid mul overflow
        let anchor = u64::MAX / 200;
        let current = anchor - anchor / 10; // 10% decrease
        assert!(check_tx_cumulative_decrease(anchor, current, 15).is_ok());
    }

    #[test]
    fn decrease_very_large_anchor_overflow_handled() {
        // anchor * 100 would overflow u64 — checked_mul should catch it
        let anchor = u64::MAX;
        let current = anchor - 1;
        // decrease = 1, numerator = 1 * 100 = 100, doesn't overflow
        assert!(check_tx_cumulative_decrease(anchor, current, 1).is_ok());
    }

    #[test]
    fn decrease_overflow_in_mul() {
        // anchor = u64::MAX, current = 0, max_pct = 100
        // decrease = u64::MAX, decrease * 100 fits in u128
        // lhs = u64::MAX * 100, rhs = 100 * u64::MAX → equal → passes
        let result = check_tx_cumulative_decrease(u64::MAX, 0, 100);
        assert!(result.is_ok(), "100% decrease with max_pct=100 should pass with u128 arithmetic");
    }

    // ── read_stored_fingerprint ─────────────────────────────────────────

    #[test]
    fn read_stored_fingerprint_ok() {
        let mut pda = blank_anchor_section();
        let fp = [0xABu8; 32];
        pda[..32].copy_from_slice(&fp);
        assert_eq!(read_stored_fingerprint(&pda), Some(fp));
    }

    #[test]
    fn read_stored_fingerprint_too_short() {
        let pda = vec![0u8; 16];
        assert_eq!(read_stored_fingerprint(&pda), None);
    }

    // ── Cumulative decrease precision tests ─────────────────────────────

    #[test]
    fn decrease_fractional_pct_caught() {
        // 15.5% decrease with max_pct=15 should be caught.
        // anchor=1000, current=845 → decrease=155, 15.5%
        // Old code: 155 * 100 / 1000 = 15 (truncated) → wrongly passes
        // New code: 155 * 100 = 15500 > 15 * 1000 = 15000 → correctly fails
        assert_eq!(
            check_tx_cumulative_decrease(1000, 845, 15),
            Err(SandboxError::TxCumulativeDecreaseExceeded.into()),
            "15.5% decrease should be caught with max_pct=15"
        );
    }

    #[test]
    fn decrease_fractional_just_under_limit_passes() {
        // 14.9% decrease with max_pct=15 should pass.
        // anchor=1000, current=851 → decrease=149, 14.9%
        // 149 * 100 = 14900 <= 15 * 1000 = 15000 → passes
        assert!(
            check_tx_cumulative_decrease(1000, 851, 15).is_ok(),
            "14.9% decrease should pass with max_pct=15"
        );
    }

    #[test]
    fn decrease_exact_limit_passes_no_truncation() {
        // Exactly 15.0% decrease with max_pct=15 should pass.
        // anchor=1000, current=850 → decrease=150, 15.0%
        // 150 * 100 = 15000 <= 15 * 1000 = 15000 → passes (equal)
        assert!(
            check_tx_cumulative_decrease(1000, 850, 15).is_ok(),
            "exactly 15% should pass with max_pct=15"
        );
    }

    #[test]
    fn decrease_overflow_large_values_u128() {
        // anchor = u64::MAX, current = 0 → decrease = u64::MAX
        // decrease * 100 would overflow u64 but fits in u128
        // With max_pct=100: lhs = u64::MAX * 100, rhs = 100 * u64::MAX → equal, passes
        assert!(
            check_tx_cumulative_decrease(u64::MAX, 0, 100).is_ok(),
            "100% decrease with max_pct=100 should pass even for large values"
        );
    }

    // ── write_anchor_fields_only tests ──────────────────────────────────

    #[test]
    fn write_fields_only_preserves_fingerprint() {
        let mut pda = vec![0u8; ANCHOR_SECTION_SIZE];
        let fp = [0xABu8; 32];
        let fields = vec![
            (Pubkey::new_unique(), 1000u64),
            (Pubkey::new_unique(), 2000u64),
        ];
        // Write full snapshot (fingerprint + fields)
        write_anchor_snapshot(&mut pda, &fp, &fields);
        assert_eq!(&pda[..32], &fp);
        assert_eq!(pda[FIELD_COUNT_OFFSET], 2);

        // Now update fields only — fingerprint must survive
        let new_fields = vec![
            (Pubkey::new_unique(), 9999u64),
        ];
        write_anchor_fields_only(&mut pda, &new_fields);

        // Fingerprint preserved
        assert_eq!(&pda[..32], &fp, "fingerprint must not be overwritten");
        // Field count updated
        assert_eq!(pda[FIELD_COUNT_OFFSET], 1);
        // Read back
        let read = read_anchor_snapshot(&pda).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].1, 9999);
    }

    #[test]
    fn write_fields_only_zero_fields() {
        let mut pda = vec![0u8; ANCHOR_SECTION_SIZE];
        let fp = [0xCDu8; 32];
        let fields = vec![(Pubkey::new_unique(), 500u64)];
        write_anchor_snapshot(&mut pda, &fp, &fields);

        // Clear fields
        write_anchor_fields_only(&mut pda, &[]);
        assert_eq!(&pda[..32], &fp, "fingerprint preserved");
        assert_eq!(pda[FIELD_COUNT_OFFSET], 0);
        let read = read_anchor_snapshot(&pda).unwrap();
        assert!(read.is_empty());
    }

    #[test]
    fn write_fields_only_max_fields() {
        let mut pda = vec![0u8; ANCHOR_SECTION_SIZE];
        let fp = [0xEFu8; 32];
        pda[..32].copy_from_slice(&fp);

        let fields: Vec<(Pubkey, u64)> = (0..MAX_ANCHOR_FIELDS)
            .map(|i| (Pubkey::new_unique(), (i as u64) * 1000))
            .collect();
        write_anchor_fields_only(&mut pda, &fields);

        assert_eq!(&pda[..32], &fp, "fingerprint preserved");
        assert_eq!(pda[FIELD_COUNT_OFFSET], MAX_ANCHOR_FIELDS as u8);
        let read = read_anchor_snapshot(&pda).unwrap();
        assert_eq!(read.len(), MAX_ANCHOR_FIELDS);
        for (i, (_, val)) in read.iter().enumerate() {
            assert_eq!(*val, (i as u64) * 1000);
        }
    }

    #[test]
    #[should_panic(expected = "too many anchor fields")]
    fn write_fields_only_panics_on_overflow() {
        let mut pda = vec![0u8; ANCHOR_SECTION_SIZE + FIELD_SIZE];
        let fields: Vec<(Pubkey, u64)> = (0..MAX_ANCHOR_FIELDS + 1)
            .map(|i| (Pubkey::new_unique(), i as u64))
            .collect();
        write_anchor_fields_only(&mut pda, &fields);
    }

    #[test]
    #[should_panic(expected = "PDA anchor section too small")]
    fn write_fields_only_panics_on_undersized_buffer() {
        let mut pda = vec![0u8; FIELDS_START - 1]; // too small
        write_anchor_fields_only(&mut pda, &[(Pubkey::new_unique(), 100)]);
    }
}

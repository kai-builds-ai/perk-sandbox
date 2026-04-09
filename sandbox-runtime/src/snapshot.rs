//! Account Snapshot Mechanism (Spec §4)
//!
//! Copy-and-drop pattern: borrow account data, copy specific field bytes,
//! DROP borrow immediately. Business logic needs mutable borrows after snapshot.
//!
//! Two strategies:
//! - **Strategy A (fixed-offset):** Direct byte read at compile-time known offset.
//!   ~200-400 CU per field. For fields where ALL preceding fields are fixed-size.
//! - **Strategy B (Borsh-deser prefix):** Runtime deserialization for fields after
//!   variable-length types. Parse prefix up to target field, not entire struct.
//!   ~1,000-3,000 CU per field.

use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

use crate::error::SandboxError;

// ---------------------------------------------------------------------------
// Strategy A: Fixed-offset snapshot
// ---------------------------------------------------------------------------

/// Read a fixed-offset field from an account's data into a caller-provided buffer.
///
/// # Copy-and-drop guarantee
/// The `RefCell` borrow on account data is acquired, bytes are copied into `buf`,
/// and the borrow is **dropped** before this function returns.
///
/// # Errors
/// - `SandboxError::SnapshotFailed` if `offset + buf.len()` exceeds account data length.
/// - `SandboxError::SnapshotFailed` if the borrow fails (account already mutably borrowed).
#[inline]
pub fn snapshot_field_fixed(
    account: &AccountInfo,
    offset: usize,
    buf: &mut [u8],
) -> Result<(), ProgramError> {
    let size = buf.len();
    // Checked arithmetic: offset + size could overflow on 32-bit.
    let end = offset
        .checked_add(size)
        .ok_or(ProgramError::from(SandboxError::SnapshotFailed))?;

    // Acquire borrow, copy, drop.
    {
        let data = account
            .try_borrow_data()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;

        if end > data.len() {
            return Err(SandboxError::SnapshotFailed.into());
        }

        buf.copy_from_slice(&data[offset..end]);
        // `data` (Ref) is dropped here at end of block.
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Strategy B: Borsh-deser prefix snapshot
// ---------------------------------------------------------------------------

/// A prefix parser that walks through variable-length Borsh-encoded fields
/// and returns the byte offset where the target field begins.
///
/// The parser receives the full account data slice and a starting cursor position
/// (typically 8 to skip the Anchor discriminator). It must advance the cursor past
/// all variable-length prefix fields and return the offset of the target field.
///
/// # Errors
/// Return `SandboxError::SnapshotFailed` on any parse failure or out-of-bounds.
pub type PrefixParser = fn(data: &[u8], cursor: usize) -> Result<usize, ProgramError>;

/// Read a Borsh-variable-offset field from an account's data.
///
/// 1. Borrows account data (immutable).
/// 2. Calls `prefix_parser` to compute the dynamic offset of the target field.
/// 3. Adds `field_offset_after_prefix` to handle any fixed-size fields between
///    the end of the variable-length prefix and the target field.
/// 4. Copies `buf.len()` bytes into the caller-provided buffer.
/// 5. **Drops** the borrow before returning.
///
/// # Errors
/// - `SandboxError::SnapshotFailed` on borrow failure, parse failure, or out-of-bounds.
#[inline]
pub fn snapshot_field_borsh(
    account: &AccountInfo,
    prefix_parser: PrefixParser,
    field_offset_after_prefix: usize,
    buf: &mut [u8],
) -> Result<(), ProgramError> {
    let size = buf.len();

    {
        let data = account
            .try_borrow_data()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;

        // Run prefix parser to find dynamic offset.
        let prefix_end = prefix_parser(&data, 8)?; // 8 = skip Anchor discriminator

        let offset = prefix_end
            .checked_add(field_offset_after_prefix)
            .ok_or(ProgramError::from(SandboxError::SnapshotFailed))?;

        let end = offset
            .checked_add(size)
            .ok_or(ProgramError::from(SandboxError::SnapshotFailed))?;

        if end > data.len() {
            return Err(SandboxError::SnapshotFailed.into());
        }

        buf.copy_from_slice(&data[offset..end]);
        // `data` (Ref) dropped here.
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Borsh prefix parsing helpers
// ---------------------------------------------------------------------------

/// Skip a Borsh `Option<T>` where T is a fixed-size type of `inner_size` bytes.
///
/// Reads the tag byte at `cursor`:
/// - `0` → None, advance 1 byte
/// - `1` → Some, advance 1 + inner_size bytes
///
/// Returns the new cursor position.
#[inline]
pub fn skip_borsh_option_fixed(
    data: &[u8],
    cursor: usize,
    inner_size: usize,
) -> Result<usize, ProgramError> {
    if cursor >= data.len() {
        return Err(SandboxError::SnapshotFailed.into());
    }

    let tag = data[cursor];
    let after_tag = cursor
        .checked_add(1)
        .ok_or(ProgramError::from(SandboxError::SnapshotFailed))?;

    match tag {
        0 => Ok(after_tag),
        1 => {
            let end = after_tag
                .checked_add(inner_size)
                .ok_or(ProgramError::from(SandboxError::SnapshotFailed))?;
            if end > data.len() {
                return Err(SandboxError::SnapshotFailed.into());
            }
            Ok(end)
        }
        _ => Err(SandboxError::SnapshotFailed.into()),
    }
}

/// Skip a Borsh `Vec<T>` where T is a fixed-size type of `element_size` bytes.
///
/// Reads the 4-byte little-endian length at `cursor`, then skips `len * element_size`.
#[inline]
pub fn skip_borsh_vec_fixed(
    data: &[u8],
    cursor: usize,
    element_size: usize,
) -> Result<usize, ProgramError> {
    let len_end = cursor
        .checked_add(4)
        .ok_or(ProgramError::from(SandboxError::SnapshotFailed))?;
    if len_end > data.len() {
        return Err(SandboxError::SnapshotFailed.into());
    }

    let len = u32::from_le_bytes(
        data[cursor..len_end]
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?,
    ) as usize;

    let total_bytes = len
        .checked_mul(element_size)
        .ok_or(ProgramError::from(SandboxError::SnapshotFailed))?;

    let end = len_end
        .checked_add(total_bytes)
        .ok_or(ProgramError::from(SandboxError::SnapshotFailed))?;

    if end > data.len() {
        return Err(SandboxError::SnapshotFailed.into());
    }

    Ok(end)
}

/// Skip a Borsh `String`.
///
/// Strings are encoded as `Vec<u8>` in Borsh: 4-byte LE length + that many bytes.
#[inline]
pub fn skip_borsh_string(data: &[u8], cursor: usize) -> Result<usize, ProgramError> {
    skip_borsh_vec_fixed(data, cursor, 1)
}

// ---------------------------------------------------------------------------
// SnapshotSet — holds before-snapshots for invariant comparison
// ---------------------------------------------------------------------------

/// Key for a snapshot entry: (account pubkey, field name).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SnapshotKey {
    pub account: Pubkey,
    pub field: &'static str,
}

/// A set of before-snapshots captured prior to business logic execution.
///
/// Heap-allocated: uses `Vec` internally so it works on-chain without std HashMap.
/// For typical invariant sets (≤32 fields), linear scan is faster than hashing
/// and avoids pulling in the HashMap allocator on BPF.
#[derive(Debug, Default)]
pub struct SnapshotSet {
    entries: Vec<(SnapshotKey, Vec<u8>)>,
}

impl SnapshotSet {
    /// Create a new empty snapshot set.
    #[inline]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create with pre-allocated capacity (use for known field counts).
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    /// Insert a snapshot. Overwrites if the key already exists.
    pub fn insert(&mut self, account: Pubkey, field: &'static str, data: Vec<u8>) {
        let key = SnapshotKey { account, field };
        for entry in self.entries.iter_mut() {
            if entry.0 == key {
                entry.1 = data;
                return;
            }
        }
        self.entries.push((key, data));
    }

    /// Retrieve a snapshot by account and field name.
    pub fn get(&self, account: &Pubkey, field: &str) -> Option<&[u8]> {
        for (key, data) in &self.entries {
            if key.account == *account && key.field == field {
                return Some(data.as_slice());
            }
        }
        None
    }

    /// Number of entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Convenience: typed snapshot helpers (stack-allocated)
// ---------------------------------------------------------------------------

/// Snapshot a `u64` field at a fixed offset.
#[inline]
pub fn snapshot_u64(account: &AccountInfo, offset: usize) -> Result<u64, ProgramError> {
    let mut buf = [0u8; 8];
    snapshot_field_fixed(account, offset, &mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Snapshot an `i64` field at a fixed offset.
#[inline]
pub fn snapshot_i64(account: &AccountInfo, offset: usize) -> Result<i64, ProgramError> {
    let mut buf = [0u8; 8];
    snapshot_field_fixed(account, offset, &mut buf)?;
    Ok(i64::from_le_bytes(buf))
}

/// Snapshot a `u32` field at a fixed offset.
#[inline]
pub fn snapshot_u32(account: &AccountInfo, offset: usize) -> Result<u32, ProgramError> {
    let mut buf = [0u8; 4];
    snapshot_field_fixed(account, offset, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Snapshot a `u16` field at a fixed offset.
#[inline]
pub fn snapshot_u16(account: &AccountInfo, offset: usize) -> Result<u16, ProgramError> {
    let mut buf = [0u8; 2];
    snapshot_field_fixed(account, offset, &mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

/// Snapshot a `u8` field at a fixed offset.
#[inline]
pub fn snapshot_u8(account: &AccountInfo, offset: usize) -> Result<u8, ProgramError> {
    let mut buf = [0u8; 1];
    snapshot_field_fixed(account, offset, &mut buf)?;
    Ok(buf[0])
}

/// Snapshot a `bool` field at a fixed offset (Borsh: 0 = false, 1 = true).
#[inline]
pub fn snapshot_bool(account: &AccountInfo, offset: usize) -> Result<bool, ProgramError> {
    let mut buf = [0u8; 1];
    snapshot_field_fixed(account, offset, &mut buf)?;
    match buf[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SandboxError::SnapshotFailed.into()),
    }
}

/// Snapshot a `Pubkey` field at a fixed offset.
#[inline]
pub fn snapshot_pubkey(account: &AccountInfo, offset: usize) -> Result<Pubkey, ProgramError> {
    let mut buf = [0u8; 32];
    snapshot_field_fixed(account, offset, &mut buf)?;
    Ok(Pubkey::new_from_array(buf))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::clock::Epoch;

    // -----------------------------------------------------------------------
    // Strategy A tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_snapshot_u64() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let value: u64 = 1_000_000_000;
        let mut data = vec![0u8; 16];
        data[8..16].copy_from_slice(&value.to_le_bytes());

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        let result = snapshot_u64(&account, 8).unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn test_snapshot_i64() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let value: i64 = -42_000;
        let mut data = vec![0u8; 16];
        data[8..16].copy_from_slice(&value.to_le_bytes());

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        let result = snapshot_i64(&account, 8).unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn test_snapshot_pubkey() {
        let expected = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 40];
        data[8..40].copy_from_slice(expected.as_ref());

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        let result = snapshot_pubkey(&account, 8).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_snapshot_bool_true() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 9];
        data[8] = 1;

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        assert!(snapshot_bool(&account, 8).unwrap());
    }

    #[test]
    fn test_snapshot_bool_false() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 9];

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        assert!(!snapshot_bool(&account, 8).unwrap());
    }

    #[test]
    fn test_snapshot_bool_invalid_value() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 9];
        data[8] = 2;

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        assert!(snapshot_bool(&account, 8).is_err());
    }

    #[test]
    fn test_bounds_check_failure() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 10];

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        // Try to read u64 at offset 8, needs 8..16 but only 10 bytes.
        assert!(snapshot_u64(&account, 8).is_err());
    }

    #[test]
    fn test_bounds_check_zero_length_account() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![];

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        assert!(snapshot_field_fixed(&account, 0, &mut [0u8; 1]).is_err());
    }

    #[test]
    fn test_overflow_offset_plus_size() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 16];

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        // usize::MAX offset triggers checked_add overflow
        assert!(snapshot_field_fixed(&account, usize::MAX, &mut [0u8; 8]).is_err());
    }

    // -----------------------------------------------------------------------
    // Strategy B tests (Borsh-deser prefix)
    // -----------------------------------------------------------------------

    #[test]
    fn test_borsh_deser_after_option_pubkey_none() {
        // Layout: [8-byte disc][Option<Pubkey> = None (0x00)][u64 target]
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let value: u64 = 999_999;
        let mut data = vec![0u8; 8 + 1 + 8];
        data[8] = 0; // None
        data[9..17].copy_from_slice(&value.to_le_bytes());

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        fn parse_option_pubkey(data: &[u8], cursor: usize) -> Result<usize, ProgramError> {
            skip_borsh_option_fixed(data, cursor, 32)
        }

        let mut buf = [0u8; 8];
        snapshot_field_borsh(&account, parse_option_pubkey, 0, &mut buf).unwrap();
        assert_eq!(u64::from_le_bytes(buf), value);
    }

    #[test]
    fn test_borsh_deser_after_option_pubkey_some() {
        // Layout: [8-byte disc][Option<Pubkey> = Some (1+32)][u64 target]
        let fake_pk = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let value: u64 = 123_456_789;
        let mut data = vec![0u8; 8 + 1 + 32 + 8];
        data[8] = 1; // Some
        data[9..41].copy_from_slice(fake_pk.as_ref());
        data[41..49].copy_from_slice(&value.to_le_bytes());

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        fn parse_option_pubkey(data: &[u8], cursor: usize) -> Result<usize, ProgramError> {
            skip_borsh_option_fixed(data, cursor, 32)
        }

        let mut buf = [0u8; 8];
        snapshot_field_borsh(&account, parse_option_pubkey, 0, &mut buf).unwrap();
        assert_eq!(u64::from_le_bytes(buf), value);
    }

    #[test]
    fn test_borsh_deser_bounds_failure() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 10]; // too short
        data[8] = 1; // Some — needs 33 more bytes

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        fn parse_option_pubkey(data: &[u8], cursor: usize) -> Result<usize, ProgramError> {
            skip_borsh_option_fixed(data, cursor, 32)
        }

        let mut buf = [0u8; 8];
        assert!(snapshot_field_borsh(&account, parse_option_pubkey, 0, &mut buf).is_err());
    }

    // -----------------------------------------------------------------------
    // Borrow-drop test (critical for the copy-and-drop pattern)
    // -----------------------------------------------------------------------

    #[test]
    fn test_borrow_dropped_after_snapshot() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 0u64;
        let mut data = vec![0u8; 16];
        data[8..16].copy_from_slice(&42u64.to_le_bytes());

        let account = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data, &owner, false, Epoch::default(),
        );

        // Snapshot acquires and drops immutable borrow
        let val = snapshot_u64(&account, 8).unwrap();
        assert_eq!(val, 42);

        // MUTABLE borrow must succeed — proves snapshot dropped its borrow.
        {
            let mut data = account.try_borrow_mut_data().expect(
                "Mutable borrow should succeed after snapshot dropped its immutable borrow",
            );
            data[8..16].copy_from_slice(&99u64.to_le_bytes());
        }

        // Verify mutation
        let val2 = snapshot_u64(&account, 8).unwrap();
        assert_eq!(val2, 99);
    }

    // -----------------------------------------------------------------------
    // SnapshotSet tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_snapshot_set_insert_get() {
        let mut set = SnapshotSet::new();
        let pk = Pubkey::new_unique();

        set.insert(pk, "vault_balance", 42u64.to_le_bytes().to_vec());
        set.insert(pk, "authority", Pubkey::new_unique().to_bytes().to_vec());

        let balance = set.get(&pk, "vault_balance").unwrap();
        assert_eq!(u64::from_le_bytes(balance.try_into().unwrap()), 42);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_snapshot_set_overwrite() {
        let mut set = SnapshotSet::new();
        let pk = Pubkey::new_unique();

        set.insert(pk, "balance", 100u64.to_le_bytes().to_vec());
        set.insert(pk, "balance", 200u64.to_le_bytes().to_vec());

        assert_eq!(set.len(), 1);
        let val = set.get(&pk, "balance").unwrap();
        assert_eq!(u64::from_le_bytes(val.try_into().unwrap()), 200);
    }

    #[test]
    fn test_snapshot_set_missing() {
        let set = SnapshotSet::new();
        assert!(set.get(&Pubkey::new_unique(), "nope").is_none());
        assert!(set.is_empty());
    }

    // -----------------------------------------------------------------------
    // Borsh skip helpers unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_skip_borsh_option_none() {
        let data = [0u8];
        assert_eq!(skip_borsh_option_fixed(&data, 0, 32).unwrap(), 1);
    }

    #[test]
    fn test_skip_borsh_option_some() {
        let mut data = vec![1u8];
        data.extend_from_slice(&[0u8; 32]);
        assert_eq!(skip_borsh_option_fixed(&data, 0, 32).unwrap(), 33);
    }

    #[test]
    fn test_skip_borsh_vec() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 24]); // 3 * 8
        assert_eq!(skip_borsh_vec_fixed(&data, 0, 8).unwrap(), 28);
    }

    #[test]
    fn test_skip_borsh_string() {
        let s = "hello";
        let mut data = Vec::new();
        data.extend_from_slice(&(s.len() as u32).to_le_bytes());
        data.extend_from_slice(s.as_bytes());
        assert_eq!(skip_borsh_string(&data, 0).unwrap(), 9);
    }
}

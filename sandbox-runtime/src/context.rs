//! Invariant context for custom invariant functions (Section 3.6).
//!
//! Provides `InvariantContext` and `AccountSnapshot` for developer-written
//! custom invariant checks.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

use crate::error::SandboxError;

/// Snapshot of an account's state at a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSnapshot {
    /// Account lamports at snapshot time.
    pub lamports: u64,
    /// Raw account data at snapshot time (copy).
    pub data: Vec<u8>,
    /// Whether the account existed (had lamports > 0 or data.len() > 0).
    pub exists: bool,
}

impl AccountSnapshot {
    /// Create a snapshot from an AccountInfo.
    pub fn from_account_info(account: &AccountInfo) -> Result<Self, ProgramError> {
        let data = account
            .try_borrow_data()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;

        Ok(Self {
            lamports: account.lamports(),
            data: data.to_vec(),
            exists: account.lamports() > 0 || !data.is_empty(),
        })
    }

    /// Create an empty snapshot (account does not exist).
    pub fn empty() -> Self {
        Self {
            lamports: 0,
            data: Vec::new(),
            exists: false,
        }
    }

    /// Read a fixed-size field at the given byte offset.
    ///
    /// Bounds-checked: returns `Err(SnapshotFailed)` if `offset + size_of::<T>()` exceeds data length.
    ///
    /// `T` must implement `FromLeBytes` (provided for standard numeric types and Pubkey).
    pub fn field<T: FromLeBytes>(&self, offset: usize) -> Result<T, ProgramError> {
        let size = core::mem::size_of::<T>();
        let end = offset
            .checked_add(size)
            .ok_or(SandboxError::SnapshotFailed)?;
        if end > self.data.len() {
            return Err(SandboxError::SnapshotFailed.into());
        }
        T::from_le_bytes(&self.data[offset..end])
    }
}

/// Trait for types that can be read from little-endian bytes.
pub trait FromLeBytes: Sized {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError>;
}

impl FromLeBytes for u8 {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() < 1 {
            return Err(SandboxError::SnapshotFailed.into());
        }
        Ok(bytes[0])
    }
}

impl FromLeBytes for u16 {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        let arr: [u8; 2] = bytes
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;
        Ok(u16::from_le_bytes(arr))
    }
}

impl FromLeBytes for u32 {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        let arr: [u8; 4] = bytes
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;
        Ok(u32::from_le_bytes(arr))
    }
}

impl FromLeBytes for u64 {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;
        Ok(u64::from_le_bytes(arr))
    }
}

impl FromLeBytes for i8 {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() < 1 {
            return Err(SandboxError::SnapshotFailed.into());
        }
        Ok(bytes[0] as i8)
    }
}

impl FromLeBytes for i16 {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        let arr: [u8; 2] = bytes
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;
        Ok(i16::from_le_bytes(arr))
    }
}

impl FromLeBytes for i32 {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        let arr: [u8; 4] = bytes
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;
        Ok(i32::from_le_bytes(arr))
    }
}

impl FromLeBytes for i64 {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;
        Ok(i64::from_le_bytes(arr))
    }
}

impl FromLeBytes for bool {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.is_empty() {
            return Err(SandboxError::SnapshotFailed.into());
        }
        Ok(bytes[0] != 0)
    }
}

impl FromLeBytes for Pubkey {
    fn from_le_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() < 32 {
            return Err(SandboxError::SnapshotFailed.into());
        }
        let arr: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;
        Ok(Pubkey::new_from_array(arr))
    }
}

/// Context passed to custom invariant check functions.
///
/// All account snapshots are keyed by Pubkey. Uses `BTreeMap` for deterministic
/// ordering (important for on-chain reproducibility, and avoids `HashMap`'s
/// `std` dependency in no_std environments).
pub struct InvariantContext<'a, 'info> {
    /// Account states BEFORE business logic executed.
    pub before: BTreeMap<Pubkey, AccountSnapshot>,
    /// Account states AFTER business logic executed.
    pub after: BTreeMap<Pubkey, AccountSnapshot>,
    /// Account states at the START of the transaction (anchor snapshots).
    pub tx_start: BTreeMap<Pubkey, AccountSnapshot>,
    /// The instruction discriminator byte.
    pub instruction_discriminator: u8,
    /// The transaction signer.
    pub signer: Pubkey,
    /// Current clock slot.
    pub clock_slot: u64,
    /// Current clock timestamp (Unix seconds).
    pub clock_timestamp: i64,
    /// Reference to remaining accounts from the instruction.
    pub remaining_accounts: &'a [AccountInfo<'info>],
}

impl<'a, 'info> InvariantContext<'a, 'info> {
    /// Create a new empty context.
    pub fn new(
        instruction_discriminator: u8,
        signer: Pubkey,
        clock_slot: u64,
        clock_timestamp: i64,
        remaining_accounts: &'a [AccountInfo<'info>],
    ) -> Self {
        Self {
            before: BTreeMap::new(),
            after: BTreeMap::new(),
            tx_start: BTreeMap::new(),
            instruction_discriminator,
            signer,
            clock_slot,
            clock_timestamp,
            remaining_accounts,
        }
    }

    /// Insert a before-snapshot for the given account.
    pub fn insert_before(
        &mut self,
        key: Pubkey,
        snapshot: AccountSnapshot,
    ) {
        self.before.insert(key, snapshot);
    }

    /// Insert an after-snapshot for the given account.
    pub fn insert_after(
        &mut self,
        key: Pubkey,
        snapshot: AccountSnapshot,
    ) {
        self.after.insert(key, snapshot);
    }

    /// Insert a transaction-start snapshot for the given account.
    pub fn insert_tx_start(
        &mut self,
        key: Pubkey,
        snapshot: AccountSnapshot,
    ) {
        self.tx_start.insert(key, snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::clock::Epoch;

    #[test]
    fn test_account_snapshot_field_u64() {
        let mut data = vec![0u8; 80];
        // Write a u64 at offset 64
        let value: u64 = 123_456_789;
        data[64..72].copy_from_slice(&value.to_le_bytes());

        let snap = AccountSnapshot {
            lamports: 1000,
            data,
            exists: true,
        };

        let read: u64 = snap.field(64).unwrap();
        assert_eq!(read, 123_456_789);
    }

    #[test]
    fn test_account_snapshot_field_pubkey() {
        let pk = Pubkey::new_unique();
        let mut data = vec![0u8; 64];
        data[32..64].copy_from_slice(pk.as_ref());

        let snap = AccountSnapshot {
            lamports: 1000,
            data,
            exists: true,
        };

        let read: Pubkey = snap.field(32).unwrap();
        assert_eq!(read, pk);
    }

    #[test]
    fn test_account_snapshot_field_u8() {
        let data = vec![42u8, 0, 0, 0];
        let snap = AccountSnapshot {
            lamports: 0,
            data,
            exists: true,
        };

        let read: u8 = snap.field(0).unwrap();
        assert_eq!(read, 42);
    }

    #[test]
    fn test_account_snapshot_field_bool() {
        let data = vec![1u8, 0];
        let snap = AccountSnapshot {
            lamports: 0,
            data,
            exists: true,
        };

        let t: bool = snap.field(0).unwrap();
        assert!(t);
        let f: bool = snap.field(1).unwrap();
        assert!(!f);
    }

    #[test]
    fn test_account_snapshot_field_out_of_bounds() {
        let data = vec![0u8; 4];
        let snap = AccountSnapshot {
            lamports: 0,
            data,
            exists: true,
        };

        let result: Result<u64, _> = snap.field(0);
        assert!(result.is_err()); // 4 bytes < 8 needed for u64
    }

    #[test]
    fn test_account_snapshot_field_offset_overflow() {
        let data = vec![0u8; 8];
        let snap = AccountSnapshot {
            lamports: 0,
            data,
            exists: true,
        };

        let result: Result<u64, _> = snap.field(usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_account_snapshot_empty() {
        let snap = AccountSnapshot::empty();
        assert!(!snap.exists);
        assert_eq!(snap.lamports, 0);
        assert!(snap.data.is_empty());
    }

    #[test]
    fn test_from_account_info() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 42_000u64;
        let mut data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

        let info = AccountInfo::new(
            &key,
            false,
            false,
            &mut lamports,
            &mut data,
            &owner,
            false,
            Epoch::default(),
        );

        let snap = AccountSnapshot::from_account_info(&info).unwrap();
        assert!(snap.exists);
        assert_eq!(snap.lamports, 42_000);
        assert_eq!(snap.data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_invariant_context_insert_and_read() {
        let accounts: Vec<AccountInfo> = vec![];
        let signer = Pubkey::new_unique();
        let mut ctx = InvariantContext::new(1, signer, 100, 1_700_000_000, &accounts);

        let key = Pubkey::new_unique();
        let mut data = vec![0u8; 16];
        let val: u64 = 9999;
        data[8..16].copy_from_slice(&val.to_le_bytes());

        let snap = AccountSnapshot {
            lamports: 500,
            data,
            exists: true,
        };

        ctx.insert_before(key, snap.clone());
        ctx.insert_after(key, snap.clone());

        let before = ctx.before.get(&key).unwrap();
        let read: u64 = before.field(8).unwrap();
        assert_eq!(read, 9999);

        let after = ctx.after.get(&key).unwrap();
        let read: u64 = after.field(8).unwrap();
        assert_eq!(read, 9999);
    }

    #[test]
    fn test_invariant_context_fields() {
        let accounts: Vec<AccountInfo> = vec![];
        let signer = Pubkey::new_unique();
        let ctx = InvariantContext::new(42, signer, 12345, -500, &accounts);

        assert_eq!(ctx.instruction_discriminator, 42);
        assert_eq!(ctx.signer, signer);
        assert_eq!(ctx.clock_slot, 12345);
        assert_eq!(ctx.clock_timestamp, -500);
        assert!(ctx.remaining_accounts.is_empty());
    }

    #[test]
    fn test_field_i64() {
        let mut data = vec![0u8; 16];
        let val: i64 = -42;
        data[8..16].copy_from_slice(&val.to_le_bytes());

        let snap = AccountSnapshot {
            lamports: 0,
            data,
            exists: true,
        };

        let read: i64 = snap.field(8).unwrap();
        assert_eq!(read, -42);
    }
}

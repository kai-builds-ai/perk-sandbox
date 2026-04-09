//! External account deserialization for PERK Sandbox.
//!
//! Zero-dependency deserialization of SPL Token, SPL Token-2022, and System accounts.
//! All reads are bounds-checked. No full Borsh deserialization — direct byte reads only.

use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

use crate::error::SandboxError;

// ── Program IDs ──

/// SPL Token program ID.
pub const TOKEN_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// SPL Token-2022 program ID.
pub const TOKEN_2022_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

// ── Token Account Layout ──
// mint:   Pubkey @ 0   (32 bytes)
// owner:  Pubkey @ 32  (32 bytes)
// amount: u64    @ 64  (8 bytes)
// ...rest of fields up to 165 bytes base
const TOKEN_ACCOUNT_MIN_SIZE: usize = 165;
const TOKEN_MINT_OFFSET: usize = 0;
const TOKEN_OWNER_OFFSET: usize = 32;
const TOKEN_AMOUNT_OFFSET: usize = 64;

// ── Mint Account Layout ──
// mint_authority option tag: u32 @ 0 (4 bytes) — COption<Pubkey>
// mint_authority pubkey: Pubkey @ 4 (32 bytes) — present if tag == 1
// supply: u64 @ 36 (8 bytes)
// decimals: u8 @ 44 (1 byte)
// ...rest up to 82 bytes
const MINT_ACCOUNT_MIN_SIZE: usize = 82;
const MINT_SUPPLY_OFFSET: usize = 36;
const MINT_DECIMALS_OFFSET: usize = 44;
const MINT_AUTHORITY_TAG_OFFSET: usize = 0;
const MINT_AUTHORITY_PUBKEY_OFFSET: usize = 4;

/// Deserialized SPL Token account (base fields only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenAccount {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
}

/// Deserialized SPL Mint account (base fields only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintAccount {
    /// `None` if the mint authority is disabled (COption tag == 0).
    pub mint_authority: Option<Pubkey>,
    pub supply: u64,
    pub decimals: u8,
}

/// Check if the given pubkey is either SPL Token or Token-2022 program.
pub fn is_token_program(owner: &Pubkey) -> bool {
    *owner == TOKEN_PROGRAM_ID || *owner == TOKEN_2022_PROGRAM_ID
}

/// Deserialize a token account from raw account data.
///
/// Works for both SPL Token and Token-2022 (same base layout; Token-2022 may have
/// extensions after byte 165, which we ignore).
///
/// Returns `Err` if:
/// - Account data is too small (< 165 bytes)
/// - Account is not owned by a token program
pub fn deserialize_token_account(account: &AccountInfo) -> Result<TokenAccount, ProgramError> {
    if !is_token_program(account.owner) {
        return Err(SandboxError::BoundViolation.into());
    }

    let data = account
        .try_borrow_data()
        .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;

    if data.len() < TOKEN_ACCOUNT_MIN_SIZE {
        return Err(SandboxError::PDACorrupted.into());
    }

    let mint = Pubkey::try_from(&data[TOKEN_MINT_OFFSET..TOKEN_MINT_OFFSET + 32])
        .map_err(|_| ProgramError::from(SandboxError::PDACorrupted))?;

    let owner = Pubkey::try_from(&data[TOKEN_OWNER_OFFSET..TOKEN_OWNER_OFFSET + 32])
        .map_err(|_| ProgramError::from(SandboxError::PDACorrupted))?;

    let amount = u64::from_le_bytes(
        data[TOKEN_AMOUNT_OFFSET..TOKEN_AMOUNT_OFFSET + 8]
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::PDACorrupted))?,
    );

    Ok(TokenAccount {
        mint,
        owner,
        amount,
    })
}

/// Deserialize a mint account from raw account data.
///
/// Works for both SPL Token and Token-2022 (same base layout).
pub fn deserialize_mint_account(account: &AccountInfo) -> Result<MintAccount, ProgramError> {
    if !is_token_program(account.owner) {
        return Err(SandboxError::BoundViolation.into());
    }

    let data = account
        .try_borrow_data()
        .map_err(|_| ProgramError::from(SandboxError::SnapshotFailed))?;

    if data.len() < MINT_ACCOUNT_MIN_SIZE {
        return Err(SandboxError::PDACorrupted.into());
    }

    // COption<Pubkey>: 4-byte tag (0 = None, 1 = Some) followed by 32-byte pubkey
    let authority_tag = u32::from_le_bytes(
        data[MINT_AUTHORITY_TAG_OFFSET..MINT_AUTHORITY_TAG_OFFSET + 4]
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::PDACorrupted))?,
    );

    let mint_authority = if authority_tag == 1 {
        Some(
            Pubkey::try_from(
                &data[MINT_AUTHORITY_PUBKEY_OFFSET..MINT_AUTHORITY_PUBKEY_OFFSET + 32],
            )
            .map_err(|_| ProgramError::from(SandboxError::PDACorrupted))?,
        )
    } else {
        None
    };

    let supply = u64::from_le_bytes(
        data[MINT_SUPPLY_OFFSET..MINT_SUPPLY_OFFSET + 8]
            .try_into()
            .map_err(|_| ProgramError::from(SandboxError::PDACorrupted))?,
    );

    let decimals = data[MINT_DECIMALS_OFFSET];

    Ok(MintAccount {
        mint_authority,
        supply,
        decimals,
    })
}

/// Read token balance from either SPL Token or Token-2022 account.
pub fn read_token_balance(account: &AccountInfo) -> Result<u64, ProgramError> {
    let token = deserialize_token_account(account)?;
    Ok(token.amount)
}

/// Read mint supply from either SPL Token or Token-2022 mint account.
pub fn read_mint_supply(account: &AccountInfo) -> Result<u64, ProgramError> {
    let mint = deserialize_mint_account(account)?;
    Ok(mint.supply)
}

/// Read lamports from a system account (or any AccountInfo).
pub fn read_system_lamports(account: &AccountInfo) -> u64 {
    account.lamports()
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::clock::Epoch;

    /// Build a fake SPL Token account with the given fields.
    fn build_token_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
        let mut data = vec![0u8; TOKEN_ACCOUNT_MIN_SIZE];
        data[TOKEN_MINT_OFFSET..TOKEN_MINT_OFFSET + 32].copy_from_slice(mint.as_ref());
        data[TOKEN_OWNER_OFFSET..TOKEN_OWNER_OFFSET + 32].copy_from_slice(owner.as_ref());
        data[TOKEN_AMOUNT_OFFSET..TOKEN_AMOUNT_OFFSET + 8]
            .copy_from_slice(&amount.to_le_bytes());
        data
    }

    /// Build a fake SPL Token-2022 account (same base + some extension bytes).
    fn build_token_2022_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
        let mut data = build_token_data(mint, owner, amount);
        // Token-2022 has extensions after byte 165. Add some dummy extension bytes.
        data.extend_from_slice(&[0u8; 64]);
        data
    }

    /// Build a fake mint account.
    fn build_mint_data(authority: Option<&Pubkey>, supply: u64, decimals: u8) -> Vec<u8> {
        let mut data = vec![0u8; MINT_ACCOUNT_MIN_SIZE];
        match authority {
            Some(pk) => {
                data[MINT_AUTHORITY_TAG_OFFSET..MINT_AUTHORITY_TAG_OFFSET + 4]
                    .copy_from_slice(&1u32.to_le_bytes());
                data[MINT_AUTHORITY_PUBKEY_OFFSET..MINT_AUTHORITY_PUBKEY_OFFSET + 32]
                    .copy_from_slice(pk.as_ref());
            }
            None => {
                data[MINT_AUTHORITY_TAG_OFFSET..MINT_AUTHORITY_TAG_OFFSET + 4]
                    .copy_from_slice(&0u32.to_le_bytes());
            }
        }
        data[MINT_SUPPLY_OFFSET..MINT_SUPPLY_OFFSET + 8]
            .copy_from_slice(&supply.to_le_bytes());
        data[MINT_DECIMALS_OFFSET] = decimals;
        data
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

    #[test]
    fn test_is_token_program() {
        assert!(is_token_program(&TOKEN_PROGRAM_ID));
        assert!(is_token_program(&TOKEN_2022_PROGRAM_ID));
        assert!(!is_token_program(&Pubkey::new_unique()));
    }

    #[test]
    fn test_deserialize_spl_token_account() {
        let mint = Pubkey::new_unique();
        let owner_pk = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let token_program = TOKEN_PROGRAM_ID;
        let mut lamports = 1_000_000u64;
        let mut data = build_token_data(&mint, &owner_pk, 500_000);

        let info = make_account_info(&key, &mut lamports, &mut data, &token_program);
        let token = deserialize_token_account(&info).unwrap();

        assert_eq!(token.mint, mint);
        assert_eq!(token.owner, owner_pk);
        assert_eq!(token.amount, 500_000);
    }

    #[test]
    fn test_deserialize_token_2022_account() {
        let mint = Pubkey::new_unique();
        let owner_pk = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let token_2022 = TOKEN_2022_PROGRAM_ID;
        let mut lamports = 1_000_000u64;
        let mut data = build_token_2022_data(&mint, &owner_pk, 999_999);

        let info = make_account_info(&key, &mut lamports, &mut data, &token_2022);
        let token = deserialize_token_account(&info).unwrap();

        assert_eq!(token.mint, mint);
        assert_eq!(token.owner, owner_pk);
        assert_eq!(token.amount, 999_999);
    }

    #[test]
    fn test_deserialize_mint_with_authority() {
        let authority = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let token_program = TOKEN_PROGRAM_ID;
        let mut lamports = 1_000_000u64;
        let mut data = build_mint_data(Some(&authority), 1_000_000_000, 9);

        let info = make_account_info(&key, &mut lamports, &mut data, &token_program);
        let mint = deserialize_mint_account(&info).unwrap();

        assert_eq!(mint.mint_authority, Some(authority));
        assert_eq!(mint.supply, 1_000_000_000);
        assert_eq!(mint.decimals, 9);
    }

    #[test]
    fn test_deserialize_mint_no_authority() {
        let key = Pubkey::new_unique();
        let token_program = TOKEN_2022_PROGRAM_ID;
        let mut lamports = 1_000_000u64;
        let mut data = build_mint_data(None, 500_000, 6);

        let info = make_account_info(&key, &mut lamports, &mut data, &token_program);
        let mint = deserialize_mint_account(&info).unwrap();

        assert_eq!(mint.mint_authority, None);
        assert_eq!(mint.supply, 500_000);
        assert_eq!(mint.decimals, 6);
    }

    #[test]
    fn test_read_token_balance() {
        let mint = Pubkey::new_unique();
        let owner_pk = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let token_program = TOKEN_PROGRAM_ID;
        let mut lamports = 1_000_000u64;
        let mut data = build_token_data(&mint, &owner_pk, 12345);

        let info = make_account_info(&key, &mut lamports, &mut data, &token_program);
        assert_eq!(read_token_balance(&info).unwrap(), 12345);
    }

    #[test]
    fn test_read_mint_supply() {
        let key = Pubkey::new_unique();
        let token_program = TOKEN_PROGRAM_ID;
        let mut lamports = 1_000_000u64;
        let mut data = build_mint_data(None, 7_777_777, 8);

        let info = make_account_info(&key, &mut lamports, &mut data, &token_program);
        assert_eq!(read_mint_supply(&info).unwrap(), 7_777_777);
    }

    #[test]
    fn test_wrong_owner_rejected() {
        let mint = Pubkey::new_unique();
        let owner_pk = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let wrong_owner = Pubkey::new_unique();
        let mut lamports = 1_000_000u64;
        let mut data = build_token_data(&mint, &owner_pk, 100);

        let info = make_account_info(&key, &mut lamports, &mut data, &wrong_owner);
        assert!(deserialize_token_account(&info).is_err());
    }

    #[test]
    fn test_data_too_small() {
        let key = Pubkey::new_unique();
        let token_program = TOKEN_PROGRAM_ID;
        let mut lamports = 1_000_000u64;
        let mut data = vec![0u8; 50]; // too small

        let info = make_account_info(&key, &mut lamports, &mut data, &token_program);
        assert!(deserialize_token_account(&info).is_err());
    }

    #[test]
    fn test_system_lamports() {
        let key = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mut lamports = 42_000_000u64;
        let mut data = vec![];

        let info = make_account_info(&key, &mut lamports, &mut data, &owner);
        assert_eq!(read_system_lamports(&info), 42_000_000);
    }
}

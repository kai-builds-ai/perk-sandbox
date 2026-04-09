use anchor_lang::prelude::*;
use perk_sandbox_macros::sandbox_program;

declare_id!("11111111111111111111111111111111");

/// Test program — proves the sandbox_program macro generates valid Anchor-compatible code.
/// In real usage, this would be:
///   #[cfg_attr(feature = "sandbox", sandbox_program(config = "sandbox.toml"))]
///   #[cfg_attr(not(feature = "sandbox"), program)]
/// For the spike, we use sandbox_program directly.
#[sandbox_program(config = "sandbox.toml")]
pub mod test_perps {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }

    pub fn open_position(ctx: Context<OpenPosition>, leverage: u8, collateral: u64) -> Result<()> {
        Ok(())
    }

    pub fn close_position(ctx: Context<ClosePosition>) -> Result<()> {
        Ok(())
    }

    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        Ok(())
    }
}

// ── Account structs ──

#[derive(Accounts)]
pub struct Initialize {}

#[derive(Accounts)]
pub struct OpenPosition {}

#[derive(Accounts)]
pub struct ClosePosition {}

#[derive(Accounts)]
pub struct Liquidate {}

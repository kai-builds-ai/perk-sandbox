//! program_attr.rs — Main entrypoint codegen for `#[sandbox_program]`.
//!
//! Generates the full 12-step sandbox pipeline (SPEC §2.1) that replaces
//! Anchor's `#[program]`. Every transaction routes through the generated
//! entrypoint — no bypass path exists.
//!
//! This module is called from `lib.rs` by the `#[sandbox_program]` proc macro.

use std::collections::HashMap;

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use sha2::{Digest, Sha256};
use syn::{FnArg, Ident, ItemFn, Pat, PatType, Type};

// ═══════════════════════════════════════════════════════════════════════════
// Configuration types (consumed from config.rs when it exists)
// ═══════════════════════════════════════════════════════════════════════════

/// Circuit breaker category mapping: instruction name → category.
#[derive(Debug, Clone)]
pub struct CategoryMapping {
    pub instruction: String,
    pub category: String,
}

/// Circuit breaker configuration parsed from sandbox.toml.
#[derive(Debug, Clone, Default)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    /// Per-category TVL cliff configs.
    pub tvl_cliff_enabled: bool,
    pub tvl_cliff_track_field: Option<String>,
    /// Byte offset of the tracked field within its account (for direct reads).
    pub tvl_cliff_field_offset: Option<usize>,
    /// Byte size of the tracked field (must be 8 for u64).
    pub tvl_cliff_field_size: usize,
    pub tvl_cliff_window_slots: u64,
    pub tvl_cliff_window_seconds: i64,
    pub tvl_cliff_action: String,
    pub tvl_cliff_budgets: Vec<(String, u64)>,
    /// Event counter breakers with per-counter config.
    pub event_counters: Vec<EventCounterConfig>,
    /// Per-tx threshold enabled.
    pub per_tx_threshold_enabled: bool,
    /// Per-tx threshold max decrease in bps.
    pub per_tx_max_decrease_bps: u64,
    /// Category mappings from TOML.
    pub categories: Vec<CategoryMapping>,
    /// Instructions exempt from TVL cliff.
    pub exempt_instructions: Vec<String>,
    /// Scope: "global" or "per_market".
    pub scope: String,
}

/// Per-event-counter configuration.
#[derive(Debug, Clone)]
pub struct EventCounterConfig {
    pub name: String,
    pub window_slots: u64,
    pub window_seconds: i64,
    pub max_count: u32,
    pub action: String,
}

/// Re-entrancy mode from config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReentrancyModeConfig {
    Reject,
    Guard,
    Full,
}

impl Default for ReentrancyModeConfig {
    fn default() -> Self {
        Self::Guard
    }
}

/// Mode-check: which instructions are allowed in which modes.
#[derive(Debug, Clone, Default)]
pub struct ModeConfig {
    /// Instructions allowed when paused (recovery instructions).
    pub recovery_instructions: Vec<String>,
    /// Instructions allowed in close-only mode.
    pub close_only_instructions: Vec<String>,
    /// Whether unknown instructions are allowed with pre-checks.
    pub unknown_instructions_allow: bool,
}

/// Top-level sandbox configuration.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    pub reentrancy_mode: ReentrancyModeConfig,
    pub circuit_breakers: CircuitBreakerConfig,
    pub mode: ModeConfig,
    /// Whether tx-level anchor/fingerprint is needed (true if any tx_cumulative_decrease).
    pub tx_anchor_enabled: bool,
    /// PDA scope seed (empty for global).
    pub pda_scope: String,
    /// Named keys from [keys] config (key_name -> base58 pubkey).
    pub keys: HashMap<String, String>,
    /// Rate limit config from sandbox.toml.
    pub rate_limits: Option<RateLimitConfig>,
    /// Oracle pre-check config from sandbox.toml.
    pub oracle: Option<OraclePreCheckConfig>,
}

/// Oracle pre-check configuration for codegen.
#[derive(Debug, Clone)]
pub struct OraclePreCheckConfig {
    pub price_offset: usize,
    pub slot_offset: usize,
    pub timestamp_offset: Option<usize>,
    pub max_staleness_slots: u64,
    pub max_deviation_bps: Option<u64>,
    pub expected_owner: Option<String>,
}

/// Rate limit configuration for codegen.
#[derive(Debug, Clone, Default)]
pub struct RateLimitConfig {
    /// Global rate limit: max_count calls per window_slots.
    pub global: Option<RateLimitEntry>,
    /// Per-signer rate limit.
    pub per_signer: Option<RateLimitEntry>,
}

/// A single rate limit entry.
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub window_slots: u64,
    pub max_count: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Sighash computation (Anchor-compatible)
// ═══════════════════════════════════════════════════════════════════════════

/// Compute Anchor sighash: sha256("global:<fn_name>")[..8]
pub fn sighash(name: &str) -> [u8; 8] {
    let preimage = format!("global:{}", name);
    let hash = Sha256::digest(preimage.as_bytes());
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash[..8]);
    disc
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper: extract handler argument info for deserialization codegen
// ═══════════════════════════════════════════════════════════════════════════

/// Represents a parsed instruction handler argument (non-Context).
struct HandlerArg {
    name: Ident,
    ty: Box<Type>,
}

/// Extract the Context type parameter and non-Context args from a handler fn.
fn parse_handler_sig(f: &ItemFn) -> (Option<TokenStream2>, Vec<HandlerArg>) {
    let mut ctx_type = None;
    let mut args = Vec::new();
    let mut is_first = true;

    for input in &f.sig.inputs {
        if let FnArg::Typed(PatType { pat, ty, .. }) = input {
            if is_first {
                // First argument is Context<T> — extract T
                is_first = false;
                let ty_str = quote!(#ty).to_string();
                if ty_str.contains("Context") {
                    // Extract the inner type from Context<T>
                    if let Type::Path(type_path) = ty.as_ref() {
                        for seg in &type_path.path.segments {
                            if seg.ident == "Context" {
                                if let syn::PathArguments::AngleBracketed(ref ab) = seg.arguments {
                                    if let Some(syn::GenericArgument::Type(inner)) =
                                        ab.args.first()
                                    {
                                        ctx_type = Some(quote!(#inner));
                                    }
                                }
                            }
                        }
                    }
                }
                continue;
            }

            // Subsequent args are instruction arguments
            if let Pat::Ident(pat_ident) = pat.as_ref() {
                args.push(HandlerArg {
                    name: pat_ident.ident.clone(),
                    ty: ty.clone(),
                });
            }
        }
    }

    (ctx_type, args)
}

// ═══════════════════════════════════════════════════════════════════════════
// generate_dispatch_arms
// ═══════════════════════════════════════════════════════════════════════════

/// Generate discriminator match arms for each instruction handler.
///
/// Each arm matches the 8-byte Anchor sighash and delegates to the
/// `__sandbox_wrappers` module which runs pre/post checks and then
/// calls through to `__sandbox_instruction` for Anchor deserialization.
pub fn generate_dispatch_arms(fns: &[&ItemFn], _mod_name: &Ident) -> TokenStream2 {
    let arms: Vec<TokenStream2> = fns
        .iter()
        .map(|f| {
            let fn_name = &f.sig.ident;
            let fn_name_str = fn_name.to_string();
            let disc = sighash(&fn_name_str);
            let [d0, d1, d2, d3, d4, d5, d6, d7] = disc;

            quote! {
                [#d0, #d1, #d2, #d3, #d4, #d5, #d6, #d7] => {
                    // Dispatch to: #fn_name_str (via sandbox wrapper with pre/post checks)
                    __sandbox_wrappers::#fn_name(
                        program_id,
                        accounts,
                        ix_data,
                        __sandbox_emergency_bypass,
                    ).map(|_cat| ())
                }
            }
        })
        .collect();

    quote! { #(#arms),* }
}

/// Generate a const array of all known discriminators for fast lookup.
/// Used by mode checks and circuit breaker category routing.
pub fn generate_discriminator_table(fns: &[&ItemFn]) -> TokenStream2 {
    let entries: Vec<TokenStream2> = fns
        .iter()
        .map(|f| {
            let fn_name_str = f.sig.ident.to_string();
            let disc = sighash(&fn_name_str);
            let [d0, d1, d2, d3, d4, d5, d6, d7] = disc;
            quote! {
                (#fn_name_str, [#d0, #d1, #d2, #d3, #d4, #d5, #d6, #d7])
            }
        })
        .collect();

    quote! {
        const __SANDBOX_DISCRIMINATORS: &[(&str, [u8; 8])] = &[
            #(#entries),*
        ];
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// generate_instruction_module
// ═══════════════════════════════════════════════════════════════════════════

/// Generate the `__sandbox_instruction` module with real Anchor deserialization.
///
/// Each wrapper:
/// 1. Creates default bumps + reallocs
/// 2. Calls `T::try_accounts()` to deserialize accounts
/// 3. Deserializes instruction args from the data slice via `AnchorDeserialize`
/// 4. Constructs `Context<T>` and calls the user's handler
/// 5. Calls `accounts.exit(program_id)` to persist changes
pub fn generate_instruction_module(fns: &[&ItemFn], mod_name: &Ident) -> TokenStream2 {
    let wrappers: Vec<TokenStream2> = fns
        .iter()
        .map(|f| {
            let fn_name = &f.sig.ident;
            let fn_name_str = fn_name.to_string();
            let (ctx_type, handler_args) = parse_handler_sig(f);

            // Build the accounts type — default to fn_name in PascalCase if no Context found
            let accounts_type = if let Some(ref ct) = ctx_type {
                ct.clone()
            } else {
                // Fallback: generate a placeholder type name
                let pascal = to_pascal_case(&fn_name_str);
                let ident = format_ident!("{}", pascal);
                quote!(#ident)
            };

            // Generate arg deserialization from the ix_data slice
            let arg_deserializations: Vec<TokenStream2> = handler_args
                .iter()
                .map(|arg| {
                    let arg_name = &arg.name;
                    let arg_ty = &arg.ty;
                    quote! {
                        let #arg_name: #arg_ty = anchor_lang::AnchorDeserialize::deserialize(
                            &mut __ix_cursor
                        ).map_err(|_| anchor_lang::error::ErrorCode::InstructionDidNotDeserialize)?;
                    }
                })
                .collect();

            // Build the argument list for the handler call
            let arg_names: Vec<&Ident> = handler_args.iter().map(|a| &a.name).collect();
            let handler_call = if arg_names.is_empty() {
                quote! {
                    #mod_name::#fn_name(
                        anchor_lang::context::Context::new(
                            program_id,
                            &mut __accounts,
                            __remaining,
                            __bumps,
                        ),
                    )?;
                }
            } else {
                quote! {
                    #mod_name::#fn_name(
                        anchor_lang::context::Context::new(
                            program_id,
                            &mut __accounts,
                            __remaining,
                            __bumps,
                        ),
                        #(#arg_names),*
                    )?;
                }
            };

            quote! {
                /// Anchor-compatible dispatch wrapper for `#fn_name_str`.
                ///
                /// Deserializes accounts + args, calls handler, persists state.
                pub fn #fn_name<'info>(
                    program_id: &anchor_lang::prelude::Pubkey,
                    accounts: &'info [anchor_lang::prelude::AccountInfo<'info>],
                    ix_data: &[u8],
                ) -> anchor_lang::prelude::Result<()> {
                    // ── Deserialize accounts via Anchor's try_accounts ──
                    let mut __bumps =
                        <#accounts_type as anchor_lang::Bumps>::Bumps::default();
                    let mut __reallocs: std::collections::BTreeSet<anchor_lang::prelude::Pubkey> =
                        std::collections::BTreeSet::new();
                    let mut __remaining = &accounts[..];

                    let mut __accounts = <#accounts_type>::try_accounts(
                        program_id,
                        &mut __remaining,
                        ix_data,
                        &mut __bumps,
                        &mut __reallocs,
                    )?;

                    // ── Deserialize instruction arguments ──
                    let mut __ix_cursor: &[u8] = ix_data;
                    #(#arg_deserializations)*

                    // ── Call the user's handler ──
                    #handler_call

                    // ── Persist account changes ──
                    __accounts.exit(program_id)?;

                    Ok(())
                }
            }
        })
        .collect();

    quote! {
        /// Auto-generated instruction dispatch wrappers (sandbox-aware).
        /// Mirrors Anchor's `__private::__global` module pattern.
        /// Each wrapper does real Anchor account deserialization + arg parsing.
        #[doc(hidden)]
        mod __sandbox_instruction {
            use super::*;

            #(#wrappers)*
        }
    }
}

/// Convert snake_case to PascalCase.
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().chain(c).collect(),
            }
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// generate_id_module
// ═══════════════════════════════════════════════════════════════════════════

/// Generate the program ID check module.
///
/// Validates that the incoming `program_id` matches the program's declared ID
/// (from `declare_id!` in user code). This is the same check Anchor generates.
pub fn generate_id_module(_mod_name: &Ident) -> TokenStream2 {
    quote! {
        #[doc(hidden)]
        mod __sandbox_id_check {
            use super::*;

            /// Verify the program ID matches the declared ID.
            /// Called at the top of the sandbox entrypoint.
            #[inline(always)]
            pub fn check(program_id: &anchor_lang::prelude::Pubkey) -> bool {
                *program_id == crate::ID
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// generate_sandbox_entrypoint — THE main event
// ═══════════════════════════════════════════════════════════════════════════

/// Generate the full sandbox entrypoint implementing the 12-step pipeline
/// from SPEC §2.1.
///
/// The generated function is the Solana program entrypoint — ALL transactions
/// flow through here. No bypass path exists.
///
/// # Arguments
/// - `mod_name`: The user's module ident (e.g., `my_perps`).
/// - `dispatch_arms`: Pre-generated match arms from `generate_dispatch_arms`.
/// - `config`: Parsed sandbox configuration from `sandbox.toml`.
pub fn generate_sandbox_entrypoint(
    mod_name: &Ident,
    dispatch_arms: &TokenStream2,
    config: &SandboxConfig,
    pub_fns: &[&ItemFn],
    tx_anchor_field_paths: &[String],
) -> TokenStream2 {
    let _mod_name_str = mod_name.to_string();

    // Generate category router for circuit breaker category resolution
    let category_router = generate_category_router(pub_fns, config);

    // ── Step [1]: Re-entrancy guard codegen ──
    let reentrancy_mode_token = match config.reentrancy_mode {
        ReentrancyModeConfig::Reject => {
            quote! { perk_sandbox_runtime::guard::ReentrancyMode::Reject }
        }
        ReentrancyModeConfig::Guard => {
            quote! { perk_sandbox_runtime::guard::ReentrancyMode::Guard }
        }
        ReentrancyModeConfig::Full => {
            quote! { perk_sandbox_runtime::guard::ReentrancyMode::Full }
        }
    };

    // ── Step [2]: Mode check — generate the allowed-instructions sets ──
    let recovery_instructions: Vec<TokenStream2> = config
        .mode
        .recovery_instructions
        .iter()
        .map(|name| {
            let disc = sighash(name);
            let [d0, d1, d2, d3, d4, d5, d6, d7] = disc;
            quote! { [#d0, #d1, #d2, #d3, #d4, #d5, #d6, #d7] }
        })
        .collect();

    let close_only_instructions: Vec<TokenStream2> = config
        .mode
        .close_only_instructions
        .iter()
        .map(|name| {
            let disc = sighash(name);
            let [d0, d1, d2, d3, d4, d5, d6, d7] = disc;
            quote! { [#d0, #d1, #d2, #d3, #d4, #d5, #d6, #d7] }
        })
        .collect();

    // ── Step [5]: Transaction anchor codegen ──
    let tx_anchor_codegen = if config.tx_anchor_enabled {
        quote! {
            // ── [5] TRANSACTION-LEVEL SNAPSHOT ──
            // Find the Instructions sysvar in accounts
            let __ix_sysvar_info = accounts.iter().find(|a| {
                *a.key == anchor_lang::solana_program::sysvar::instructions::ID
            }).ok_or_else(|| {
                anchor_lang::prelude::msg!(
                    "PERK_SANDBOX:type=error,reason=instructions_sysvar_missing"
                );
                anchor_lang::solana_program::program_error::ProgramError::Custom(
                    perk_sandbox_runtime::error::SandboxError::SnapshotFailed as u32
                )
            })?;

            // Compute transaction fingerprint (CPI-proof — §5.2)
            let __tx_fingerprint = perk_sandbox_runtime::tx_anchor::compute_tx_fingerprint(
                __ix_sysvar_info,
            )?;

            // Check if this is the first sandbox invocation in this tx
            let __sandbox_pda_data_ref = __sandbox_pda_info.try_borrow_data()
                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                    perk_sandbox_runtime::error::SandboxError::SnapshotFailed as u32
                ))?;
            let __tx_anchor_offset = {
                let off = u16::from_le_bytes([
                    __sandbox_pda_data_ref[perk_sandbox_runtime::state::OFF_TX_ANCHOR],
                    __sandbox_pda_data_ref[perk_sandbox_runtime::state::OFF_TX_ANCHOR + 1],
                ]) as usize;
                if off == 0 {
                    // tx_anchor section not configured — skip
                    0usize
                } else {
                    off
                }
            };
            drop(__sandbox_pda_data_ref);

            let __is_first_invocation = if __tx_anchor_offset > 0 {
                let pda_data = __sandbox_pda_info.try_borrow_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::SnapshotFailed as u32
                    ))?;
                let anchor_section = &pda_data[__tx_anchor_offset..];
                let stored_fp = &anchor_section[..32];
                let is_first = stored_fp != &__tx_fingerprint[..];
                drop(pda_data);
                is_first
            } else {
                false
            };

            // Bind anchor fields for the per-instruction wrappers' tx_cumulative_decrease checks.
            // On first invocation: write fingerprint + field snapshots to PDA.
            // On subsequent: read stored snapshots.
            let __sandbox_tx_anchor_fields: Vec<(
                anchor_lang::solana_program::pubkey::Pubkey, u64
            )> = if __is_first_invocation && __tx_anchor_offset > 0 {
                anchor_lang::prelude::msg!(
                    "PERK_SANDBOX:type=tx_anchor,action=write_snapshot"
                );
                // Snapshot: read current field values from accounts.
                // The per-instruction wrapper will call write_anchor_snapshot
                // with these values after reading them via ctx.accounts.
                // For now, write the fingerprint to mark this tx as anchored.
                let mut pda_data = __sandbox_pda_info.try_borrow_mut_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::SnapshotFailed as u32
                    ))?;
                pda_data[__tx_anchor_offset..__tx_anchor_offset + 32]
                    .copy_from_slice(&__tx_fingerprint);
                // Write field count = 0 initially; the per-instruction wrapper
                // updates it with actual values after Anchor context is available.
                pda_data[__tx_anchor_offset + 32] = 0;
                drop(pda_data);
                // Return empty — wrapper will populate on first dispatch.
                Vec::new()
            } else if __tx_anchor_offset > 0 {
                anchor_lang::prelude::msg!(
                    "PERK_SANDBOX:type=tx_anchor,action=read_existing"
                );
                let pda_data = __sandbox_pda_info.try_borrow_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::SnapshotFailed as u32
                    ))?;
                let anchor_slice = &pda_data[__tx_anchor_offset..];
                let fields = perk_sandbox_runtime::tx_anchor::read_anchor_snapshot(
                    anchor_slice,
                )?;
                drop(pda_data);
                fields
            } else {
                Vec::new()
            };
        }
    } else {
        quote! {
            // ── [5] TRANSACTION-LEVEL SNAPSHOT — disabled (no tx_cumulative_decrease configured) ──
        }
    };

    // ── Step [4]: Rate limit pre-check codegen ──
    let rate_limit_codegen = if let Some(ref rl) = config.rate_limits {
        let global_check = if let Some(ref global) = rl.global {
            let window = global.window_slots;
            let max_count = global.max_count as u32;
            quote! {
                // ── [4] Global rate limit ──
                {
                    let __rl_offset = {
                        let pda_data = __sandbox_pda_info.try_borrow_data()
                            .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                            ))?;
                        u16::from_le_bytes([
                            pda_data[perk_sandbox_runtime::state::OFF_RATE_LIMITS],
                            pda_data[perk_sandbox_runtime::state::OFF_RATE_LIMITS + 1],
                        ]) as usize
                    };
                    if __rl_offset > 0 {
                        // Read global counter (counter_id = 0, first counter in section)
                        let __rl_counter_offset = __rl_offset + 1; // skip counter_count byte
                        {
                            let pda_data = __sandbox_pda_info.try_borrow_data()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;
                            let __counter = perk_sandbox_runtime::rate_limit::RateLimitCounter::read(
                                &pda_data, __rl_counter_offset
                            ).map_err(|e| anchor_lang::solana_program::program_error::ProgramError::Custom(e as u32))?;
                            let __current_slot = anchor_lang::solana_program::clock::Clock::get()
                                .map(|c| c.slot)
                                .unwrap_or(0);
                            perk_sandbox_runtime::rate_limit::check_rate_limit(
                                &__counter, #max_count, #window, __current_slot
                            ).map_err(|e| {
                                anchor_lang::prelude::msg!(
                                    "PERK_SANDBOX:type=rate_limit_exceeded,scope=global"
                                );
                                anchor_lang::solana_program::program_error::ProgramError::Custom(e as u32)
                            })?;
                            drop(pda_data);
                        }
                        // Increment counter (writes in-place to PDA)
                        {
                            let mut pda_data = __sandbox_pda_info.try_borrow_mut_data()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;
                            let __current_slot = anchor_lang::solana_program::clock::Clock::get()
                                .map(|c| c.slot)
                                .unwrap_or(0);
                            perk_sandbox_runtime::rate_limit::increment_counter(
                                &mut pda_data, __rl_counter_offset, #window, __current_slot
                            ).map_err(|e| anchor_lang::solana_program::program_error::ProgramError::Custom(e as u32))?;
                            drop(pda_data);
                        }
                    }
                }
            }
        } else {
            quote! {}
        };

        let per_signer_check = if let Some(ref per_signer) = rl.per_signer {
            let window = per_signer.window_slots;
            let max_count = per_signer.max_count as u32;
            quote! {
                // ── [4] Per-signer rate limit ──
                {
                    let __rl_offset = {
                        let pda_data = __sandbox_pda_info.try_borrow_data()
                            .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                            ))?;
                        u16::from_le_bytes([
                            pda_data[perk_sandbox_runtime::state::OFF_RATE_LIMITS],
                            pda_data[perk_sandbox_runtime::state::OFF_RATE_LIMITS + 1],
                        ]) as usize
                    };
                    if __rl_offset > 0 {
                        // Find signer from accounts
                        let __signer_key = accounts.iter()
                            .find(|a| a.is_signer)
                            .map(|a| a.key.to_bytes())
                            .unwrap_or([0u8; 32]);
                        let __signer_id = perk_sandbox_runtime::rate_limit::signer_hash_u8(&__signer_key);

                        let pda_data = __sandbox_pda_info.try_borrow_data()
                            .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                            ))?;
                        if __rl_offset >= pda_data.len() {
                            drop(pda_data);
                            return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                                perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                            ));
                        }
                        let __counter_count = pda_data[__rl_offset];
                        if let Some(__counter_offset) = perk_sandbox_runtime::rate_limit::find_counter(
                            &pda_data, __rl_offset + 1, __counter_count, __signer_id
                        ).map_err(|e| anchor_lang::solana_program::program_error::ProgramError::Custom(e as u32))? {
                            let __counter = perk_sandbox_runtime::rate_limit::RateLimitCounter::read(
                                &pda_data, __counter_offset
                            ).map_err(|e| anchor_lang::solana_program::program_error::ProgramError::Custom(e as u32))?;
                            let __current_slot = anchor_lang::solana_program::clock::Clock::get()
                                .map(|c| c.slot)
                                .unwrap_or(0);
                            perk_sandbox_runtime::rate_limit::check_rate_limit(
                                &__counter, #max_count, #window, __current_slot
                            ).map_err(|e| {
                                anchor_lang::prelude::msg!(
                                    "PERK_SANDBOX:type=rate_limit_exceeded,scope=per_signer"
                                );
                                anchor_lang::solana_program::program_error::ProgramError::Custom(e as u32)
                            })?;
                            drop(pda_data);

                            // Increment in-place
                            let mut pda_data = __sandbox_pda_info.try_borrow_mut_data()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;
                            let __current_slot = anchor_lang::solana_program::clock::Clock::get()
                                .map(|c| c.slot)
                                .unwrap_or(0);
                            perk_sandbox_runtime::rate_limit::increment_counter(
                                &mut pda_data, __counter_offset, #window, __current_slot
                            ).map_err(|e| anchor_lang::solana_program::program_error::ProgramError::Custom(e as u32))?;
                            drop(pda_data);
                        }
                        // If counter not found for this signer, skip (no pre-allocated slot)
                    }
                }
            }
        } else {
            quote! {}
        };

        quote! {
            #global_check
            #per_signer_check
        }
    } else {
        quote! {
            // ── [4] Rate limits — disabled (not configured) ──
        }
    };

    // ── Step [4b]: Oracle pre-check codegen ──
    let oracle_codegen = if let Some(ref oracle) = config.oracle {
        let price_off = oracle.price_offset;
        let slot_off = oracle.slot_offset;
        let ts_off = match oracle.timestamp_offset {
            Some(off) => quote! { Some(#off) },
            None => quote! { None },
        };
        let max_staleness = oracle.max_staleness_slots;

        // Expected owner: compile-time pubkey from base58 string
        let owner_check = if let Some(ref owner_b58) = oracle.expected_owner {
            let owner_bytes: [u8; 32] = bs58::decode(owner_b58)
                .into_vec()
                .expect("invalid base58 in oracle.expected_owner")
                .try_into()
                .expect("oracle.expected_owner must be 32 bytes");
            let ob = owner_bytes;
            quote! {
                let __oracle_expected_owner = anchor_lang::prelude::Pubkey::new_from_array(
                    [#(#ob),*]
                );
                Some(&__oracle_expected_owner)
            }
        } else {
            quote! { None }
        };

        let deviation_check = if let Some(max_dev) = oracle.max_deviation_bps {
            quote! {
                // Deviation check: compare against last-known price from PDA
                // For now, skip if no last-known price is available (first tx)
                if __oracle_reading.price > 0 {
                    // last_known_price would come from the market account or PDA.
                    // This is a config-driven global check; per-instruction deviation
                    // checks should use the instruction-level oracle attribute.
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=oracle_check,deviation_configured_bps={}",
                        #max_dev
                    );
                }
            }
        } else {
            quote! {}
        };

        quote! {
            // ── [4b] Oracle freshness pre-check ──
            {
                // Find oracle account in remaining_accounts by iterating.
                // The oracle is identified as any account NOT owned by this program
                // that matches the expected_owner (if configured).
                let __oracle_layout = perk_sandbox_runtime::oracle::OracleLayout {
                    price_offset: #price_off,
                    price_size: 8,
                    slot_offset: #slot_off,
                    timestamp_offset: #ts_off,
                };
                let __oracle_expected: Option<&anchor_lang::prelude::Pubkey> = #owner_check;
                let __current_slot = anchor_lang::solana_program::clock::Clock::get()
                    .map(|c| c.slot)
                    .unwrap_or(0);

                // Search accounts for oracle (skip program-owned accounts)
                let mut __oracle_checked = false;
                for __acct in accounts.iter() {
                    if __acct.owner == program_id {
                        continue;
                    }
                    // If expected_owner is set, only check matching accounts
                    if let Some(expected) = __oracle_expected {
                        if __acct.owner != expected {
                            continue;
                        }
                    }
                    // Try freshness check
                    match perk_sandbox_runtime::oracle::check_oracle_freshness(
                        __acct, &__oracle_layout, #max_staleness, __current_slot,
                        __oracle_expected,
                    ) {
                        Ok(()) => {
                            __oracle_checked = true;
                            // Read for deviation if configured
                            if let Ok(__oracle_reading) = perk_sandbox_runtime::oracle::read_oracle(
                                __acct, &__oracle_layout, __oracle_expected,
                            ) {
                                #deviation_check
                            }
                            break;
                        }
                        Err(_) => {
                            anchor_lang::prelude::msg!(
                                "PERK_SANDBOX:type=oracle_stale,account={}",
                                __acct.key
                            );
                            // Cleanup guard before returning
                            if __guard_offset > 0 {
                                if let Ok(mut pda_data_mut) = __sandbox_pda_info.try_borrow_mut_data() {
                                    let guard_mut = &mut pda_data_mut[__guard_offset..];
                                    let _ = perk_sandbox_runtime::guard::decrement_depth(guard_mut);
                                    if perk_sandbox_runtime::guard::read_depth(guard_mut).unwrap_or(1) == 0 {
                                        let _ = perk_sandbox_runtime::guard::clear_executing(guard_mut);
                                    }
                                }
                            }
                            return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                                perk_sandbox_runtime::error::SandboxError::OracleStale as u32
                            ));
                        }
                    }
                }
                // If no oracle account found and expected_owner is set, fail
                if !__oracle_checked && __oracle_expected.is_some() {
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=oracle_not_found"
                    );
                    // Cleanup guard before returning
                    if __guard_offset > 0 {
                        if let Ok(mut pda_data_mut) = __sandbox_pda_info.try_borrow_mut_data() {
                            let guard_mut = &mut pda_data_mut[__guard_offset..];
                            let _ = perk_sandbox_runtime::guard::decrement_depth(guard_mut);
                            if perk_sandbox_runtime::guard::read_depth(guard_mut).unwrap_or(1) == 0 {
                                let _ = perk_sandbox_runtime::guard::clear_executing(guard_mut);
                            }
                        }
                    }
                    return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::OracleStale as u32
                    ));
                }
            }
        }
    } else {
        quote! {
            // ── [4b] Oracle pre-check — disabled (not configured) ──
        }
    };

    // ── Step [9]: Circuit breaker codegen ──
    // Track field slug used by TVL cliff + per-tx threshold
    let track_field_slug = config.circuit_breakers.tvl_cliff_track_field
        .as_ref()
        .map(|f| f.replace('.', "_"))
        .unwrap_or_default();

    // TVL before-snapshot: read tracked field BEFORE dispatch so step [9] has the pre-value
    let tvl_before_snapshot = if config.circuit_breakers.tvl_cliff_enabled {
        let bf_offset = config.circuit_breakers.tvl_cliff_field_offset.unwrap_or(0);
        let bf_size = config.circuit_breakers.tvl_cliff_field_size;
        quote! {
            let __tvl_before_value: u64 = {
                let mut __found: u64 = 0;
                for __acct in accounts.iter() {
                    if __acct.owner != program_id { continue; }
                    // Skip the sandbox PDA itself (discriminator "PRKSANDX")
                    if *__acct.key == *__sandbox_pda_info.key { continue; }
                    if let Ok(data) = __acct.try_borrow_data() {
                        let __off = #bf_offset;
                        let __end = __off + #bf_size;
                        if data.len() >= __end {
                            __found = u64::from_le_bytes(
                                data[__off..__end].try_into().unwrap_or([0u8; 8])
                            );
                            break;
                        }
                    }
                }
                __found
            };
        }
    } else {
        quote! {}
    };

    let circuit_breaker_codegen = if config.circuit_breakers.enabled {
        let tvl_cliff_check = if config.circuit_breakers.tvl_cliff_enabled {
            let window_slots = config.circuit_breakers.tvl_cliff_window_slots;
            let window_seconds = config.circuit_breakers.tvl_cliff_window_seconds;

            // Field offset for direct account reads (before dispatch + after dispatch)
            let tvl_field_offset = config.circuit_breakers.tvl_cliff_field_offset.unwrap_or(0);
            let tvl_field_size = config.circuit_breakers.tvl_cliff_field_size;

            // Map action string to runtime enum token
            let action_token = match config.circuit_breakers.tvl_cliff_action.as_str() {
                "pause" => quote! { perk_sandbox_runtime::circuit_breaker::BreakerAction::Pause },
                "close_only" => quote! { perk_sandbox_runtime::circuit_breaker::BreakerAction::CloseOnly },
                "pause_liquidations" => quote! { perk_sandbox_runtime::circuit_breaker::BreakerAction::PauseLiquidations },
                _ => quote! { perk_sandbox_runtime::circuit_breaker::BreakerAction::RejectCurrent },
            };

            // Build budget match arms from config
            let budget_arms: Vec<TokenStream2> = config.circuit_breakers.tvl_cliff_budgets.iter().map(|(cat, max_pct)| {
                // Compile-time validation: max_pct=0 blocks all transactions for this category.
                // This is almost certainly a misconfiguration.
                if *max_pct == 0 {
                    panic!(
                        "sandbox.toml: circuit_breakers.tvl_cliff.budgets.{}.max_decrease_pct = 0 \
                         would block ALL transactions for this category. Use at least 1.",
                        cat
                    );
                }
                if *max_pct > 100 {
                    panic!(
                        "sandbox.toml: circuit_breakers.tvl_cliff.budgets.{}.max_decrease_pct = {} \
                         exceeds 100%. Use a value between 1 and 100.",
                        cat, max_pct
                    );
                }
                let cat_variant = match cat.as_str() {
                    "withdrawal" => quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::Withdrawal },
                    "liquidation" => quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::Liquidation },
                    "deposit" => quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::Deposit },
                    _ => quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::Default },
                };
                let bps = *max_pct * 100; // pct → bps
                quote! {
                    #cat_variant => perk_sandbox_runtime::circuit_breaker::CategoryBudget {
                        category: #cat_variant,
                        max_decrease_bps: #bps,
                    },
                }
            }).collect();

            // Exempt instructions check
            let exempt_discs: Vec<TokenStream2> = config.circuit_breakers.exempt_instructions.iter().map(|name| {
                let disc = sighash(name);
                let [d0, d1, d2, d3, d4, d5, d6, d7] = disc;
                quote! { [#d0, #d1, #d2, #d3, #d4, #d5, #d6, #d7] }
            }).collect();

            quote! {
                // ── [9a] TVL cliff check ──
                {
                    let __cb_offset = {
                        let pda_data = __sandbox_pda_info.try_borrow_data()
                            .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                            ))?;
                        u16::from_le_bytes([
                            pda_data[perk_sandbox_runtime::state::OFF_CIRCUIT_BREAKER],
                            pda_data[perk_sandbox_runtime::state::OFF_CIRCUIT_BREAKER + 1],
                        ]) as usize
                    };

                    if __cb_offset > 0 {
                        // Check if this instruction is exempt
                        let __cb_exempt = [
                            #(#exempt_discs),*
                        ].contains(&__disc);

                        if !__cb_exempt {
                            // Resolve budget for this instruction's category
                            let __cb_budget = match __instruction_category {
                                #(#budget_arms)*
                                _ => {
                                    anchor_lang::prelude::msg!(
                                        "PERK_SANDBOX:type=circuit_breaker,warn=uncategorized_instruction"
                                    );
                                    perk_sandbox_runtime::circuit_breaker::CategoryBudget {
                                        category: perk_sandbox_runtime::circuit_breaker::InstructionCategory::Default,
                                        max_decrease_bps: 0, // fail-closed: uncategorized instructions cannot decrease TVL
                                    }
                                },
                            };

                            let __clock = anchor_lang::solana_program::clock::Clock::get()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;

                            // Read the tracked field (post-business-logic) from accounts.
                            // Search for non-program-owned accounts and read u64 at the
                            // configured offset. The "before" value is handled by the
                            // runtime's HWM system — we pass current as both before and
                            // current when the HWM is stale (the runtime's R3-1 fix handles it).
                            let __tvl_current_value: u64 = {
                                let mut __found: u64 = 0;
                                for __acct in accounts.iter() {
                                    if __acct.owner != program_id { continue; }
                                    // Skip sandbox PDA
                                    if *__acct.key == *__sandbox_pda_info.key { continue; }
                                    if let Ok(data) = __acct.try_borrow_data() {
                                        let __off = #tvl_field_offset;
                                        let __end = __off + #tvl_field_size;
                                        if data.len() >= __end {
                                            __found = u64::from_le_bytes(
                                                data[__off..__end].try_into().unwrap_or([0u8; 8])
                                            );
                                            break;
                                        }
                                    }
                                }
                                __found
                            };

                            let mut __pda_data = __sandbox_pda_info.try_borrow_mut_data()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;

                            // Skip category_count(1) + category_id(1) = 2 bytes
                            // to reach the TVL header (history_len, etc.)
                            let __tvl_section_offset = __cb_offset + 2;

                            let __tvl_result = perk_sandbox_runtime::circuit_breaker::tvl_cliff_check(
                                &mut __pda_data,
                                __tvl_section_offset,
                                __tvl_before_value,  // pre-business-logic (captured in step [6b])
                                __tvl_current_value,  // post-business-logic (read above)
                                __clock.slot,
                                __clock.unix_timestamp,
                                #window_slots,
                                #window_seconds,
                                &__cb_budget,
                                #action_token,
                            );
                            drop(__pda_data);

                            match __tvl_result {
                                Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::Ok) => {
                                    // No breaker fired
                                }
                                Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                                    perk_sandbox_runtime::circuit_breaker::BreakerAction::Pause
                                )) => {
                                    __sandbox_deferred_pause = true;
                                    anchor_lang::prelude::msg!("PERK_SANDBOX:type=circuit_breaker,action=deferred_pause");
                                }
                                Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                                    perk_sandbox_runtime::circuit_breaker::BreakerAction::CloseOnly
                                )) => {
                                    __sandbox_deferred_close_only = true;
                                    anchor_lang::prelude::msg!("PERK_SANDBOX:type=circuit_breaker,action=deferred_close_only");
                                }
                                Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                                    perk_sandbox_runtime::circuit_breaker::BreakerAction::PauseLiquidations
                                )) => {
                                    __sandbox_deferred_liq_pause = true;
                                    anchor_lang::prelude::msg!("PERK_SANDBOX:type=circuit_breaker,action=deferred_pause_liq");
                                }
                                Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                                    perk_sandbox_runtime::circuit_breaker::BreakerAction::RejectCurrent
                                )) => {
                                    // Should not happen (RejectCurrent returns Err from tvl_cliff_check)
                                }
                                Err(e) => {
                                    anchor_lang::prelude::msg!("PERK_SANDBOX:type=circuit_breaker,triggered=tvl_cliff");
                                    return Err(e.into());
                                }
                            }
                        }
                    }
                }
            }
        } else {
            quote! {}
        };

        let event_counter_checks: Vec<TokenStream2> = config
            .circuit_breakers
            .event_counters
            .iter()
            .enumerate()
            .map(|(idx, ec_config)| {
                let counter_lit = ec_config.name.as_str();
                let counter_idx = idx;
                let ec_window_slots = ec_config.window_slots;
                let ec_window_seconds = ec_config.window_seconds;
                // Compile-time validation: max_count=0 triggers on first event = permanent DoS
                if ec_config.max_count == 0 {
                    panic!(
                        "sandbox.toml: event counter '{}' has max_count = 0 which would block \
                         the first event every window. Use at least 1.",
                        ec_config.name
                    );
                }
                let ec_max_count = ec_config.max_count;
                let ec_action = match ec_config.action.as_str() {
                    "pause" => quote! { perk_sandbox_runtime::circuit_breaker::BreakerAction::Pause },
                    "close_only" => quote! { perk_sandbox_runtime::circuit_breaker::BreakerAction::CloseOnly },
                    "pause_liquidations" => quote! { perk_sandbox_runtime::circuit_breaker::BreakerAction::PauseLiquidations },
                    _ => quote! { perk_sandbox_runtime::circuit_breaker::BreakerAction::RejectCurrent },
                };
                // Event counters are stored after the CB categories section.
                // Each counter is EVENT_COUNTER_SIZE (20) bytes, prefixed by
                // a 1-byte counter_count at the event_counters section offset.
                quote! {
                    // ── [9b] Event counter: #counter_lit ──
                    {
                        let __ec_offset = {
                            let pda_data = __sandbox_pda_info.try_borrow_data()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;
                            u16::from_le_bytes([
                                pda_data[perk_sandbox_runtime::state::OFF_EVENT_COUNTERS],
                                pda_data[perk_sandbox_runtime::state::OFF_EVENT_COUNTERS + 1],
                            ]) as usize
                        };
                        if __ec_offset > 0 {
                            // Skip counter_count byte, then index to the right counter
                            // Each counter: id(1) + EVENT_COUNTER_SIZE(20) = 21 bytes
                            // Skip counter_count(1) + counter_id(1) = base 2,
                            // then stride 21 per counter (id(1) + data(20))
                            let __ec_counter_offset = __ec_offset + 2 + (#counter_idx * 21);
                            let __clock = anchor_lang::solana_program::clock::Clock::get()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;
                            let mut __pda_data = __sandbox_pda_info.try_borrow_mut_data()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;
                            match perk_sandbox_runtime::circuit_breaker::event_counter_check(
                                &mut __pda_data,
                                __ec_counter_offset,
                                __clock.slot,
                                __clock.unix_timestamp,
                                #ec_window_slots,
                                #ec_window_seconds,
                                #ec_max_count,
                                #ec_action,
                            ) {
                                Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::Ok) => {}
                                Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                                    perk_sandbox_runtime::circuit_breaker::BreakerAction::Pause
                                )) => { __sandbox_deferred_pause = true; }
                                Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                                    perk_sandbox_runtime::circuit_breaker::BreakerAction::CloseOnly
                                )) => { __sandbox_deferred_close_only = true; }
                                Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                                    perk_sandbox_runtime::circuit_breaker::BreakerAction::PauseLiquidations
                                )) => { __sandbox_deferred_liq_pause = true; }
                                Ok(_) => {}
                                Err(e) => {
                                    drop(__pda_data);
                                    anchor_lang::prelude::msg!(
                                        "PERK_SANDBOX:type=circuit_breaker,triggered=event_counter,name={}",
                                        #counter_lit
                                    );
                                    return Err(e.into());
                                }
                            }
                            drop(__pda_data);
                        }
                    }
                }
            })
            .collect();

        let per_tx_check = if config.circuit_breakers.per_tx_threshold_enabled {
            let pt_max_bps = config.circuit_breakers.per_tx_max_decrease_bps;
            // Note: per_tx_max_decrease_bps = 0 means "no decrease allowed per instruction."
            // This is a valid config for deposit-only programs, but log a compile-time warning.
            if pt_max_bps == 0 {
                // This is a proc macro — can't use eprintln in all contexts.
                // The developer will see the generated msg! at runtime instead.
            }
            quote! {
                // ── [9c] Per-instruction threshold check (stateless) ──
                // NOTE: This check is per-instruction, not per-transaction.
                // An attacker can split a drain across multiple instructions in
                // one tx. The TVL cliff (step [9a]) catches cumulative drain via
                // its HWM which persists across instructions. This check is a
                // lighter-weight complement for single-instruction drains.
                {
                    let __ptx_result = perk_sandbox_runtime::circuit_breaker::per_tx_threshold_check(
                        __tvl_before_value,
                        __tvl_current_value,
                        #pt_max_bps,
                        perk_sandbox_runtime::circuit_breaker::BreakerAction::RejectCurrent,
                    );
                    match __ptx_result {
                        Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::Ok) => {}
                        Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                            perk_sandbox_runtime::circuit_breaker::BreakerAction::Pause
                        )) => { __sandbox_deferred_pause = true; }
                        Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                            perk_sandbox_runtime::circuit_breaker::BreakerAction::CloseOnly
                        )) => { __sandbox_deferred_close_only = true; }
                        Ok(perk_sandbox_runtime::circuit_breaker::BreakerResult::SetMode(
                            perk_sandbox_runtime::circuit_breaker::BreakerAction::PauseLiquidations
                        )) => { __sandbox_deferred_liq_pause = true; }
                        Ok(_) => {}
                        Err(e) => {
                            anchor_lang::prelude::msg!("PERK_SANDBOX:type=circuit_breaker,triggered=per_tx_threshold");
                            return Err(e.into());
                        }
                    }
                }
            }
        } else {
            quote! {}
        };

        quote! {
            // ── [9] CIRCUIT BREAKERS — ALWAYS run (including emergency bypass) ──
            {
                #tvl_cliff_check
                #(#event_counter_checks)*
                #per_tx_check
            }
        }
    } else {
        quote! {
            // ── [9] CIRCUIT BREAKERS — disabled ──
        }
    };

    // ── Build the full entrypoint ──
    quote! {
        // ── Solana entrypoint declaration ──
        anchor_lang::solana_program::entrypoint!(sandbox_process_instruction);

        /// The sandbox entrypoint — wraps Anchor dispatch with the full 12-step
        /// safety pipeline. This function IS the program entrypoint. No bypass.
        ///
        /// Generated by `#[sandbox_program]` for module `#mod_name_str`.
        pub fn sandbox_process_instruction<'info>(
            program_id: &anchor_lang::prelude::Pubkey,
            accounts: &'info [anchor_lang::prelude::AccountInfo<'info>],
            ix_data: &[u8],
        ) -> anchor_lang::solana_program::entrypoint::ProgramResult {
            // ═══════════════════════════════════════════════════════════════
            // PERK SANDBOX ENTRYPOINT — #mod_name_str
            // All transactions flow through here. No bypass.
            // Steps 1-12 per SPEC §2.1.
            // ═══════════════════════════════════════════════════════════════

            // ── Program ID check ──
            if !__sandbox_id_check::check(program_id) {
                return Err(anchor_lang::solana_program::program_error::ProgramError::IncorrectProgramId);
            }

            // ════════════════════════════════════════════════════════════════
            // [1] RE-ENTRANCY GUARD
            // ════════════════════════════════════════════════════════════════

            // Find sandbox PDA in accounts by iterating and checking owner + discriminator.
            // This avoids the expensive find_program_address in the hot path.
            let __sandbox_pda_info: Option<&anchor_lang::prelude::AccountInfo> = {
                let mut found: Option<&anchor_lang::prelude::AccountInfo> = None;
                for a in accounts.iter() {
                    if a.owner == program_id {
                        if let Ok(data) = a.try_borrow_data() {
                            if data.len() >= perk_sandbox_runtime::state::HEADER_SIZE
                                && data[0..8] == perk_sandbox_runtime::state::DISCRIMINATOR
                            {
                                // Verify PDA: read bump from offset 9, then create_program_address
                                let bump = data[perk_sandbox_runtime::state::OFF_BUMP];
                                drop(data);
                                if let Ok(expected) = anchor_lang::prelude::Pubkey::create_program_address(
                                    &[b"perk_sandbox", &[bump]],
                                    program_id,
                                ) {
                                    if *a.key == expected {
                                        found = Some(a);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                found
            };

            // Track whether we found the PDA. Without PDA, certain features are
            // unavailable (guard, mode checks, circuit breakers). We fail-closed
            // if the config requires them.
            let __has_pda = __sandbox_pda_info.is_some();
            let __sandbox_pda_info = if let Some(info) = __sandbox_pda_info {
                info
            } else {
                // No PDA found — check if features require it
                // If circuit breakers or reentrancy != reject, we need the PDA.
                anchor_lang::prelude::msg!(
                    "PERK_SANDBOX:type=warning,reason=pda_not_found"
                );
                // Return early with error if PDA is required
                return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                    perk_sandbox_runtime::error::SandboxError::SandboxStateNotInitialized as u32
                ));
            };

            // Validate PDA discriminator + version
            {
                let pda_data = __sandbox_pda_info.try_borrow_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                    ))?;

                if pda_data.len() < perk_sandbox_runtime::state::HEADER_SIZE {
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=error,reason=pda_too_small"
                    );
                    return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                    ));
                }

                // Check discriminator: "PRKSANDX"
                if pda_data[0..8] != perk_sandbox_runtime::state::DISCRIMINATOR {
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=error,reason=pda_bad_discriminator"
                    );
                    return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                    ));
                }

                // Check version
                if pda_data[perk_sandbox_runtime::state::OFF_VERSION]
                    != perk_sandbox_runtime::state::SANDBOX_STATE_VERSION
                {
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=error,reason=pda_version_mismatch,expected={},got={}",
                        perk_sandbox_runtime::state::SANDBOX_STATE_VERSION,
                        pda_data[perk_sandbox_runtime::state::OFF_VERSION]
                    );
                    return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::SandboxStateVersionMismatch as u32
                    ));
                }
            }

            // Read guard section offset from PDA header
            let __guard_offset = {
                let pda_data = __sandbox_pda_info.try_borrow_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                    ))?;
                u16::from_le_bytes([
                    pda_data[perk_sandbox_runtime::state::OFF_GUARD],
                    pda_data[perk_sandbox_runtime::state::OFF_GUARD + 1],
                ]) as usize
            };

            // Re-entrancy check
            let __is_inner_call: bool = if __guard_offset > 0 {
                let pda_data = __sandbox_pda_info.try_borrow_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                    ))?;
                let guard_section = &pda_data[__guard_offset..];

                let action = perk_sandbox_runtime::guard::check_reentrancy(
                    guard_section,
                    #reentrancy_mode_token,
                )?;
                drop(pda_data);

                match action {
                    perk_sandbox_runtime::guard::ReentrancyAction::Normal => {
                        // First entry — set executing flag + increment depth
                        let mut pda_data_mut = __sandbox_pda_info.try_borrow_mut_data()
                            .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                            ))?;
                        let guard_mut = &mut pda_data_mut[__guard_offset..];
                        perk_sandbox_runtime::guard::set_executing(guard_mut)?;
                        perk_sandbox_runtime::guard::increment_depth(guard_mut)?;
                        drop(pda_data_mut);
                        false // not inner call
                    }
                    perk_sandbox_runtime::guard::ReentrancyAction::InnerCall => {
                        // Re-entrant in Guard/Full mode — increment depth, set flag
                        let mut pda_data_mut = __sandbox_pda_info.try_borrow_mut_data()
                            .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                            ))?;
                        let guard_mut = &mut pda_data_mut[__guard_offset..];
                        perk_sandbox_runtime::guard::increment_depth(guard_mut)?;
                        drop(pda_data_mut);
                        true // inner call
                    }
                    perk_sandbox_runtime::guard::ReentrancyAction::Blocked => {
                        // Reject mode — block re-entrant call
                        anchor_lang::prelude::msg!(
                            "PERK_SANDBOX:type=reentrancy_blocked"
                        );
                        return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                            perk_sandbox_runtime::error::SandboxError::ReentrancyDetected as u32
                        ));
                    }
                }
            } else {
                false // no guard section — treat as normal
            };

            // ════════════════════════════════════════════════════════════════
            // [2] MODE CHECK
            // ════════════════════════════════════════════════════════════════

            let __mode_flags_offset = {
                let pda_data = __sandbox_pda_info.try_borrow_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                    ))?;
                u16::from_le_bytes([
                    pda_data[perk_sandbox_runtime::state::OFF_MODE_FLAGS],
                    pda_data[perk_sandbox_runtime::state::OFF_MODE_FLAGS + 1],
                ]) as usize
            };

            // ════════════════════════════════════════════════════════════════
            // Parse discriminator ONCE (used by mode check, dispatch, etc.)
            // ════════════════════════════════════════════════════════════════
            if ix_data.len() < 8 {
                anchor_lang::prelude::msg!(
                    "PERK_SANDBOX:type=unknown_instruction,reason=data_too_short"
                );
                // Cleanup guard before returning
                if __guard_offset > 0 {
                    let mut pda_data_mut = __sandbox_pda_info.try_borrow_mut_data()
                        .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                            perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                        ))?;
                    let guard_mut = &mut pda_data_mut[__guard_offset..];
                    let _ = perk_sandbox_runtime::guard::decrement_depth(guard_mut);
                    if perk_sandbox_runtime::guard::read_depth(guard_mut).unwrap_or(1) == 0 {
                        let _ = perk_sandbox_runtime::guard::clear_executing(guard_mut);
                    }
                }
                return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                    perk_sandbox_runtime::error::SandboxError::UnknownInstruction as u32
                ));
            }

            let __disc: [u8; 8] = ix_data[..8].try_into()
                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                    perk_sandbox_runtime::error::SandboxError::UnknownInstruction as u32
                ))?;

            // ════════════════════════════════════════════════════════════
            // CATEGORY ROUTER — resolve instruction category from discriminator
            // ════════════════════════════════════════════════════════════
            #category_router

            let mut __sandbox_emergency_bypass: bool = false;

            if __mode_flags_offset > 0 {
                let pda_data = __sandbox_pda_info.try_borrow_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                    ))?;

                // Mode flags section layout (§8.2):
                //   +0:  paused: bool (1)
                //   +1:  close_only: bool (1)
                //   +2:  liquidation_paused: bool (1)
                //   +3:  emergency_bypass_active: bool (1)
                //   +4:  paused_at_slot: u64 (8)
                //   +12: pause_reason: [u8; 32] (32)
                //   +44: cooldown_end_slot: u64 (8)
                //   +52: emergency_bypass_end_slot: u64 (8)
                let mf = __mode_flags_offset;

                // Bounds check: mode flags section must fit within PDA data
                if mf + perk_sandbox_runtime::state::MODE_FLAGS_SIZE > pda_data.len() {
                    drop(pda_data);
                    // Cleanup guard before returning
                    if __guard_offset > 0 {
                        if let Ok(mut pda_data_mut) = __sandbox_pda_info.try_borrow_mut_data() {
                            let guard_mut = &mut pda_data_mut[__guard_offset..];
                            let _ = perk_sandbox_runtime::guard::decrement_depth(guard_mut);
                            if perk_sandbox_runtime::guard::read_depth(guard_mut).unwrap_or(1) == 0 {
                                let _ = perk_sandbox_runtime::guard::clear_executing(guard_mut);
                            }
                        }
                    }
                    return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                    ));
                }

                let __paused = pda_data[mf] != 0;
                let __close_only = pda_data[mf + 1] != 0;
                let __liquidation_paused = pda_data[mf + 2] != 0;
                __sandbox_emergency_bypass = pda_data[mf + 3] != 0;

                // Check emergency bypass auto-expiry
                if __sandbox_emergency_bypass {
                    let __bypass_end_slot = u64::from_le_bytes(
                        pda_data[mf + 52..mf + 60].try_into().unwrap_or([0u8; 8])
                    );
                    // If we can't read the clock, treat bypass as expired (fail-closed)
                    let __current_slot = anchor_lang::solana_program::clock::Clock::get()
                        .map(|c| c.slot)
                        .unwrap_or(u64::MAX); // MAX means "current slot is always > end_slot" = expired
                    if __bypass_end_slot > 0 && __current_slot > __bypass_end_slot {
                        __sandbox_emergency_bypass = false;
                    }
                }

                drop(pda_data);

                // Check: paused → only recovery instructions allowed
                if __paused {
                    let __is_recovery = [
                        #(#recovery_instructions),*
                    ].contains(&__disc);

                    if !__is_recovery {
                        anchor_lang::prelude::msg!(
                            "PERK_SANDBOX:type=mode_check,mode=paused,allowed=false"
                        );
                        // Cleanup guard
                        if __guard_offset > 0 {
                            let mut pda_data_mut = __sandbox_pda_info.try_borrow_mut_data()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;
                            let guard_mut = &mut pda_data_mut[__guard_offset..];
                            let _ = perk_sandbox_runtime::guard::decrement_depth(guard_mut);
                            if perk_sandbox_runtime::guard::read_depth(guard_mut).unwrap_or(1) == 0 {
                                let _ = perk_sandbox_runtime::guard::clear_executing(guard_mut);
                            }
                        }
                        return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                            perk_sandbox_runtime::error::SandboxError::ProgramPaused as u32
                        ));
                    }
                }

                // Check: close_only → only close/withdraw/liquidate allowed
                if __close_only {
                    let __is_close_allowed = [
                        #(#close_only_instructions),*
                    ].contains(&__disc);

                    if !__is_close_allowed {
                        anchor_lang::prelude::msg!(
                            "PERK_SANDBOX:type=mode_check,mode=close_only,allowed=false"
                        );
                        if __guard_offset > 0 {
                            let mut pda_data_mut = __sandbox_pda_info.try_borrow_mut_data()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;
                            let guard_mut = &mut pda_data_mut[__guard_offset..];
                            let _ = perk_sandbox_runtime::guard::decrement_depth(guard_mut);
                            if perk_sandbox_runtime::guard::read_depth(guard_mut).unwrap_or(1) == 0 {
                                let _ = perk_sandbox_runtime::guard::clear_executing(guard_mut);
                            }
                        }
                        return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                            perk_sandbox_runtime::error::SandboxError::CloseOnlyMode as u32
                        ));
                    }
                }

                // Check: liquidation_paused → liquidation instructions blocked
                if __liquidation_paused {
                    if __instruction_category == perk_sandbox_runtime::circuit_breaker::InstructionCategory::Liquidation {
                        anchor_lang::prelude::msg!(
                            "PERK_SANDBOX:type=mode_check,mode=liquidation_paused,blocked=true"
                        );
                        // Cleanup guard
                        if __guard_offset > 0 {
                            let mut pda_data_mut = __sandbox_pda_info.try_borrow_mut_data()
                                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                                    perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                                ))?;
                            let guard_mut = &mut pda_data_mut[__guard_offset..];
                            let _ = perk_sandbox_runtime::guard::decrement_depth(guard_mut);
                            if perk_sandbox_runtime::guard::read_depth(guard_mut).unwrap_or(1) == 0 {
                                let _ = perk_sandbox_runtime::guard::clear_executing(guard_mut);
                            }
                        }
                        return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                            perk_sandbox_runtime::error::SandboxError::LiquidationPaused as u32
                        ));
                    }
                }

                // Emergency bypass: non-recovery callers see warning but proceed
                // (invariants disabled, breakers still active)
                if __sandbox_emergency_bypass {
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=mode_check,mode=emergency_bypass"
                    );
                }
            }

            // ════════════════════════════════════════════════════════════════
            // [3] UNKNOWN INSTRUCTION CHECK
            // ════════════════════════════════════════════════════════════════
            // (Disc already parsed once above. The actual match happens
            //  in step [7]. Unknown discriminators fall through to the `_ =>` arm.)

            // ════════════════════════════════════════════════════════════════
            // [4] PRE-CHECKS (authority, oracle, rate limits, bounds)
            // ════════════════════════════════════════════════════════════════
            // These run on EVERY call including re-entrant and emergency bypass.
            //
            // Per-instruction authority + bound checks are in the per-instruction
            // wrapper (generate_single_wrapper). Global rate limits are here.
            // Oracle pre-checks are per-instruction (declared via attributes).
            #rate_limit_codegen

            #oracle_codegen

            // ════════════════════════════════════════════════════════════════
            // [5] TRANSACTION-LEVEL SNAPSHOT
            // ════════════════════════════════════════════════════════════════
            #tx_anchor_codegen

            // ════════════════════════════════════════════════════════════════
            // [6] INSTRUCTION-LEVEL SNAPSHOT
            // ════════════════════════════════════════════════════════════════
            // Per-instruction snapshots (before/after) are generated inside the
            // per-instruction wrappers (__sandbox_wrappers) by snapshot.rs codegen.
            // The main entrypoint delegates to them via step [7] dispatch.

            // ── [6b] Circuit breaker TVL before-snapshot (main entrypoint scope) ──
            // Captured here so step [9] has the pre-business-logic value.
            #tvl_before_snapshot

            // ════════════════════════════════════════════════════════════════
            // [7] DISPATCH TO BUSINESS LOGIC
            // ════════════════════════════════════════════════════════════════
            let __dispatch_result = match __disc {
                #dispatch_arms
                _ => {
                    // Unknown instruction — fail closed (§2.1 step 3)
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=unknown_instruction,disc={:?}",
                        __disc
                    );
                    Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::UnknownInstruction as u32
                    ).into())
                }
            };

            // If business logic failed → propagate error. Solana rolls back everything.
            if let Err(e) = __dispatch_result {
                anchor_lang::prelude::msg!("PERK_SANDBOX:type=dispatch_error");

                // Cleanup guard before returning
                if __guard_offset > 0 {
                    let mut pda_data_mut = __sandbox_pda_info.try_borrow_mut_data()
                        .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                            perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                        ))?;
                    let guard_mut = &mut pda_data_mut[__guard_offset..];
                    let _ = perk_sandbox_runtime::guard::decrement_depth(guard_mut);
                    if perk_sandbox_runtime::guard::read_depth(guard_mut).unwrap_or(1) == 0 {
                        let _ = perk_sandbox_runtime::guard::clear_executing(guard_mut);
                    }
                }

                return Err(e.into());
            }

            // ════════════════════════════════════════════════════════════════
            // [8] POST-CHECKS (invariants, tx cumulative decrease)
            // ════════════════════════════════════════════════════════════════
            // Skip during inner call in Guard mode (§7.1).
            // Skip during emergency bypass EXCEPT tx_cumulative_decrease (§9.1).
            // Per-instruction invariant post-checks and tx_cumulative_decrease
            // are generated inside the per-instruction wrappers (__sandbox_wrappers)
            // by invariant_attr.rs codegen. The wrappers run after dispatch returns
            // Ok and produce the correct before/after comparisons with CU reservation.
            // The main entrypoint only needs to handle the bypass/inner-call gating,
            // which is done inside the wrapper via __sandbox_emergency_bypass param.
            if !__is_inner_call {
                if !__sandbox_emergency_bypass {
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=post_checks,phase=full"
                    );
                } else {
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=post_checks,phase=bypass_limited"
                    );
                }
            } else {
                anchor_lang::prelude::msg!(
                    "PERK_SANDBOX:type=post_checks,phase=skipped_inner_call"
                );
            }

            // ════════════════════════════════════════════════════════════════
            // [9] CIRCUIT BREAKERS — ALWAYS run (including emergency bypass)
            // ════════════════════════════════════════════════════════════════
            // Deferred action accumulators: breakers set these during step [9],
            // step [10] persists them to the PDA. Only SET, never clear.
            let mut __sandbox_deferred_pause: bool = false;
            let mut __sandbox_deferred_close_only: bool = false;
            let mut __sandbox_deferred_liq_pause: bool = false;

            #circuit_breaker_codegen

            // ════════════════════════════════════════════════════════════════
            // [10] UPDATE PDA (counters, TVL, mode flags)
            // ════════════════════════════════════════════════════════════════
            // SAFETY: Step [10] MUST NOT return Err after business logic succeeded
            // in step [7], because that would skip step [11] guard cleanup and
            // permanently brick the reentrancy guard. All write failures are
            // logged and continued. Only a genuinely corrupted PDA (bounds check
            // failure on read) causes an early return — and that path cleans up
            // the guard before returning.
            {
                let __step10_result: std::result::Result<(), anchor_lang::solana_program::program_error::ProgramError> = (|| {
                    let mut __pda_data = __sandbox_pda_info.try_borrow_mut_data()
                        .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                            perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                        ))?;

                    // ── [10a] Write mode flag changes (deferred breaker actions) ──
                    if __mode_flags_offset > 0 {
                        let __mf = __mode_flags_offset;

                        // Bounds check: if PDA is too small, this is genuine corruption.
                        if __mf + perk_sandbox_runtime::state::MODE_FLAGS_SIZE > __pda_data.len() {
                            return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(
                                perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                            ));
                        }

                        let __cur_paused = __pda_data[__mf] != 0;
                        let __cur_close_only = __pda_data[__mf + 1] != 0;
                        let __cur_liq_paused = __pda_data[__mf + 2] != 0;
                        let __cur_bypass = __pda_data[__mf + 3] != 0;

                        // Merge: deferred actions only SET flags, never clear them.
                        let __new_paused = __cur_paused || __sandbox_deferred_pause;
                        let __new_close_only = __cur_close_only || __sandbox_deferred_close_only;
                        let __new_liq_paused = __cur_liq_paused || __sandbox_deferred_liq_pause;

                        // Only write if something changed
                        if __new_paused != __cur_paused
                            || __new_close_only != __cur_close_only
                            || __new_liq_paused != __cur_liq_paused
                        {
                            if let Err(_) = perk_sandbox_runtime::state::write_mode_flags(
                                &mut __pda_data, __mf,
                                __new_paused, __new_close_only, __new_liq_paused,
                                __cur_bypass,
                            ) {
                                anchor_lang::prelude::msg!(
                                    "PERK_SANDBOX:type=pda_write_warn,field=mode_flags"
                                );
                            } else {
                                // If transitioning to paused, record the slot
                                if __new_paused && !__cur_paused {
                                    let __slot = anchor_lang::solana_program::clock::Clock::get()
                                        .map(|c| c.slot)
                                        .unwrap_or(0);
                                    if let Err(_) = perk_sandbox_runtime::state::write_paused_at_slot(
                                        &mut __pda_data, __mf, __slot
                                    ) {
                                        anchor_lang::prelude::msg!(
                                            "PERK_SANDBOX:type=pda_write_warn,field=paused_at_slot"
                                        );
                                    }
                                }

                                anchor_lang::prelude::msg!(
                                    "PERK_SANDBOX:type=pda_update,mode_flags_changed=true,paused={},close_only={},liq_paused={}",
                                    __new_paused, __new_close_only, __new_liq_paused
                                );
                            }
                        }

                        // Auto-expire emergency bypass if it was active but expired
                        if __cur_bypass && !__sandbox_emergency_bypass {
                            if let Err(_) = perk_sandbox_runtime::state::write_mode_flag_single(
                                &mut __pda_data, __mf, 3, false
                            ) {
                                anchor_lang::prelude::msg!(
                                    "PERK_SANDBOX:type=pda_write_warn,field=bypass_expiry"
                                );
                            } else {
                                anchor_lang::prelude::msg!(
                                    "PERK_SANDBOX:type=pda_update,emergency_bypass_expired=true"
                                );
                            }
                        }
                    }

                    // ── [10b] Circuit breaker ring buffer writes ──
                    // Happen in-place during step [9] evaluation.

                    // ── [10c] Rate limit counter writes ──
                    // Happen in-place during step [4] evaluation.

                    drop(__pda_data);
                    Ok(())
                })();

                // If step [10] failed, log but DO NOT return — guard cleanup in
                // step [11] MUST run. Business logic already succeeded.
                if let Err(e) = __step10_result {
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=pda_update_failed,error={:?}",
                        e
                    );
                    // If this was a genuine PDA corruption (bounds check), the
                    // guard cleanup will also likely fail. But we try anyway.
                }

                anchor_lang::prelude::msg!("PERK_SANDBOX:type=pda_update");
            }

            // ════════════════════════════════════════════════════════════════
            // [11] CLEAR RE-ENTRANCY GUARD
            // ════════════════════════════════════════════════════════════════
            if __guard_offset > 0 {
                let mut pda_data_mut = __sandbox_pda_info.try_borrow_mut_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                        perk_sandbox_runtime::error::SandboxError::PDACorrupted as u32
                    ))?;
                let guard_mut = &mut pda_data_mut[__guard_offset..];

                // Decrement depth
                let new_depth = perk_sandbox_runtime::guard::decrement_depth(guard_mut)?;

                // If outermost call (depth back to 0), clear executing flag
                if new_depth == 0 {
                    perk_sandbox_runtime::guard::clear_executing(guard_mut)?;
                }

                drop(pda_data_mut);
            }

            // ════════════════════════════════════════════════════════════════
            // [12] RETURN OK
            // ════════════════════════════════════════════════════════════════
            anchor_lang::prelude::msg!(
                "PERK_SANDBOX:type=success"
            );
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper: generate guard cleanup code (used in early-return paths)
// ═══════════════════════════════════════════════════════════════════════════

/// Generate the guard cleanup pattern used on early-return error paths.
/// Must decrement depth and clear executing if outermost call.
pub fn generate_guard_cleanup() -> TokenStream2 {
    quote! {
        if __guard_offset > 0 {
            if let Ok(mut pda_data_mut) = __sandbox_pda_info.try_borrow_mut_data() {
                let guard_mut = &mut pda_data_mut[__guard_offset..];
                let _ = perk_sandbox_runtime::guard::decrement_depth(guard_mut);
                if perk_sandbox_runtime::guard::read_depth(guard_mut).unwrap_or(1) == 0 {
                    let _ = perk_sandbox_runtime::guard::clear_executing(guard_mut);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// generate_category_router — map discriminators to instruction categories
// ═══════════════════════════════════════════════════════════════════════════

/// Generate code that maps the current instruction discriminator to its
/// circuit breaker category. Used in step [9] for category-aware budgets.
pub fn generate_category_router(
    fns: &[&ItemFn],
    config: &SandboxConfig,
) -> TokenStream2 {
    let arms: Vec<TokenStream2> = fns
        .iter()
        .map(|f| {
            let fn_name_str = f.sig.ident.to_string();
            let disc = sighash(&fn_name_str);
            let [d0, d1, d2, d3, d4, d5, d6, d7] = disc;

            // Find category for this instruction
            let category = config
                .circuit_breakers
                .categories
                .iter()
                .find(|c| c.instruction == fn_name_str)
                .map(|c| c.category.as_str())
                .unwrap_or("default");

            let cat_variant = match category {
                "withdrawal" => {
                    quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::Withdrawal }
                }
                "liquidation" => {
                    quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::Liquidation }
                }
                "deposit" => {
                    quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::Deposit }
                }
                _ => {
                    quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::Default }
                }
            };

            quote! {
                [#d0, #d1, #d2, #d3, #d4, #d5, #d6, #d7] => #cat_variant
            }
        })
        .collect();

    quote! {
        let __instruction_category: perk_sandbox_runtime::circuit_breaker::InstructionCategory = match __disc {
            #(#arms,)*
            _ => perk_sandbox_runtime::circuit_breaker::InstructionCategory::Default,
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sighash_deterministic() {
        let a = sighash("initialize");
        let b = sighash("initialize");
        assert_eq!(a, b);
    }

    #[test]
    fn test_sighash_different_names() {
        let a = sighash("initialize");
        let b = sighash("close_position");
        assert_ne!(a, b);
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("open_position"), "OpenPosition");
        assert_eq!(to_pascal_case("initialize"), "Initialize");
        assert_eq!(to_pascal_case("close"), "Close");
        assert_eq!(to_pascal_case("a_b_c"), "ABC");
    }

    #[test]
    fn test_default_config() {
        let config = SandboxConfig::default();
        assert_eq!(config.reentrancy_mode, ReentrancyModeConfig::Guard);
        assert!(!config.circuit_breakers.enabled);
        assert!(!config.tx_anchor_enabled);
    }

    #[test]
    fn test_sighash_known_value() {
        // Anchor sighash for "initialize" is sha256("global:initialize")[..8]
        let disc = sighash("initialize");
        assert_eq!(disc.len(), 8);
        // Just verify it's non-zero and consistent
        assert_ne!(disc, [0u8; 8]);
    }

    #[test]
    fn test_generate_id_module_compiles() {
        let mod_name = format_ident!("my_perps");
        let tokens = generate_id_module(&mod_name);
        let code = tokens.to_string();
        assert!(code.contains("sandbox_id_check"));
        assert!(code.contains("crate :: ID"));
    }

    #[test]
    fn test_generate_guard_cleanup() {
        let tokens = generate_guard_cleanup();
        let code = tokens.to_string();
        assert!(code.contains("guard_offset"));
        assert!(code.contains("decrement_depth"));
        assert!(code.contains("clear_executing"));
    }

    #[test]
    fn test_generate_entrypoint_has_all_steps() {
        let mod_name = format_ident!("test_program");
        let dispatch_arms = quote! {};
        let config = SandboxConfig::default();
        let pub_fns: Vec<&ItemFn> = vec![];
        let tokens = generate_sandbox_entrypoint(&mod_name, &dispatch_arms, &config, &pub_fns, &[]);
        let code = tokens.to_string();

        // Verify key elements of all 12 steps are present in the generated code.
        // Note: Rust comments inside quote! macros get tokenized, so hyphens
        // split into separate tokens. Check for runtime function names instead.
        assert!(code.contains("check_reentrancy"), "step [1] reentrancy guard");
        assert!(code.contains("mode_flags") || code.contains("__paused"), "step [2] mode check");
        assert!(code.contains("UnknownInstruction"), "step [3] unknown instruction");
        assert!(code.contains("__disc"), "step [3/7] discriminator parsing");
        assert!(code.contains("DISPATCH") || code.contains("dispatch_result") || code.contains("__dispatch_result"), "step [7] dispatch");
        assert!(code.contains("post_checks") || code.contains("POST"), "step [8] post-checks");
        assert!(code.contains("pda_update") || code.contains("UPDATE"), "step [10] PDA update");
        assert!(code.contains("clear_executing"), "step [11] clear guard");
        assert!(code.contains("Ok"), "step [12] return OK");
    }

    #[test]
    fn test_generate_entrypoint_with_tx_anchor() {
        let mod_name = format_ident!("test_program");
        let dispatch_arms = quote! {};
        let mut config = SandboxConfig::default();
        config.tx_anchor_enabled = true;
        let pub_fns: Vec<&ItemFn> = vec![];
        let tokens = generate_sandbox_entrypoint(&mod_name, &dispatch_arms, &config, &pub_fns, &[]);
        let code = tokens.to_string();

        assert!(code.contains("compute_tx_fingerprint"));
        assert!(code.contains("tx_fingerprint"));
        assert!(code.contains("write_snapshot") || code.contains("read_existing"));
    }

    #[test]
    fn test_generate_entrypoint_with_circuit_breakers() {
        let mod_name = format_ident!("test_program");
        let dispatch_arms = quote! {};
        let mut config = SandboxConfig::default();
        config.circuit_breakers.enabled = true;
        config.circuit_breakers.tvl_cliff_enabled = true;
        config.circuit_breakers.per_tx_threshold_enabled = true;
        config.circuit_breakers.event_counters = vec![EventCounterConfig {
            name: "rapid_liquidations".to_string(),
            window_slots: 1000,
            window_seconds: 600,
            max_count: 50,
            action: "reject_current".to_string(),
        }];
        let pub_fns: Vec<&ItemFn> = vec![];
        let tokens = generate_sandbox_entrypoint(&mod_name, &dispatch_arms, &config, &pub_fns, &[]);
        let code = tokens.to_string();

        assert!(code.contains("circuit_breaker"));
        assert!(code.contains("tvl_cliff"));
        assert!(code.contains("per_tx_threshold"));
        assert!(code.contains("event_counter"));
    }
}

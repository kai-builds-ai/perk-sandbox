//! Transaction-level anchor snapshot codegen (macro side).
//!
//! Generates code that runs at step [5] of the sandbox entrypoint to:
//! - Compute a transaction fingerprint via the Instructions sysvar
//! - On first sandbox invocation: snapshot tx-anchor fields, write to PDA
//! - On subsequent invocations: read the existing anchor snapshot
//!
//! Also generates step [8c]: per-transaction cumulative decrease checks.
//!
//! Spec reference: §5 (Transaction-Level Invariants)

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

// ── Types ────────────────────────────────────────────────────────────────────

/// Configuration for a single tx-level anchor field.
///
/// Each field references an account in the transaction context and a specific
/// data field within that account whose value should be snapshotted at the
/// start of the transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAnchorField {
    /// The account name as it appears in the Anchor Context (e.g. `"market"`).
    pub account_name: String,
    /// Dot-separated field path within the account (e.g. `"vault_balance"`).
    pub field_path: String,
    /// Rust type of the field (e.g. `"u64"`).
    pub field_type: String,
}

// ── Step [5]: Transaction anchor setup ───────────────────────────────────────

/// Generate the transaction anchor setup code that runs at step [5].
///
/// On first invocation in the transaction:
/// 1. Gets the Instructions sysvar from accounts
/// 2. Calls `compute_tx_fingerprint(ix_sysvar)` to get a deterministic hash
/// 3. Calls `is_first_sandbox_invocation(pda_data, &fingerprint)` to detect first call
/// 4. If first: reads each field's current value, calls `write_anchor_snapshot`
/// 5. If not first: calls `read_anchor_snapshot` to retrieve stored values
///
/// The generated code produces a `Vec<(Pubkey, u64)>` binding named
/// `__sandbox_tx_anchor_fields` containing the anchor values.
///
/// # Parameters
/// - `fields`: slice of [`TxAnchorField`] describing which account fields to snapshot
///
/// # Generated bindings
/// - `__sandbox_tx_fingerprint: [u8; 32]`
/// - `__sandbox_is_first_ix: bool`
/// - `__sandbox_tx_anchor_fields: Vec<(Pubkey, u64)>`
pub fn generate_tx_anchor_setup(fields: &[TxAnchorField]) -> TokenStream {
    if fields.is_empty() {
        // No tx-level invariants configured — generate no-op bindings
        return quote! {
            let __sandbox_tx_fingerprint: [u8; 32] = [0u8; 32];
            let __sandbox_is_first_ix: bool = true;
            let __sandbox_tx_anchor_fields: Vec<(
                anchor_lang::solana_program::pubkey::Pubkey, u64
            )> = Vec::new();
        };
    }

    // Build the field snapshot expressions for the "first invocation" branch.
    // Each expression reads the current value of an account field and produces
    // a (Pubkey, u64) tuple.
    let snapshot_exprs: Vec<TokenStream> = fields
        .iter()
        .map(|field| {
            let account_ident = format_ident!("{}", field.account_name);
            let field_ident = format_ident!("{}", field.field_path);

            // We read the field value from the deserialized Anchor account.
            // The account key provides the Pubkey for the anchor entry.
            // NOTE: This assumes the account is accessible via `ctx.accounts.<name>`
            // and the field is a simple u64 (the most common case for tx anchors).
            quote! {
                (
                    *ctx.accounts.#account_ident.to_account_info().key,
                    ctx.accounts.#account_ident.#field_ident as u64,
                )
            }
        })
        .collect();

    let field_count = fields.len();

    quote! {
        // ── Step [5]: Transaction-level snapshot ──
        // Get the Instructions sysvar account (must be included in tx accounts)
        let __sandbox_ix_sysvar = {
            let ix_sysvar_id = anchor_lang::solana_program::sysvar::instructions::ID;
            let mut found: Option<&anchor_lang::solana_program::account_info::AccountInfo> = None;
            for ai in accounts.iter() {
                if ai.key == &ix_sysvar_id {
                    found = Some(ai);
                    break;
                }
            }
            found.ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(
                6073u32, // SnapshotFailed — Instructions sysvar not provided
            ))?
        };

        // Compute deterministic transaction fingerprint
        let __sandbox_tx_fingerprint: [u8; 32] =
            perk_sandbox_runtime::tx_anchor::compute_tx_fingerprint(__sandbox_ix_sysvar)?;

        // Check if this is the first sandbox invocation in this transaction
        let __sandbox_pda_anchor_data = {
            let pda_data = __sandbox_pda_info.try_borrow_data()
                .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(6073u32))?;
            // Read from the tx_anchor section offset in the PDA
            let anchor_offset = __sandbox_tx_anchor_offset as usize;
            if anchor_offset == 0 || anchor_offset >= pda_data.len() {
                return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6071u32));
            }
            pda_data[anchor_offset..].to_vec()
        };

        let __sandbox_is_first_ix: bool =
            perk_sandbox_runtime::tx_anchor::is_first_sandbox_invocation(
                &__sandbox_pda_anchor_data,
                &__sandbox_tx_fingerprint,
            );

        let __sandbox_tx_anchor_fields: Vec<(anchor_lang::solana_program::pubkey::Pubkey, u64)> =
            if __sandbox_is_first_ix {
                // First invocation: snapshot current field values
                let snapshot_fields: Vec<(anchor_lang::solana_program::pubkey::Pubkey, u64)> = vec![
                    #(#snapshot_exprs),*
                ];

                // Write to PDA anchor section
                {
                    let mut pda_data = __sandbox_pda_info.try_borrow_mut_data()
                        .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(
                            6073u32,
                        ))?;
                    let anchor_offset = __sandbox_tx_anchor_offset as usize;
                    perk_sandbox_runtime::tx_anchor::write_anchor_snapshot(
                        &mut pda_data[anchor_offset..],
                        &__sandbox_tx_fingerprint,
                        &snapshot_fields,
                    );
                }

                snapshot_fields
            } else {
                // Subsequent invocation: read existing anchor snapshot
                perk_sandbox_runtime::tx_anchor::read_anchor_snapshot(
                    &__sandbox_pda_anchor_data,
                )?
            };

        // Sanity check: field count matches expected
        if __sandbox_tx_anchor_fields.len() != #field_count {
            anchor_lang::prelude::msg!(
                "PERK_SANDBOX:type=anchor_field_count_mismatch,expected={},got={}",
                #field_count,
                __sandbox_tx_anchor_fields.len()
            );
            return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6071u32));
        }
    }
}

// ── Step [8c]: Cumulative decrease check ─────────────────────────────────────

/// Generate the tx cumulative decrease check code that runs at step [8c].
///
/// This compares the current value of a field against the transaction-start
/// anchor value and enforces that the cumulative decrease across all
/// instructions in this transaction doesn't exceed `max_pct` percent.
///
/// **Always runs** — even during emergency bypass (spec §9.1).
///
/// # Parameters
/// - `field`: the anchor field to check
/// - `max_pct`: maximum allowed decrease percentage (0 = monotonic, no decrease)
///
/// # Assumptions
/// - `__sandbox_tx_anchor_fields` is in scope (from `generate_tx_anchor_setup`)
/// - The account is still accessible via `ctx.accounts.<name>`
pub fn generate_tx_cumulative_decrease_check(
    field: &TxAnchorField,
    max_pct: u8,
) -> TokenStream {
    let account_ident = format_ident!("{}", field.account_name);
    let field_ident = format_ident!("{}", field.field_path);
    let field_desc = format!("{}.{}", field.account_name, field.field_path);
    let max_pct_lit = max_pct;

    quote! {
        // ── Step [8c]: tx_cumulative_decrease check for #field_desc ──
        {
            let __current_value: u64 = ctx.accounts.#account_ident.#field_ident as u64;

            // Find the anchor value for this account
            let __account_key = *ctx.accounts.#account_ident.to_account_info().key;
            let __anchor_value: u64 = __sandbox_tx_anchor_fields
                .iter()
                .find(|(pk, _)| pk == &__account_key)
                .map(|(_, v)| *v)
                .ok_or_else(|| {
                    anchor_lang::prelude::msg!(
                        "PERK_SANDBOX:type=anchor_field_missing,field={}",
                        #field_desc
                    );
                    anchor_lang::solana_program::program_error::ProgramError::Custom(6071u32)
                })?;

            // Check cumulative decrease is within bounds
            perk_sandbox_runtime::tx_anchor::check_tx_cumulative_decrease(
                __anchor_value,
                __current_value,
                #max_pct_lit,
            ).map_err(|e| {
                anchor_lang::prelude::msg!(
                    "PERK_SANDBOX:type=tx_cumulative_decrease_exceeded,field={},anchor={},current={},max_pct={}",
                    #field_desc,
                    __anchor_value,
                    __current_value,
                    #max_pct_lit,
                );
                e
            })?;
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Parse a `tx_cumulative_decrease` invariant attribute into its components.
///
/// Expected format: `tx_cumulative_decrease(field = "account.field", max_pct = N)`
///
/// Returns `(TxAnchorField, u8)` — the field config and max percentage.
pub fn parse_tx_cumulative_decrease(
    tokens: proc_macro2::TokenStream,
) -> Result<(TxAnchorField, u8), syn::Error> {
    use syn::parse::{Parse, ParseStream};
    use syn::{Ident, LitInt, LitStr, Token};

    struct TxCumDecreaseArgs {
        field: String,
        max_pct: u8,
    }

    impl Parse for TxCumDecreaseArgs {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            let mut field: Option<String> = None;
            let mut max_pct: Option<u8> = None;

            while !input.is_empty() {
                let key: Ident = input.parse()?;
                let _: Token![=] = input.parse()?;

                match key.to_string().as_str() {
                    "field" => {
                        let lit: LitStr = input.parse()?;
                        field = Some(lit.value());
                    }
                    "max_pct" => {
                        let lit: LitInt = input.parse()?;
                        max_pct = Some(lit.base10_parse()?);
                    }
                    other => {
                        return Err(syn::Error::new(
                            key.span(),
                            format!("unknown parameter '{other}' in tx_cumulative_decrease"),
                        ));
                    }
                }

                // Optional trailing comma
                if input.peek(Token![,]) {
                    let _: Token![,] = input.parse()?;
                }
            }

            let field_str = field.ok_or_else(|| {
                syn::Error::new(
                    proc_macro2::Span::call_site(),
                    "tx_cumulative_decrease requires 'field' parameter",
                )
            })?;

            let max_pct_val = max_pct.ok_or_else(|| {
                syn::Error::new(
                    proc_macro2::Span::call_site(),
                    "tx_cumulative_decrease requires 'max_pct' parameter",
                )
            })?;

            Ok(TxCumDecreaseArgs {
                field: field_str,
                max_pct: max_pct_val,
            })
        }
    }

    let args: TxCumDecreaseArgs = syn::parse2(tokens)?;

    // Split "account.field" into account_name and field_path
    let parts: Vec<&str> = args.field.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            format!(
                "tx_cumulative_decrease field must be 'account.field', got '{}'",
                args.field
            ),
        ));
    }

    let anchor_field = TxAnchorField {
        account_name: parts[0].to_string(),
        field_path: parts[1].to_string(),
        field_type: "u64".to_string(), // tx anchors are always u64
    };

    Ok((anchor_field, args.max_pct))
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── TxAnchorField construction ──────────────────────────────────────

    #[test]
    fn tx_anchor_field_basic() {
        let field = TxAnchorField {
            account_name: "market".into(),
            field_path: "vault_balance".into(),
            field_type: "u64".into(),
        };
        assert_eq!(field.account_name, "market");
        assert_eq!(field.field_path, "vault_balance");
        assert_eq!(field.field_type, "u64");
    }

    // ── generate_tx_anchor_setup ────────────────────────────────────────

    #[test]
    fn setup_empty_fields_produces_noop() {
        let tokens = generate_tx_anchor_setup(&[]);
        let code = tokens.to_string();
        // Should produce zero-initialized bindings
        assert!(
            code.contains("__sandbox_tx_fingerprint"),
            "should declare fingerprint binding"
        );
        assert!(
            code.contains("__sandbox_is_first_ix"),
            "should declare first-ix binding"
        );
        assert!(
            code.contains("__sandbox_tx_anchor_fields"),
            "should declare anchor fields binding"
        );
        // Should NOT contain runtime calls
        assert!(
            !code.contains("compute_tx_fingerprint"),
            "empty fields should not call compute_tx_fingerprint"
        );
    }

    #[test]
    fn setup_single_field_generates_runtime_calls() {
        let fields = vec![TxAnchorField {
            account_name: "market".into(),
            field_path: "vault_balance".into(),
            field_type: "u64".into(),
        }];
        let tokens = generate_tx_anchor_setup(&fields);
        let code = tokens.to_string();

        assert!(
            code.contains("compute_tx_fingerprint"),
            "should call compute_tx_fingerprint"
        );
        assert!(
            code.contains("is_first_sandbox_invocation"),
            "should call is_first_sandbox_invocation"
        );
        assert!(
            code.contains("write_anchor_snapshot"),
            "should call write_anchor_snapshot on first ix"
        );
        assert!(
            code.contains("read_anchor_snapshot"),
            "should call read_anchor_snapshot on subsequent ix"
        );
        assert!(
            code.contains("vault_balance"),
            "should reference the field"
        );
    }

    #[test]
    fn setup_multiple_fields_generates_all_snapshots() {
        let fields = vec![
            TxAnchorField {
                account_name: "market".into(),
                field_path: "vault_balance".into(),
                field_type: "u64".into(),
            },
            TxAnchorField {
                account_name: "market".into(),
                field_path: "total_long_collateral".into(),
                field_type: "u64".into(),
            },
        ];
        let tokens = generate_tx_anchor_setup(&fields);
        let code = tokens.to_string();

        assert!(code.contains("vault_balance"), "should snapshot vault_balance");
        assert!(
            code.contains("total_long_collateral"),
            "should snapshot total_long_collateral"
        );
        // Field count check
        assert!(code.contains("2"), "should check for 2 fields");
    }

    // ── generate_tx_cumulative_decrease_check ───────────────────────────

    #[test]
    fn decrease_check_generates_runtime_call() {
        let field = TxAnchorField {
            account_name: "market".into(),
            field_path: "vault_balance".into(),
            field_type: "u64".into(),
        };
        let tokens = generate_tx_cumulative_decrease_check(&field, 15);
        let code = tokens.to_string();

        assert!(
            code.contains("check_tx_cumulative_decrease"),
            "should call check_tx_cumulative_decrease"
        );
        assert!(
            code.contains("__sandbox_tx_anchor_fields"),
            "should reference anchor fields"
        );
        assert!(
            code.contains("vault_balance"),
            "should reference the field"
        );
        assert!(
            code.contains("15"),
            "should include max_pct value"
        );
    }

    #[test]
    fn decrease_check_zero_pct_monotonic() {
        let field = TxAnchorField {
            account_name: "vault".into(),
            field_path: "balance".into(),
            field_type: "u64".into(),
        };
        let tokens = generate_tx_cumulative_decrease_check(&field, 0);
        let code = tokens.to_string();

        assert!(
            code.contains("check_tx_cumulative_decrease"),
            "should still call runtime check for monotonic"
        );
    }

    #[test]
    fn decrease_check_includes_logging() {
        let field = TxAnchorField {
            account_name: "market".into(),
            field_path: "vault_balance".into(),
            field_type: "u64".into(),
        };
        let tokens = generate_tx_cumulative_decrease_check(&field, 10);
        let code = tokens.to_string();

        assert!(
            code.contains("PERK_SANDBOX:type=tx_cumulative_decrease_exceeded"),
            "should log on violation"
        );
    }

    // ── parse_tx_cumulative_decrease ─────────────────────────────────────

    #[test]
    fn parse_valid_tx_cumulative_decrease() {
        let tokens: proc_macro2::TokenStream =
            quote! { field = "market.vault_balance", max_pct = 15 };
        let (field, max_pct) = parse_tx_cumulative_decrease(tokens).unwrap();
        assert_eq!(field.account_name, "market");
        assert_eq!(field.field_path, "vault_balance");
        assert_eq!(field.field_type, "u64");
        assert_eq!(max_pct, 15);
    }

    #[test]
    fn parse_tx_cumulative_decrease_reversed_params() {
        let tokens: proc_macro2::TokenStream =
            quote! { max_pct = 5, field = "pool.tvl" };
        let (field, max_pct) = parse_tx_cumulative_decrease(tokens).unwrap();
        assert_eq!(field.account_name, "pool");
        assert_eq!(field.field_path, "tvl");
        assert_eq!(max_pct, 5);
    }

    #[test]
    fn parse_tx_cumulative_decrease_zero_pct() {
        let tokens: proc_macro2::TokenStream =
            quote! { field = "vault.balance", max_pct = 0 };
        let (_, max_pct) = parse_tx_cumulative_decrease(tokens).unwrap();
        assert_eq!(max_pct, 0);
    }

    #[test]
    fn parse_tx_cumulative_decrease_missing_field() {
        let tokens: proc_macro2::TokenStream = quote! { max_pct = 10 };
        let err = parse_tx_cumulative_decrease(tokens).unwrap_err();
        assert!(
            err.to_string().contains("field"),
            "should mention missing 'field': {}",
            err
        );
    }

    #[test]
    fn parse_tx_cumulative_decrease_missing_max_pct() {
        let tokens: proc_macro2::TokenStream =
            quote! { field = "market.vault_balance" };
        let err = parse_tx_cumulative_decrease(tokens).unwrap_err();
        assert!(
            err.to_string().contains("max_pct"),
            "should mention missing 'max_pct': {}",
            err
        );
    }

    #[test]
    fn parse_tx_cumulative_decrease_no_dot_in_field() {
        let tokens: proc_macro2::TokenStream =
            quote! { field = "vault_balance", max_pct = 10 };
        let err = parse_tx_cumulative_decrease(tokens).unwrap_err();
        assert!(
            err.to_string().contains("account.field"),
            "should explain format: {}",
            err
        );
    }

    #[test]
    fn parse_tx_cumulative_decrease_unknown_param() {
        let tokens: proc_macro2::TokenStream =
            quote! { field = "market.vault", max_pct = 10, bogus = 42 };
        let err = parse_tx_cumulative_decrease(tokens).unwrap_err();
        assert!(
            err.to_string().contains("bogus"),
            "should mention unknown param: {}",
            err
        );
    }

    #[test]
    fn parse_tx_cumulative_decrease_trailing_comma() {
        // Trailing comma should be fine
        let tokens: proc_macro2::TokenStream =
            quote! { field = "market.vault_balance", max_pct = 15, };
        let result = parse_tx_cumulative_decrease(tokens);
        assert!(result.is_ok(), "trailing comma should be accepted");
    }
}

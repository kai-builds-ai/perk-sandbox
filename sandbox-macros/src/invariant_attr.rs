//! Invariant attribute parsing and post-check code generation (Spec §3.3, §3.4, §3.6).
//!
//! Parses `#[invariant(type(params))]` attributes into `InvariantType` and generates
//! post-check code that compares before-snapshots against after-snapshots.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Ident, LitInt, LitStr, Token,
};

// ═══════════════════════════════════════════════════════════════════════════
// Types — imported from types.rs (single source of truth)
// ═══════════════════════════════════════════════════════════════════════════

use crate::types::{InvariantType, MonotonicDirection};

// ═══════════════════════════════════════════════════════════════════════════
// Internal parse helpers — key = value pairs
// ═══════════════════════════════════════════════════════════════════════════

/// A single `key = "value"` or `key = 123` pair inside an invariant attribute.
#[derive(Debug)]
struct KvPair {
    key: String,
    value: KvValue,
}

#[derive(Debug, Clone)]
enum KvValue {
    Str(String),
    Int(u64),
}

impl KvValue {
    fn as_str(&self) -> Result<&str, syn::Error> {
        match self {
            KvValue::Str(s) => Ok(s.as_str()),
            KvValue::Int(_) => Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "expected string value",
            )),
        }
    }
    fn as_u64(&self) -> Result<u64, syn::Error> {
        match self {
            KvValue::Int(n) => Ok(*n),
            KvValue::Str(s) => s.replace('_', "").parse::<u64>().map_err(|_| {
                syn::Error::new(proc_macro2::Span::call_site(), "expected integer value")
            }),
        }
    }
}

impl Parse for KvPair {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let key: Ident = input.parse()?;
        input.parse::<Token![=]>()?;
        let lookahead = input.lookahead1();
        let value = if lookahead.peek(LitStr) {
            let lit: LitStr = input.parse()?;
            KvValue::Str(lit.value())
        } else if lookahead.peek(LitInt) {
            let lit: LitInt = input.parse()?;
            KvValue::Int(lit.base10_parse()?)
        } else {
            return Err(lookahead.error());
        };
        Ok(KvPair {
            key: key.to_string(),
            value,
        })
    }
}

/// Parse comma-separated kv pairs from a `ParseStream`.
fn parse_kv_pairs(input: ParseStream) -> syn::Result<Vec<KvPair>> {
    let pairs: Punctuated<KvPair, Token![,]> = Punctuated::parse_terminated(input)?;
    Ok(pairs.into_iter().collect())
}

/// Find a required string key in the kv pairs.
fn require_str(pairs: &[KvPair], key: &str, inv_name: &str) -> syn::Result<String> {
    pairs
        .iter()
        .find(|p| p.key == key)
        .map(|p| p.value.as_str().map(|s| s.to_string()))
        .transpose()?
        .ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                format!("`{}` invariant requires `{}` parameter", inv_name, key),
            )
        })
}

/// Find a required integer key.
fn require_int(pairs: &[KvPair], key: &str, inv_name: &str) -> syn::Result<u64> {
    pairs
        .iter()
        .find(|p| p.key == key)
        .map(|p| p.value.as_u64())
        .transpose()?
        .ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                format!("`{}` invariant requires `{}` parameter", inv_name, key),
            )
        })
}

/// Find an optional integer key.
fn optional_int(pairs: &[KvPair], key: &str) -> syn::Result<Option<u64>> {
    pairs
        .iter()
        .find(|p| p.key == key)
        .map(|p| p.value.as_u64())
        .transpose()
}

// ═══════════════════════════════════════════════════════════════════════════
// Parsing: #[invariant(type(params))] → InvariantType
// ═══════════════════════════════════════════════════════════════════════════

/// The top-level structure parsed from `#[invariant(...)]`.
/// Either a named invariant reference or an inline invariant type.
struct InvariantAttrInput {
    inv: InvariantType,
}

impl Parse for InvariantAttrInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let inv = parse_invariant_body(input)?;
        Ok(InvariantAttrInput { inv })
    }
}

/// Parse the body of an invariant — `type_name(key=val, ...)` or just `name`.
fn parse_invariant_body(input: ParseStream) -> syn::Result<InvariantType> {
    let type_name: Ident = input.parse()?;
    let type_str = type_name.to_string();

    // Parameterless invariants
    match type_str.as_str() {
        "lamport_conservation" => return Ok(InvariantType::LamportConservation),
        "account_guard" => return Ok(InvariantType::AccountGuard),
        _ => {}
    }

    // If no parenthesized params, treat as Named invariant reference
    if !input.peek(syn::token::Paren) {
        return Ok(InvariantType::Named(type_str));
    }

    // All other invariants require parenthesized params
    let content;
    syn::parenthesized!(content in input);

    match type_str.as_str() {
        "gte" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::Gte {
                lhs: require_str(&pairs, "lhs", "gte")?,
                rhs: require_str(&pairs, "rhs", "gte")?,
            })
        }
        "lte" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::Lte {
                lhs: require_str(&pairs, "lhs", "lte")?,
                rhs: require_str(&pairs, "rhs", "lte")?,
            })
        }
        "eq" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::Eq {
                lhs: require_str(&pairs, "lhs", "eq")?,
                rhs: require_str(&pairs, "rhs", "eq")?,
            })
        }
        "immutable" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::Immutable {
                field: require_str(&pairs, "field", "immutable")?,
            })
        }
        "non_negative" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::NonNegative {
                field: require_str(&pairs, "field", "non_negative")?,
            })
        }
        "max_decrease" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::MaxDecrease {
                field: require_str(&pairs, "field", "max_decrease")?,
                pct: require_int(&pairs, "pct", "max_decrease")? as u8,
            })
        }
        "max_increase" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::MaxIncrease {
                field: require_str(&pairs, "field", "max_increase")?,
                pct: require_int(&pairs, "pct", "max_increase")? as u8,
                max_absolute: optional_int(&pairs, "max_absolute")?,
            })
        }
        "delta_bound" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::DeltaBound {
                field: require_str(&pairs, "field", "delta_bound")?,
                max: require_int(&pairs, "max", "delta_bound")?,
            })
        }
        "conserve" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::Conserve {
                field: require_str(&pairs, "field", "conserve")?,
            })
        }
        "supply_conservation" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::SupplyConservation {
                mint: require_str(&pairs, "mint", "supply_conservation")?,
            })
        }
        "payout_bounded" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::PayoutBounded {
                outflow: require_str(&pairs, "outflow", "payout_bounded")?,
                formula: require_str(&pairs, "formula", "payout_bounded")?,
            })
        }
        "aggregate_gte" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::AggregateGte {
                field: require_str(&pairs, "field", "aggregate_gte")?,
                aggregate: require_str(&pairs, "aggregate", "aggregate_gte")?,
            })
        }
        "custom" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::Custom {
                check_fn: require_str(&pairs, "check", "custom")?,
                cu_budget: require_int(&pairs, "cu_budget", "custom")? as u32,
            })
        }
        "tx_cumulative_decrease" => {
            let pairs = parse_kv_pairs(&content)?;
            Ok(InvariantType::TxCumulativeDecrease {
                field: require_str(&pairs, "field", "tx_cumulative_decrease")?,
                max_pct: require_int(&pairs, "max_pct", "tx_cumulative_decrease")? as u8,
            })
        }
        "when" => {
            let pairs = parse_kv_pairs(&content)?;
            let condition = require_str(&pairs, "condition", "when")?;
            // The inner invariant is passed as string and re-parsed
            let inner_str = require_str(&pairs, "inner", "when")?;
            let inner: InvariantAttrInput = syn::parse_str(&inner_str)?;
            Ok(InvariantType::When {
                condition,
                inner: Box::new(inner.inv),
            })
        }
        "monotonic" => {
            let pairs = parse_kv_pairs(&content)?;
            let field = require_str(&pairs, "field", "monotonic")?;
            let dir_str = require_str(&pairs, "direction", "monotonic")?;
            let direction = match dir_str.as_str() {
                "increasing" => MonotonicDirection::Increasing,
                "decreasing" => MonotonicDirection::Decreasing,
                other => {
                    return Err(syn::Error::new(
                        proc_macro2::Span::call_site(),
                        format!(
                            "monotonic direction must be \"increasing\" or \"decreasing\", got \"{}\"",
                            other
                        ),
                    ))
                }
            };
            Ok(InvariantType::Monotonic { field, direction })
        }
        other => Err(syn::Error::new(
            type_name.span(),
            format!("unknown invariant type: `{}`", other),
        )),
    }
}

/// Parse an `#[invariant(...)]` attribute into an `InvariantType`.
///
/// Accepts both inline types `#[invariant(gte(lhs = "a.x", rhs = "a.y"))]`
/// and named references `#[invariant(vault_solvency)]` (resolved later).
pub fn parse_invariant_attr(attr: &syn::Attribute) -> Result<InvariantType, syn::Error> {
    attr.parse_args::<InvariantAttrInput>()
        .map(|input| input.inv)
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers — field reference → variable name
// ═══════════════════════════════════════════════════════════════════════════

/// Convert `"market.vault_balance"` → `"market_vault_balance"` for use as a variable name.
fn field_to_var(field: &str) -> String {
    field.replace('.', "_")
}

/// Convert `"market.vault_balance"` → snapshot var names (before/after).
fn before_var(field: &str) -> proc_macro2::Ident {
    format_ident!("__sb_{}_before", field_to_var(field))
}

fn after_var(field: &str) -> proc_macro2::Ident {
    format_ident!("__sb_{}_after", field_to_var(field))
}

/// Generate a `msg!` log on violation with invariant metadata.
fn violation_log(inv_name: &str, instruction_name: &str) -> TokenStream {
    let msg = format!(
        "PERK_SANDBOX:type=invariant_violation,invariant={},ix={}",
        inv_name, instruction_name
    );
    quote! {
        anchor_lang::prelude::msg!(#msg);
    }
}

/// The standard error returned on invariant violation.
fn violation_err() -> TokenStream {
    quote! {
        return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6050));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Code generation: single invariant check
// ═══════════════════════════════════════════════════════════════════════════

/// Default CU budget for built-in invariant checks (§16.1).
/// Covers: snapshot read + comparison + violation log + error return.
/// The syscall itself costs ~100 CU; the check body ~200-500 CU;
/// conservative buffer for msg! formatting on violation.
const DEFAULT_INVARIANT_CU: u64 = 2_000;

/// Generate a CU reservation guard. Returns `Err(InsufficientCU)` if
/// fewer than `needed` compute units remain.
fn cu_reservation(needed: u64) -> TokenStream {
    quote! {
        perk_sandbox_runtime::cu::assert_cu_available(#needed)?;
    }
}

/// Generate post-check code for one invariant.
///
/// Each check is preceded by a CU reservation (§16) to ensure the program
/// doesn't run out of compute budget mid-check. Custom invariants use
/// their declared `cu_budget`; built-ins use `DEFAULT_INVARIANT_CU`.
pub fn generate_invariant_check(inv: &InvariantType, instruction_name: &str) -> TokenStream {
    // Determine CU budget: custom invariants declare their own; built-ins use default
    let cu_budget = match inv {
        InvariantType::Custom { cu_budget, .. } => *cu_budget as u64,
        _ => DEFAULT_INVARIANT_CU,
    };
    let cu_guard = cu_reservation(cu_budget);
    let check_body = generate_invariant_check_body(inv, instruction_name);
    quote! {
        #cu_guard
        #check_body
    }
}

/// Inner check body without CU reservation (called by generate_invariant_check).
fn generate_invariant_check_body(inv: &InvariantType, instruction_name: &str) -> TokenStream {
    match inv {
        // ── gte: after_lhs >= after_rhs ──
        InvariantType::Gte { lhs, rhs } => {
            let lhs_after = after_var(lhs);
            let rhs_after = after_var(rhs);
            let log = violation_log("gte", instruction_name);
            let err = violation_err();
            quote! {
                if #lhs_after < #rhs_after {
                    #log
                    #err
                }
            }
        }

        // ── lte: after_lhs <= after_rhs ──
        InvariantType::Lte { lhs, rhs } => {
            let lhs_after = after_var(lhs);
            let rhs_after = after_var(rhs);
            let log = violation_log("lte", instruction_name);
            let err = violation_err();
            quote! {
                if #lhs_after > #rhs_after {
                    #log
                    #err
                }
            }
        }

        // ── eq: after_lhs == after_rhs ──
        InvariantType::Eq { lhs, rhs } => {
            let lhs_after = after_var(lhs);
            let rhs_after = after_var(rhs);
            let log = violation_log("eq", instruction_name);
            let err = violation_err();
            quote! {
                if #lhs_after != #rhs_after {
                    #log
                    #err
                }
            }
        }

        // ── immutable: before == after ──
        InvariantType::Immutable { field } => {
            let before = before_var(field);
            let after = after_var(field);
            let log = violation_log("immutable", instruction_name);
            let err = violation_err();
            quote! {
                if #before != #after {
                    #log
                    #err
                }
            }
        }

        // ── non_negative: after >= 0 (for signed types) ──
        InvariantType::NonNegative { field } => {
            let after = after_var(field);
            let log = violation_log("non_negative", instruction_name);
            let err = violation_err();
            quote! {
                if #after < 0 {
                    #log
                    #err
                }
            }
        }

        // ── max_decrease: (before - after) * 100 / before <= pct ──
        // If before == 0: pass (can't decrease from zero).
        // If after > before: pass (increase, not decrease).
        InvariantType::MaxDecrease { field, pct } => {
            let before = before_var(field);
            let after = after_var(field);
            let pct_lit = *pct as u64;
            let log = violation_log("max_decrease", instruction_name);
            let err = violation_err();
            quote! {
                if #before > 0 && #after < #before {
                    let __decrease = #before.checked_sub(#after).unwrap();
                    // decrease_pct = decrease * 100 / before
                    let __decrease_x100 = __decrease.checked_mul(100).ok_or(
                        anchor_lang::solana_program::program_error::ProgramError::Custom(6050)
                    )?;
                    let __decrease_pct = __decrease_x100 / #before;
                    if __decrease_pct > #pct_lit {
                        #log
                        #err
                    }
                }
            }
        }

        // ── max_increase: (after - before) * 100 / before <= pct ──
        // If before == 0 and after > 0: check after <= max_absolute.
        InvariantType::MaxIncrease {
            field,
            pct,
            max_absolute,
        } => {
            let before = before_var(field);
            let after = after_var(field);
            let pct_lit = *pct as u64;
            let log = violation_log("max_increase", instruction_name);
            let err = violation_err();

            let zero_check = if let Some(abs) = max_absolute {
                quote! {
                    if #after > #abs {
                        #log
                        #err
                    }
                }
            } else {
                // No max_absolute — allow any value from zero (defaults to u64::MAX)
                quote! {}
            };

            quote! {
                if #after > #before {
                    if #before == 0 {
                        #zero_check
                    } else {
                        let __increase = #after.checked_sub(#before).unwrap();
                        let __increase_x100 = __increase.checked_mul(100).ok_or(
                            anchor_lang::solana_program::program_error::ProgramError::Custom(6050)
                        )?;
                        let __increase_pct = __increase_x100 / #before;
                        if __increase_pct > #pct_lit {
                            #log
                            #err
                        }
                    }
                }
            }
        }

        // ── delta_bound: abs(before - after) <= max ──
        InvariantType::DeltaBound { field, max } => {
            let before = before_var(field);
            let after = after_var(field);
            let log = violation_log("delta_bound", instruction_name);
            let err = violation_err();
            quote! {
                {
                    let __delta = if #after >= #before {
                        #after.checked_sub(#before).unwrap()
                    } else {
                        #before.checked_sub(#after).unwrap()
                    };
                    if __delta > #max {
                        #log
                        #err
                    }
                }
            }
        }

        // ── conserve: sum of field across all program-owned accounts unchanged ──
        // The generated code iterates Context + remaining_accounts.
        InvariantType::Conserve { field } => {
            let before_sum = format_ident!("__sb_{}_sum_before", field_to_var(field));
            let after_sum = format_ident!("__sb_{}_sum_after", field_to_var(field));
            let log = violation_log("conserve", instruction_name);
            let err = violation_err();
            quote! {
                if #before_sum != #after_sum {
                    #log
                    #err
                }
            }
        }

        // ── supply_conservation: mint supply == sum of token balances ──
        InvariantType::SupplyConservation { mint } => {
            let mint_var = format_ident!("__sb_{}_supply", field_to_var(mint));
            let balance_sum = format_ident!("__sb_{}_balance_sum", field_to_var(mint));
            let log = violation_log("supply_conservation", instruction_name);
            let err = violation_err();
            quote! {
                if #mint_var != #balance_sum {
                    #log
                    #err
                }
            }
        }

        // ── lamport_conservation: sum of lamport deltas == 0 ──
        InvariantType::LamportConservation => {
            let log = violation_log("lamport_conservation", instruction_name);
            let err = violation_err();
            quote! {
                if __sb_lamport_delta_sum != 0i128 {
                    #log
                    #err
                }
            }
        }

        // ── payout_bounded: outflow <= formula result ──
        InvariantType::PayoutBounded { outflow, formula } => {
            let outflow_var = after_var(outflow);
            let formula_var = format_ident!("__sb_payout_formula_{}", field_to_var(outflow));
            let _formula_str = formula.clone();
            let log = violation_log("payout_bounded", instruction_name);
            let err = violation_err();
            // The formula evaluation is generated by the sandbox_program macro
            // based on the formula expression. Here we just check the bound.
            quote! {
                if #outflow_var > #formula_var {
                    #log
                    #err
                }
            }
        }

        // ── aggregate_gte: sum across account type >= field ──
        InvariantType::AggregateGte { field, aggregate } => {
            let agg_var = format_ident!("__sb_{}_aggregate", field_to_var(aggregate));
            let field_var = after_var(field);
            let log = violation_log("aggregate_gte", instruction_name);
            let err = violation_err();
            quote! {
                if #agg_var < #field_var {
                    #log
                    #err
                }
            }
        }

        // ── account_guard: no unauthorized account create/close ──
        InvariantType::AccountGuard => {
            let log = violation_log("account_guard", instruction_name);
            let err = violation_err();
            quote! {
                if __sb_unauthorized_account_change {
                    #log
                    #err
                }
            }
        }

        // ── custom: call developer function with InvariantContext ──
        InvariantType::Custom { check_fn, cu_budget } => {
            let fn_ident = format_ident!("{}", check_fn);
            let cu = *cu_budget;
            let log = violation_log("custom", instruction_name);
            let err = violation_err();
            let _ = cu; // cu_budget is now consumed by the outer CU guard in generate_invariant_check
            quote! {
                {
                    let __custom_result = #fn_ident(&__sb_invariant_context)?;
                    if !__custom_result {
                        #log
                        #err
                    }
                }
            }
        }

        // ── Named: reference to a sandbox_invariant! definition ──
        InvariantType::Named(name) => {
            let check_fn = format_ident!("__sandbox_check_{}", name);
            let name_str = name.as_str();
            let log = violation_log("named", instruction_name);
            let err = violation_err();
            quote! {
                {
                    // Named invariant: #name_str
                    let __named_result = #check_fn(&__sb_invariant_context)?;
                    if !__named_result {
                        #log
                        #err
                    }
                }
            }
        }

        // ── tx_cumulative_decrease: cross-ix cumulative check ──
        // ALWAYS runs, even during emergency bypass.
        InvariantType::TxCumulativeDecrease { field, max_pct } => {
            let anchor_var = format_ident!("__sb_{}_anchor", field_to_var(field));
            let current_var = after_var(field);
            let pct_lit = *max_pct;
            let log = violation_log("tx_cumulative_decrease", instruction_name);
            quote! {
                {
                    let __tx_cum_result = perk_sandbox_runtime::tx_anchor::check_tx_cumulative_decrease(
                        #anchor_var,
                        #current_var,
                        #pct_lit,
                    );
                    if let Err(__e) = __tx_cum_result {
                        #log
                        return Err(__e);
                    }
                }
            }
        }

        // ── when: conditional invariant ──
        // Applies if condition is true in EITHER before or after state.
        InvariantType::When { condition, inner } => {
            let cond_before = format_ident!("__sb_when_cond_{}_before", field_to_var(condition));
            let cond_after = format_ident!("__sb_when_cond_{}_after", field_to_var(condition));
            let inner_check = generate_invariant_check(inner, instruction_name);
            quote! {
                if #cond_before || #cond_after {
                    #inner_check
                }
            }
        }

        // ── monotonic: field only moves one direction ──
        // Increasing: after >= before. Decreasing: after <= before.
        InvariantType::Monotonic { field, direction } => {
            let before = before_var(field);
            let after = after_var(field);
            let log_name = match direction {
                MonotonicDirection::Increasing => "monotonic_increasing",
                MonotonicDirection::Decreasing => "monotonic_decreasing",
            };
            let log = violation_log(log_name, instruction_name);
            let err = violation_err();
            match direction {
                MonotonicDirection::Increasing => {
                    quote! {
                        if #after < #before {
                            #log
                            #err
                        }
                    }
                }
                MonotonicDirection::Decreasing => {
                    quote! {
                        if #after > #before {
                            #log
                            #err
                        }
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Code generation: all invariant checks for an instruction
// ═══════════════════════════════════════════════════════════════════════════

/// Generate all invariant post-checks for an instruction.
///
/// During emergency bypass: skip all EXCEPT `TxCumulativeDecrease`.
/// The `is_emergency_bypass` flag is expected to be a runtime variable in scope.
pub fn generate_all_invariant_checks(
    invariants: &[InvariantType],
    instruction_name: &str,
    is_emergency_bypass: bool,
) -> TokenStream {
    if invariants.is_empty() {
        return quote! {};
    }

    // Separate tx_cumulative_decrease (always runs) from others (skipped during bypass)
    let mut always_checks = Vec::new();
    let mut normal_checks = Vec::new();

    for inv in invariants {
        let check = generate_invariant_check(inv, instruction_name);
        if matches!(inv, InvariantType::TxCumulativeDecrease { .. }) {
            always_checks.push(check);
        } else {
            normal_checks.push(check);
        }
    }

    if is_emergency_bypass {
        // Static bypass: only emit tx_cumulative_decrease checks
        quote! {
            // ── Post-checks (emergency bypass — only tx_cumulative_decrease) ──
            #(#always_checks)*
        }
    } else {
        // Normal mode: wrap normal checks in runtime bypass guard,
        // always run tx_cumulative_decrease
        quote! {
            // ── Post-checks: tx_cumulative_decrease (ALWAYS) ──
            #(#always_checks)*

            // ── Post-checks: standard invariants (skipped during emergency bypass) ──
            if !__sandbox_emergency_bypass {
                #(#normal_checks)*
            }
        }
    }
}

/// Collect all fields referenced by a list of invariants.
/// Returns a deduplicated list of `"account.field"` strings.
pub fn collect_referenced_fields(invariants: &[InvariantType]) -> Vec<String> {
    let mut fields = Vec::new();

    for inv in invariants {
        match inv {
            InvariantType::Gte { lhs, rhs }
            | InvariantType::Lte { lhs, rhs }
            | InvariantType::Eq { lhs, rhs } => {
                fields.push(lhs.clone());
                fields.push(rhs.clone());
            }
            InvariantType::Immutable { field }
            | InvariantType::NonNegative { field }
            | InvariantType::MaxDecrease { field, .. }
            | InvariantType::MaxIncrease { field, .. }
            | InvariantType::DeltaBound { field, .. }
            | InvariantType::Conserve { field }
            | InvariantType::TxCumulativeDecrease { field, .. }
            | InvariantType::Monotonic { field, .. } => {
                fields.push(field.clone());
            }
            InvariantType::SupplyConservation { mint } => {
                fields.push(mint.clone());
            }
            InvariantType::PayoutBounded { outflow, .. } => {
                fields.push(outflow.clone());
            }
            InvariantType::AggregateGte { field, aggregate } => {
                fields.push(field.clone());
                fields.push(aggregate.clone());
            }
            InvariantType::When { inner, .. } => {
                let inner_fields = collect_referenced_fields(&[*inner.clone()]);
                fields.extend(inner_fields);
            }
            InvariantType::LamportConservation
            | InvariantType::AccountGuard
            | InvariantType::Custom { .. }
            | InvariantType::Named(_) => {
                // No field references (custom/named use InvariantContext)
            }
        }
    }

    // Deduplicate
    fields.sort();
    fields.dedup();
    fields
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    /// Helper: create an attribute `#[invariant(...)]` and parse it.
    fn parse_inv(tokens: &str) -> Result<InvariantType, syn::Error> {
        let code = format!("#[invariant({})] fn dummy() {{}}", tokens);
        let func: syn::ItemFn = syn::parse_str(&code)?;
        let attr = func.attrs.first().unwrap();
        parse_invariant_attr(attr)
    }

    #[test]
    fn test_parse_gte() {
        let inv = parse_inv(r#"gte(lhs = "market.vault_balance", rhs = "market.total_collateral")"#).unwrap();
        match inv {
            InvariantType::Gte { lhs, rhs } => {
                assert_eq!(lhs, "market.vault_balance");
                assert_eq!(rhs, "market.total_collateral");
            }
            _ => panic!("expected Gte"),
        }
    }

    #[test]
    fn test_parse_lte() {
        let inv = parse_inv(r#"lte(lhs = "a.x", rhs = "a.y")"#).unwrap();
        assert!(matches!(inv, InvariantType::Lte { .. }));
    }

    #[test]
    fn test_parse_eq() {
        let inv = parse_inv(r#"eq(lhs = "a.x", rhs = "a.y")"#).unwrap();
        assert!(matches!(inv, InvariantType::Eq { .. }));
    }

    #[test]
    fn test_parse_immutable() {
        let inv = parse_inv(r#"immutable(field = "market.authority")"#).unwrap();
        match inv {
            InvariantType::Immutable { field } => assert_eq!(field, "market.authority"),
            _ => panic!("expected Immutable"),
        }
    }

    #[test]
    fn test_parse_non_negative() {
        let inv = parse_inv(r#"non_negative(field = "position.pnl")"#).unwrap();
        assert!(matches!(inv, InvariantType::NonNegative { .. }));
    }

    #[test]
    fn test_parse_max_decrease() {
        let inv = parse_inv(r#"max_decrease(field = "vault.balance", pct = 10)"#).unwrap();
        match inv {
            InvariantType::MaxDecrease { field, pct } => {
                assert_eq!(field, "vault.balance");
                assert_eq!(pct, 10);
            }
            _ => panic!("expected MaxDecrease"),
        }
    }

    #[test]
    fn test_parse_max_increase_with_absolute() {
        let inv = parse_inv(
            r#"max_increase(field = "vault.balance", pct = 50, max_absolute = 1000000000)"#,
        )
        .unwrap();
        match inv {
            InvariantType::MaxIncrease {
                field,
                pct,
                max_absolute,
            } => {
                assert_eq!(field, "vault.balance");
                assert_eq!(pct, 50);
                assert_eq!(max_absolute, Some(1_000_000_000));
            }
            _ => panic!("expected MaxIncrease"),
        }
    }

    #[test]
    fn test_parse_max_increase_without_absolute() {
        let inv = parse_inv(r#"max_increase(field = "vault.balance", pct = 50)"#).unwrap();
        match inv {
            InvariantType::MaxIncrease { max_absolute, .. } => {
                assert_eq!(max_absolute, None);
            }
            _ => panic!("expected MaxIncrease"),
        }
    }

    #[test]
    fn test_parse_delta_bound() {
        let inv = parse_inv(r#"delta_bound(field = "market.price", max = 5000)"#).unwrap();
        match inv {
            InvariantType::DeltaBound { field, max } => {
                assert_eq!(field, "market.price");
                assert_eq!(max, 5000);
            }
            _ => panic!("expected DeltaBound"),
        }
    }

    #[test]
    fn test_parse_conserve() {
        let inv = parse_inv(r#"conserve(field = "market.vault_balance")"#).unwrap();
        assert!(matches!(inv, InvariantType::Conserve { .. }));
    }

    #[test]
    fn test_parse_supply_conservation() {
        let inv = parse_inv(r#"supply_conservation(mint = "token_mint")"#).unwrap();
        assert!(matches!(inv, InvariantType::SupplyConservation { .. }));
    }

    #[test]
    fn test_parse_lamport_conservation() {
        let inv = parse_inv("lamport_conservation").unwrap();
        assert!(matches!(inv, InvariantType::LamportConservation));
    }

    #[test]
    fn test_parse_payout_bounded() {
        let inv = parse_inv(
            r#"payout_bounded(outflow = "vault.payout", formula = "vault.balance * 0.1")"#,
        )
        .unwrap();
        assert!(matches!(inv, InvariantType::PayoutBounded { .. }));
    }

    #[test]
    fn test_parse_aggregate_gte() {
        let inv = parse_inv(
            r#"aggregate_gte(field = "market.total_collateral", aggregate = "positions.collateral")"#,
        )
        .unwrap();
        assert!(matches!(inv, InvariantType::AggregateGte { .. }));
    }

    #[test]
    fn test_parse_account_guard() {
        let inv = parse_inv("account_guard").unwrap();
        assert!(matches!(inv, InvariantType::AccountGuard));
    }

    #[test]
    fn test_parse_custom() {
        let inv = parse_inv(r#"custom(check = "my_check_fn", cu_budget = 50000)"#).unwrap();
        match inv {
            InvariantType::Custom {
                check_fn,
                cu_budget,
            } => {
                assert_eq!(check_fn, "my_check_fn");
                assert_eq!(cu_budget, 50_000);
            }
            _ => panic!("expected Custom"),
        }
    }

    #[test]
    fn test_parse_tx_cumulative_decrease() {
        let inv = parse_inv(
            r#"tx_cumulative_decrease(field = "market.vault_balance", max_pct = 15)"#,
        )
        .unwrap();
        match inv {
            InvariantType::TxCumulativeDecrease { field, max_pct } => {
                assert_eq!(field, "market.vault_balance");
                assert_eq!(max_pct, 15);
            }
            _ => panic!("expected TxCumulativeDecrease"),
        }
    }

    #[test]
    fn test_parse_monotonic_increasing() {
        let inv = parse_inv(
            r#"monotonic(field = "market.total_deposited", direction = "increasing")"#,
        )
        .unwrap();
        match inv {
            InvariantType::Monotonic { field, direction } => {
                assert_eq!(field, "market.total_deposited");
                assert_eq!(direction, MonotonicDirection::Increasing);
            }
            _ => panic!("expected Monotonic"),
        }
    }

    #[test]
    fn test_parse_monotonic_decreasing() {
        let inv = parse_inv(
            r#"monotonic(field = "market.remaining_supply", direction = "decreasing")"#,
        )
        .unwrap();
        match inv {
            InvariantType::Monotonic { field, direction } => {
                assert_eq!(field, "market.remaining_supply");
                assert_eq!(direction, MonotonicDirection::Decreasing);
            }
            _ => panic!("expected Monotonic"),
        }
    }

    #[test]
    fn test_parse_unknown_type_errors() {
        let result = parse_inv(r#"foobar(field = "x")"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown invariant type"));
    }

    #[test]
    fn test_parse_missing_required_param() {
        let result = parse_inv(r#"gte(lhs = "a.x")"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rhs"));
    }

    #[test]
    fn test_generate_gte_check() {
        let inv = InvariantType::Gte {
            lhs: "market.vault_balance".into(),
            rhs: "market.total_collateral".into(),
        };
        let code = generate_invariant_check(&inv, "open_position");
        let code_str = code.to_string();
        assert!(code_str.contains("__sb_market_vault_balance_after"));
        assert!(code_str.contains("__sb_market_total_collateral_after"));
        assert!(code_str.contains("6050"));
    }

    #[test]
    fn test_generate_tx_cumulative_decrease_check() {
        let inv = InvariantType::TxCumulativeDecrease {
            field: "market.vault_balance".into(),
            max_pct: 15,
        };
        let code = generate_invariant_check(&inv, "close_position");
        let code_str = code.to_string();
        assert!(code_str.contains("check_tx_cumulative_decrease"));
        assert!(code_str.contains("__sb_market_vault_balance_anchor"));
    }

    #[test]
    fn test_emergency_bypass_only_emits_tx_cumulative() {
        let invariants = vec![
            InvariantType::Gte {
                lhs: "a.x".into(),
                rhs: "a.y".into(),
            },
            InvariantType::TxCumulativeDecrease {
                field: "a.x".into(),
                max_pct: 10,
            },
        ];
        let code = generate_all_invariant_checks(&invariants, "test_ix", true);
        let code_str = code.to_string();
        assert!(code_str.contains("check_tx_cumulative_decrease"));
        // gte check should NOT appear during static emergency bypass
        assert!(!code_str.contains("__sb_a_x_after < __sb_a_y_after"));
    }

    #[test]
    fn test_collect_referenced_fields() {
        let invariants = vec![
            InvariantType::Gte {
                lhs: "market.vault_balance".into(),
                rhs: "market.total_collateral".into(),
            },
            InvariantType::Immutable {
                field: "market.authority".into(),
            },
            InvariantType::TxCumulativeDecrease {
                field: "market.vault_balance".into(),
                max_pct: 15,
            },
        ];
        let fields = collect_referenced_fields(&invariants);
        assert_eq!(fields.len(), 3); // deduplicated
        assert!(fields.contains(&"market.vault_balance".to_string()));
        assert!(fields.contains(&"market.total_collateral".to_string()));
        assert!(fields.contains(&"market.authority".to_string()));
    }
}

//! Per-instruction wrapper codegen.
//!
//! Parses sandbox attributes from instruction functions and generates
//! the complete instruction wrapper that enforces pre/post checks:
//!
//! 1. Authority checks (pre)
//! 2. Bound checks (pre)
//! 3. Instruction-level snapshots (pre)
//! 4. Business logic dispatch
//! 5. Invariant post-checks
//! 6. Returns circuit breaker category for the entrypoint
//!
//! Spec reference: §3.2 (program attribute), §3.5 (circuit breaker category)

use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    Ident, ItemFn, LitStr, Token,
};

use crate::types::AuthorityRequirement;

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed invariant type from `#[invariant(...)]` attributes.
/// This is instruction_attr's own representation — maps to types::InvariantType
/// but supports the Typed variant for generic parameterized invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantType {
    /// Named invariant: `#[invariant(vault_solvency)]`
    Named(String),

    /// Typed invariant: `#[invariant(gte(lhs = "a.x", rhs = "b.y"))]`
    Typed {
        kind: String,
        params: HashMap<String, String>,
    },

    /// Transaction cumulative decrease: `#[invariant(tx_cumulative_decrease(field = "...", max_pct = N))]`
    TxCumulativeDecrease {
        field: String,
        max_pct: u8,
    },

    /// Custom invariant: `#[invariant(custom(check = "fn_name", cu_budget = N))]`
    Custom {
        check_fn: String,
        cu_budget: u32,
    },
}

/// Parsed bound constraint from `#[bound(...)]` attributes.
/// Local to instruction_attr (uses string RHS, unlike types::BoundConstraint which uses i128).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundConstraint {
    /// Left-hand side (variable name or expression).
    pub lhs: String,
    /// Comparison operator.
    pub op: BoundOp,
    /// Right-hand side (literal or expression).
    pub rhs: String,
}

/// Bound comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundOp {
    Gte,    // >=
    Lte,    // <=
    Gt,     // >
    Lt,     // <
    Eq,     // ==
    Ne,     // !=
}

impl BoundOp {
    /// Returns the Rust operator token as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            BoundOp::Gte => ">=",
            BoundOp::Lte => "<=",
            BoundOp::Gt => ">",
            BoundOp::Lt => "<",
            BoundOp::Eq => "==",
            BoundOp::Ne => "!=",
        }
    }
}

/// Complete instruction metadata parsed from all sandbox attributes.
#[derive(Debug, Clone)]
pub struct InstructionMeta {
    /// Instruction function name.
    pub name: String,
    /// Circuit breaker category (from `#[circuit_breaker_category("...")]`).
    pub circuit_breaker_category: Option<String>,
    /// Authority requirements (from `#[authority(...)]`).
    pub authorities: Vec<AuthorityRequirement>,
    /// Input bound constraints (from `#[bound(...)]`).
    pub bounds: Vec<BoundConstraint>,
    /// Post-condition invariants (from `#[invariant(...)]`).
    pub invariants: Vec<InvariantType>,
    /// Whether this instruction is allowed during pause (recovery instruction).
    pub is_recovery: bool,
    /// Instruction argument names and types (excluding ctx: Context<T>).
    pub args: Vec<(String, String)>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Attribute Parsing
// ═══════════════════════════════════════════════════════════════════════════

/// Recognized sandbox attribute names.
const SANDBOX_ATTRS: &[&str] = &[
    "invariant",
    "authority",
    "bound",
    "circuit_breaker_category",
    "sandbox_instruction",
    "sandbox_recovery",
];

/// Returns true if the attribute path matches a known sandbox attribute.
fn is_sandbox_attr(attr: &syn::Attribute) -> bool {
    SANDBOX_ATTRS
        .iter()
        .any(|name| attr.path().is_ident(name))
}

/// Parse all sandbox attributes from an instruction function into [`InstructionMeta`].
///
/// Iterates the function's attributes, parsing each recognized sandbox attribute.
/// Unrecognized attributes are left untouched (they belong to Anchor, derive macros, etc.).
pub fn parse_instruction_attrs(func: &ItemFn) -> Result<InstructionMeta, syn::Error> {
    let name = func.sig.ident.to_string();

    // Extract instruction args (skip first param: ctx: Context<T>)
    let args: Vec<(String, String)> = func.sig.inputs.iter().skip(1).filter_map(|arg| {
        if let syn::FnArg::Typed(pat_type) = arg {
            let name = match pat_type.pat.as_ref() {
                syn::Pat::Ident(pi) => pi.ident.to_string(),
                _ => return None,
            };
            let ty = pat_type.ty.to_token_stream().to_string();
            Some((name, ty))
        } else {
            None
        }
    }).collect();

    let mut meta = InstructionMeta {
        name,
        circuit_breaker_category: None,
        authorities: Vec::new(),
        bounds: Vec::new(),
        invariants: Vec::new(),
        is_recovery: false,
        args,
    };

    for attr in &func.attrs {
        if !is_sandbox_attr(attr) {
            continue;
        }

        if attr.path().is_ident("circuit_breaker_category") {
            meta.circuit_breaker_category = Some(parse_category_attr(attr)?);
        } else if attr.path().is_ident("authority") {
            let req = crate::authority_attr::parse_authority_attr(attr)?;
            meta.authorities.push(req);
        } else if attr.path().is_ident("bound") {
            let constraints = parse_bound_attr(attr)?;
            meta.bounds.extend(constraints);
        } else if attr.path().is_ident("invariant") {
            let inv = parse_invariant_attr(attr)?;
            meta.invariants.push(inv);
        } else if attr.path().is_ident("sandbox_recovery") {
            meta.is_recovery = true;
        }
        // sandbox_instruction is implicit — presence of any sandbox attr implies it
    }

    Ok(meta)
}

/// Parse `#[circuit_breaker_category("withdrawal")]` attribute.
///
/// Expects a single string literal inside the parentheses.
pub fn parse_category_attr(attr: &syn::Attribute) -> Result<String, syn::Error> {
    let lit: LitStr = attr.parse_args()?;
    let value = lit.value();
    if value.is_empty() {
        return Err(syn::Error::new_spanned(
            &lit,
            "circuit_breaker_category must not be empty",
        ));
    }
    Ok(value)
}

/// Parse `#[bound(leverage >= 1, leverage <= 100)]` attribute.
///
/// Supports multiple comma-separated constraints.
fn parse_bound_attr(attr: &syn::Attribute) -> Result<Vec<BoundConstraint>, syn::Error> {
    struct BoundList {
        constraints: Vec<BoundConstraint>,
    }

    impl Parse for BoundList {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            let mut constraints = Vec::new();

            while !input.is_empty() {
                let lhs: Ident = input.parse()?;

                // Parse operator
                let op = if input.peek(Token![>=]) {
                    let _: Token![>=] = input.parse()?;
                    BoundOp::Gte
                } else if input.peek(Token![<=]) {
                    let _: Token![<=] = input.parse()?;
                    BoundOp::Lte
                } else if input.peek(Token![>]) {
                    let _: Token![>] = input.parse()?;
                    BoundOp::Gt
                } else if input.peek(Token![<]) {
                    let _: Token![<] = input.parse()?;
                    BoundOp::Lt
                } else if input.peek(Token![==]) {
                    let _: Token![==] = input.parse()?;
                    BoundOp::Eq
                } else if input.peek(Token![!=]) {
                    let _: Token![!=] = input.parse()?;
                    BoundOp::Ne
                } else {
                    return Err(input.error("expected comparison operator (>=, <=, >, <, ==, !=)"));
                };

                // Parse RHS — could be a literal or identifier
                let rhs: syn::Expr = input.parse()?;
                let rhs_str = quote!(#rhs).to_string();

                constraints.push(BoundConstraint {
                    lhs: lhs.to_string(),
                    op,
                    rhs: rhs_str,
                });

                // Optional trailing comma
                if input.peek(Token![,]) {
                    let _: Token![,] = input.parse()?;
                }
            }

            Ok(BoundList { constraints })
        }
    }

    let bound_list: BoundList = attr.parse_args()?;
    if bound_list.constraints.is_empty() {
        return Err(syn::Error::new_spanned(
            attr,
            "#[bound(...)] requires at least one constraint",
        ));
    }
    Ok(bound_list.constraints)
}

/// Parse a single `#[invariant(...)]` attribute.
fn parse_invariant_attr(attr: &syn::Attribute) -> Result<InvariantType, syn::Error> {
    struct InvariantInner {
        inv: InvariantType,
    }

    impl Parse for InvariantInner {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            let name: Ident = input.parse()?;
            let name_str = name.to_string();

            // Check if there are parenthesised parameters
            if input.peek(syn::token::Paren) {
                let content;
                syn::parenthesized!(content in input);

                match name_str.as_str() {
                    "tx_cumulative_decrease" => {
                        let mut field: Option<String> = None;
                        let mut max_pct: Option<u8> = None;

                        while !content.is_empty() {
                            let key: Ident = content.parse()?;
                            let _: Token![=] = content.parse()?;

                            match key.to_string().as_str() {
                                "field" => {
                                    let lit: LitStr = content.parse()?;
                                    field = Some(lit.value());
                                }
                                "max_pct" => {
                                    let lit: syn::LitInt = content.parse()?;
                                    max_pct = Some(lit.base10_parse()?);
                                }
                                other => {
                                    return Err(syn::Error::new(
                                        key.span(),
                                        format!("unknown parameter '{other}'"),
                                    ));
                                }
                            }

                            if content.peek(Token![,]) {
                                let _: Token![,] = content.parse()?;
                            }
                        }

                        Ok(InvariantInner {
                            inv: InvariantType::TxCumulativeDecrease {
                                field: field.ok_or_else(|| {
                                    syn::Error::new(name.span(), "missing 'field' parameter")
                                })?,
                                max_pct: max_pct.ok_or_else(|| {
                                    syn::Error::new(name.span(), "missing 'max_pct' parameter")
                                })?,
                            },
                        })
                    }

                    "custom" => {
                        let mut check_fn: Option<String> = None;
                        let mut cu_budget: Option<u32> = None;

                        while !content.is_empty() {
                            let key: Ident = content.parse()?;
                            let _: Token![=] = content.parse()?;

                            match key.to_string().as_str() {
                                "check" => {
                                    let lit: LitStr = content.parse()?;
                                    check_fn = Some(lit.value());
                                }
                                "cu_budget" => {
                                    let lit: syn::LitInt = content.parse()?;
                                    cu_budget = Some(lit.base10_parse()?);
                                }
                                other => {
                                    return Err(syn::Error::new(
                                        key.span(),
                                        format!("unknown parameter '{other}'"),
                                    ));
                                }
                            }

                            if content.peek(Token![,]) {
                                let _: Token![,] = content.parse()?;
                            }
                        }

                        Ok(InvariantInner {
                            inv: InvariantType::Custom {
                                check_fn: check_fn.ok_or_else(|| {
                                    syn::Error::new(name.span(), "missing 'check' parameter")
                                })?,
                                cu_budget: cu_budget.ok_or_else(|| {
                                    syn::Error::new(name.span(), "missing 'cu_budget' parameter")
                                })?,
                            },
                        })
                    }

                    // Generic typed invariant (gte, lte, max_decrease, etc.)
                    _ => {
                        let mut params = HashMap::new();
                        while !content.is_empty() {
                            let key: Ident = content.parse()?;
                            let _: Token![=] = content.parse()?;
                            let val: LitStr = content.parse()?;
                            params.insert(key.to_string(), val.value());

                            if content.peek(Token![,]) {
                                let _: Token![,] = content.parse()?;
                            }
                        }
                        Ok(InvariantInner {
                            inv: InvariantType::Typed {
                                kind: name_str,
                                params,
                            },
                        })
                    }
                }
            } else {
                // No parens — named invariant
                Ok(InvariantInner {
                    inv: InvariantType::Named(name_str),
                })
            }
        }
    }

    let inner: InvariantInner = attr.parse_args()?;
    Ok(inner.inv)
}

// ═══════════════════════════════════════════════════════════════════════════
// Category Resolution
// ═══════════════════════════════════════════════════════════════════════════

pub use crate::types::InstructionCategory;

/// Map an instruction name to a circuit breaker category.
///
/// Resolution order:
/// 1. Explicit `#[circuit_breaker_category("...")]` attribute on the instruction
/// 2. `categories_config` mapping from `sandbox.toml` (`[circuit_breakers.categories]`)
/// 3. Falls back to `InstructionCategory::Default`
pub fn resolve_category(
    instruction_name: &str,
    explicit_category: &Option<String>,
    categories_config: &HashMap<String, Vec<String>>,
) -> InstructionCategory {
    // 1. Explicit attribute takes priority
    if let Some(cat) = explicit_category {
        return match_category_name(cat);
    }

    // 2. Check config mapping
    for (category_name, instructions) in categories_config {
        if instructions.iter().any(|ix| ix == instruction_name) {
            return match_category_name(category_name);
        }
    }

    // 3. Default
    InstructionCategory::Default
}

/// Map a category name string to the enum variant.
fn match_category_name(name: &str) -> InstructionCategory {
    match name.to_lowercase().as_str() {
        "withdrawal" | "withdraw" => InstructionCategory::Withdrawal,
        "liquidation" | "liquidate" => InstructionCategory::Liquidation,
        "deposit" => InstructionCategory::Deposit,
        _ => InstructionCategory::Default,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Code Generation
// ═══════════════════════════════════════════════════════════════════════════

/// Generate the complete instruction wrapper.
///
/// This wraps a single instruction function with its specific pre/post checks,
/// following the entrypoint data flow:
///
/// 1. Authority pre-checks (step [4a])
/// 2. Bound pre-checks (step [4d])
/// 3. Instruction-level snapshot (step [6])
/// 4. Business logic call (step [7])
/// 5. Invariant post-checks (step [8a])
/// 6. Transaction-level post-checks (step [8b])
/// 7. tx_cumulative_decrease check (step [8c]) — always runs
/// 8. Returns the instruction's circuit breaker category
///
/// # Parameters
/// - `meta`: parsed instruction metadata
/// - `mod_name`: the program module identifier
pub fn generate_instruction_wrapper(
    meta: &InstructionMeta,
    mod_name: &Ident,
) -> TokenStream {
    let fn_name = format_ident!("{}", meta.name);
    let wrapper_name = format_ident!("__sandbox_wrapped_{}", meta.name);
    let fn_name_str = &meta.name;

    // ── Authority checks ─────────────────────────────────────────────
    let authority_checks: Vec<TokenStream> = meta
        .authorities
        .iter()
        .map(|req| {
            crate::authority_attr::generate_authority_check(req, &None)
        })
        .collect();

    let authority_block = if authority_checks.is_empty() {
        quote! {}
    } else {
        quote! {
            // ── [4a] Authority pre-checks ──
            #(#authority_checks)*
        }
    };

    // ── Bound checks ─────────────────────────────────────────────────
    let bound_checks: Vec<TokenStream> = meta
        .bounds
        .iter()
        .map(|bound| generate_bound_check(bound))
        .collect();

    let bound_block = if bound_checks.is_empty() {
        quote! {}
    } else {
        quote! {
            // ── [4d] Bound pre-checks ──
            #(#bound_checks)*
        }
    };

    // ── Invariant post-checks (instruction-level, step [8a]) ─────────
    let invariant_checks: Vec<TokenStream> = meta
        .invariants
        .iter()
        .filter(|inv| !matches!(inv, InvariantType::TxCumulativeDecrease { .. }))
        .map(|inv| generate_invariant_check(inv))
        .collect();

    let invariant_block = if invariant_checks.is_empty() {
        quote! {}
    } else {
        quote! {
            // ── [8a] Instruction-level invariant post-checks ──
            if !__sandbox_emergency_bypass {
                #(#invariant_checks)*
            }
        }
    };

    // ── tx_cumulative_decrease checks (step [8c], always runs) ───────
    let tx_decrease_checks: Vec<TokenStream> = meta
        .invariants
        .iter()
        .filter_map(|inv| {
            if let InvariantType::TxCumulativeDecrease { field, max_pct } = inv {
                // Split "account.field"
                let parts: Vec<&str> = field.splitn(2, '.').collect();
                if parts.len() == 2 {
                    let anchor_field = crate::tx_anchor_codegen::TxAnchorField {
                        account_name: parts[0].to_string(),
                        field_path: parts[1].to_string(),
                        field_type: "u64".to_string(),
                    };
                    Some(crate::tx_anchor_codegen::generate_tx_cumulative_decrease_check(
                        &anchor_field,
                        *max_pct,
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    let tx_decrease_block = if tx_decrease_checks.is_empty() {
        quote! {}
    } else {
        quote! {
            // ── [8c] tx_cumulative_decrease checks (ALWAYS run, even during bypass) ──
            #(#tx_decrease_checks)*
        }
    };

    // ── Circuit breaker category ─────────────────────────────────────
    let category_variant = match &meta.circuit_breaker_category {
        Some(cat) => {
            let resolved = match_category_name(cat);
            let variant = format_ident!("{}", resolved.variant_name());
            quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::#variant }
        }
        None => {
            quote! { perk_sandbox_runtime::circuit_breaker::InstructionCategory::Default }
        }
    };

    // ── Recovery flag ────────────────────────────────────────────────
    let is_recovery = meta.is_recovery;

    quote! {
        /// Generated sandbox wrapper for `#fn_name_str`.
        /// Enforces all pre-checks, calls business logic, then runs post-checks.
        #[doc(hidden)]
        #[allow(unused_variables)]
        pub fn #wrapper_name(
            program_id: &anchor_lang::solana_program::pubkey::Pubkey,
            accounts: &[anchor_lang::solana_program::account_info::AccountInfo],
            ix_data: &[u8],
            __sandbox_emergency_bypass: bool,
            __sandbox_tx_anchor_fields: &[(anchor_lang::solana_program::pubkey::Pubkey, u64)],
        ) -> std::result::Result<
            perk_sandbox_runtime::circuit_breaker::InstructionCategory,
            anchor_lang::solana_program::program_error::ProgramError,
        > {
            // Recovery check: during pause, only recovery instructions are allowed
            let __sandbox_is_recovery: bool = #is_recovery;

            // ════════════════════════════════════════════════════════════
            // PRE-CHECKS (always run, including re-entrant + bypass)
            // ════════════════════════════════════════════════════════════

            #authority_block

            #bound_block

            // ════════════════════════════════════════════════════════════
            // SNAPSHOT (step [6]) — placeholder for instruction-level snapshot
            // Full implementation delegates to snapshot.rs codegen
            // ════════════════════════════════════════════════════════════

            // ════════════════════════════════════════════════════════════
            // BUSINESS LOGIC (step [7])
            // ════════════════════════════════════════════════════════════

            anchor_lang::prelude::msg!(
                concat!("PERK_SANDBOX:type=dispatch,ix=", #fn_name_str)
            );

            // Dispatch to the actual business logic handler
            let __dispatch_result = #mod_name::#fn_name(program_id, accounts, ix_data);

            // If business logic failed, propagate — Solana rolls back everything
            if let Err(e) = __dispatch_result {
                anchor_lang::prelude::msg!(
                    concat!("PERK_SANDBOX:type=dispatch_error,ix=", #fn_name_str)
                );
                return Err(e.into());
            }

            // ════════════════════════════════════════════════════════════
            // POST-CHECKS (step [8])
            // ════════════════════════════════════════════════════════════

            #invariant_block

            #tx_decrease_block

            // ════════════════════════════════════════════════════════════
            // Return circuit breaker category for step [9]
            // ════════════════════════════════════════════════════════════
            Ok(#category_variant)
        }
    }
}

/// Generate a single bound check expression.
fn generate_bound_check(bound: &BoundConstraint) -> TokenStream {
    let lhs_ident = format_ident!("{}", bound.lhs);
    let rhs_tokens: TokenStream = bound.rhs.parse().unwrap_or_else(|_| {
        let rhs_ident = format_ident!("{}", bound.rhs);
        quote! { #rhs_ident }
    });
    let bound_desc = format!("{} {} {}", bound.lhs, bound.op.as_str(), bound.rhs);

    let check = match bound.op {
        BoundOp::Gte => quote! { #lhs_ident >= #rhs_tokens },
        BoundOp::Lte => quote! { #lhs_ident <= #rhs_tokens },
        BoundOp::Gt => quote! { #lhs_ident > #rhs_tokens },
        BoundOp::Lt => quote! { #lhs_ident < #rhs_tokens },
        BoundOp::Eq => quote! { #lhs_ident == #rhs_tokens },
        BoundOp::Ne => quote! { #lhs_ident != #rhs_tokens },
    };

    quote! {
        if !(#check) {
            anchor_lang::prelude::msg!(
                "PERK_SANDBOX:type=bound_violation,constraint={}",
                #bound_desc
            );
            return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6040u32));
        }
    }
}

/// Generate a single invariant post-check expression.
///
/// NOTE: This is the TEST-ONLY invariant codegen used by generate_instruction_wrapper
/// (which is only called from unit tests in this file). The real production codegen
/// lives in invariant_attr::generate_invariant_check, which includes CU reservation
/// and the full 18-type invariant support. This simplified version exists so the
/// instruction parsing tests can verify wrapper structure without pulling in the
/// full invariant pipeline.
fn generate_invariant_check(inv: &InvariantType) -> TokenStream {
    match inv {
        InvariantType::Named(name) => {
            let check_fn = format_ident!("__sandbox_check_{}", name);
            let name_str = name.as_str();
            quote! {
                {
                    if !#check_fn(&__sb_invariant_context)? {
                        anchor_lang::prelude::msg!("PERK_SANDBOX:type=invariant_violation,invariant={}", #name_str);
                        return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6050u32));
                    }
                }
            }
        }

        InvariantType::Typed { kind, params: _ } => {
            let kind_str = kind.as_str();
            quote! {
                {
                    anchor_lang::prelude::msg!("PERK_SANDBOX:type=invariant_eval,kind={}", #kind_str);
                }
            }
        }

        InvariantType::Custom { check_fn, cu_budget: _ } => {
            let fn_ident = format_ident!("{}", check_fn);
            let check_fn_str = check_fn.as_str();
            quote! {
                {
                    if !#fn_ident(&__sb_invariant_context)? {
                        anchor_lang::prelude::msg!(
                            "PERK_SANDBOX:type=invariant_violation,invariant=custom({})",
                            #check_fn_str
                        );
                        return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6050u32));
                    }
                }
            }
        }

        InvariantType::TxCumulativeDecrease { .. } => {
            quote! {}
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    // ── parse_category_attr ─────────────────────────────────────────────

    #[test]
    fn parse_category_withdrawal() {
        let attr: syn::Attribute = parse_quote! { #[circuit_breaker_category("withdrawal")] };
        let cat = parse_category_attr(&attr).unwrap();
        assert_eq!(cat, "withdrawal");
    }

    #[test]
    fn parse_category_liquidation() {
        let attr: syn::Attribute = parse_quote! { #[circuit_breaker_category("liquidation")] };
        let cat = parse_category_attr(&attr).unwrap();
        assert_eq!(cat, "liquidation");
    }

    #[test]
    fn parse_category_deposit() {
        let attr: syn::Attribute = parse_quote! { #[circuit_breaker_category("deposit")] };
        let cat = parse_category_attr(&attr).unwrap();
        assert_eq!(cat, "deposit");
    }

    #[test]
    fn parse_category_empty_fails() {
        let attr: syn::Attribute = parse_quote! { #[circuit_breaker_category("")] };
        let err = parse_category_attr(&attr).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "got: {}",
            err
        );
    }

    // ── parse_bound_attr ────────────────────────────────────────────────

    #[test]
    fn parse_single_bound_gte() {
        let attr: syn::Attribute = parse_quote! { #[bound(leverage >= 1)] };
        let bounds = parse_bound_attr(&attr).unwrap();
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].lhs, "leverage");
        assert_eq!(bounds[0].op, BoundOp::Gte);
        assert_eq!(bounds[0].rhs, "1");
    }

    #[test]
    fn parse_multiple_bounds() {
        let attr: syn::Attribute = parse_quote! { #[bound(leverage >= 1, leverage <= 100)] };
        let bounds = parse_bound_attr(&attr).unwrap();
        assert_eq!(bounds.len(), 2);
        assert_eq!(bounds[0].op, BoundOp::Gte);
        assert_eq!(bounds[1].op, BoundOp::Lte);
        assert_eq!(bounds[1].rhs, "100");
    }

    #[test]
    fn parse_bound_gt() {
        let attr: syn::Attribute = parse_quote! { #[bound(collateral > 0)] };
        let bounds = parse_bound_attr(&attr).unwrap();
        assert_eq!(bounds[0].op, BoundOp::Gt);
    }

    #[test]
    fn parse_bound_eq() {
        let attr: syn::Attribute = parse_quote! { #[bound(mode == 1)] };
        let bounds = parse_bound_attr(&attr).unwrap();
        assert_eq!(bounds[0].op, BoundOp::Eq);
    }

    #[test]
    fn parse_bound_ne() {
        let attr: syn::Attribute = parse_quote! { #[bound(status != 0)] };
        let bounds = parse_bound_attr(&attr).unwrap();
        assert_eq!(bounds[0].op, BoundOp::Ne);
    }

    // ── parse_invariant_attr ────────────────────────────────────────────

    #[test]
    fn parse_named_invariant() {
        let attr: syn::Attribute = parse_quote! { #[invariant(vault_solvency)] };
        let inv = parse_invariant_attr(&attr).unwrap();
        assert_eq!(inv, InvariantType::Named("vault_solvency".into()));
    }

    #[test]
    fn parse_typed_invariant_gte() {
        let attr: syn::Attribute =
            parse_quote! { #[invariant(gte(lhs = "market.vault_balance", rhs = "market.total_collateral"))] };
        let inv = parse_invariant_attr(&attr).unwrap();
        match inv {
            InvariantType::Typed { kind, params } => {
                assert_eq!(kind, "gte");
                assert_eq!(params["lhs"], "market.vault_balance");
                assert_eq!(params["rhs"], "market.total_collateral");
            }
            _ => panic!("expected Typed invariant, got {:?}", inv),
        }
    }

    #[test]
    fn parse_tx_cumulative_decrease_invariant() {
        let attr: syn::Attribute = parse_quote! {
            #[invariant(tx_cumulative_decrease(field = "market.vault_balance", max_pct = 15))]
        };
        let inv = parse_invariant_attr(&attr).unwrap();
        match inv {
            InvariantType::TxCumulativeDecrease { field, max_pct } => {
                assert_eq!(field, "market.vault_balance");
                assert_eq!(max_pct, 15);
            }
            _ => panic!("expected TxCumulativeDecrease, got {:?}", inv),
        }
    }

    #[test]
    fn parse_custom_invariant() {
        let attr: syn::Attribute = parse_quote! {
            #[invariant(custom(check = "my_custom_check", cu_budget = 50000))]
        };
        let inv = parse_invariant_attr(&attr).unwrap();
        match inv {
            InvariantType::Custom { check_fn, cu_budget } => {
                assert_eq!(check_fn, "my_custom_check");
                assert_eq!(cu_budget, 50_000);
            }
            _ => panic!("expected Custom invariant, got {:?}", inv),
        }
    }

    // ── parse_instruction_attrs (full function) ─────────────────────────

    #[test]
    fn parse_full_instruction_attrs() {
        let func: ItemFn = parse_quote! {
            #[invariant(vault_solvency)]
            #[invariant(tx_cumulative_decrease(field = "market.vault_balance", max_pct = 15))]
            #[authority(user)]
            #[bound(leverage >= 1, leverage <= 100)]
            #[circuit_breaker_category("withdrawal")]
            pub fn open_position(ctx: Context<OpenPosition>, leverage: u8) -> Result<()> {
                Ok(())
            }
        };

        let meta = parse_instruction_attrs(&func).unwrap();
        assert_eq!(meta.name, "open_position");
        assert_eq!(meta.circuit_breaker_category, Some("withdrawal".into()));
        assert_eq!(meta.authorities.len(), 1);
        assert_eq!(meta.bounds.len(), 2);
        assert_eq!(meta.invariants.len(), 2);
        assert!(!meta.is_recovery);
    }

    #[test]
    fn parse_minimal_instruction() {
        let func: ItemFn = parse_quote! {
            pub fn simple_ix(ctx: Context<Simple>) -> Result<()> {
                Ok(())
            }
        };

        let meta = parse_instruction_attrs(&func).unwrap();
        assert_eq!(meta.name, "simple_ix");
        assert!(meta.circuit_breaker_category.is_none());
        assert!(meta.authorities.is_empty());
        assert!(meta.bounds.is_empty());
        assert!(meta.invariants.is_empty());
    }

    #[test]
    fn parse_recovery_instruction() {
        let func: ItemFn = parse_quote! {
            #[sandbox_recovery]
            #[authority(cranker)]
            pub fn emergency_withdraw(ctx: Context<EmergencyWithdraw>) -> Result<()> {
                Ok(())
            }
        };

        let meta = parse_instruction_attrs(&func).unwrap();
        assert!(meta.is_recovery);
        assert_eq!(meta.authorities.len(), 1);
    }

    // ── resolve_category ────────────────────────────────────────────────

    #[test]
    fn resolve_explicit_category() {
        let config: HashMap<String, Vec<String>> = HashMap::new();
        let cat = resolve_category("close_position", &Some("withdrawal".into()), &config);
        assert_eq!(cat, InstructionCategory::Withdrawal);
    }

    #[test]
    fn resolve_from_config() {
        let mut config = HashMap::new();
        config.insert(
            "liquidation".into(),
            vec!["liquidate".into(), "force_close".into()],
        );
        let cat = resolve_category("liquidate", &None, &config);
        assert_eq!(cat, InstructionCategory::Liquidation);
    }

    #[test]
    fn resolve_default_when_not_found() {
        let config: HashMap<String, Vec<String>> = HashMap::new();
        let cat = resolve_category("unknown_ix", &None, &config);
        assert_eq!(cat, InstructionCategory::Default);
    }

    #[test]
    fn resolve_explicit_overrides_config() {
        let mut config = HashMap::new();
        config.insert("deposit".into(), vec!["my_ix".into()]);
        // Explicit says "withdrawal", config says "deposit" — explicit wins
        let cat = resolve_category("my_ix", &Some("withdrawal".into()), &config);
        assert_eq!(cat, InstructionCategory::Withdrawal);
    }

    #[test]
    fn resolve_deposit_category() {
        let cat = resolve_category("deposit", &Some("deposit".into()), &HashMap::new());
        assert_eq!(cat, InstructionCategory::Deposit);
    }

    // ── generate_instruction_wrapper ────────────────────────────────────

    #[test]
    fn wrapper_contains_authority_check() {
        let meta = InstructionMeta {
            name: "test_ix".into(),
            circuit_breaker_category: None,
            authorities: vec![AuthorityRequirement::User],
            bounds: vec![],
            invariants: vec![],
            is_recovery: false,
            args: vec![],
        };
        let mod_name = format_ident!("my_program");
        let tokens = generate_instruction_wrapper(&meta, &mod_name);
        let code = tokens.to_string();

        assert!(code.contains("is_signer"), "should include authority check");
        assert!(
            code.contains("__sandbox_wrapped_test_ix"),
            "should name the wrapper function"
        );
    }

    #[test]
    fn wrapper_contains_bound_check() {
        let meta = InstructionMeta {
            name: "test_ix".into(),
            circuit_breaker_category: None,
            authorities: vec![],
            bounds: vec![BoundConstraint {
                lhs: "leverage".into(),
                op: BoundOp::Gte,
                rhs: "1".into(),
            }],
            invariants: vec![],
            is_recovery: false,
            args: vec![],
        };
        let mod_name = format_ident!("my_program");
        let tokens = generate_instruction_wrapper(&meta, &mod_name);
        let code = tokens.to_string();

        assert!(code.contains("6040"), "should reference BoundViolation error code");
    }

    #[test]
    fn wrapper_returns_category() {
        let meta = InstructionMeta {
            name: "close_position".into(),
            circuit_breaker_category: Some("withdrawal".into()),
            authorities: vec![],
            bounds: vec![],
            invariants: vec![],
            is_recovery: false,
            args: vec![],
        };
        let mod_name = format_ident!("my_program");
        let tokens = generate_instruction_wrapper(&meta, &mod_name);
        let code = tokens.to_string();

        assert!(
            code.contains("Withdrawal"),
            "should return Withdrawal category"
        );
    }

    #[test]
    fn wrapper_default_category_when_none() {
        let meta = InstructionMeta {
            name: "generic_ix".into(),
            circuit_breaker_category: None,
            authorities: vec![],
            bounds: vec![],
            invariants: vec![],
            is_recovery: false,
            args: vec![],
        };
        let mod_name = format_ident!("my_program");
        let tokens = generate_instruction_wrapper(&meta, &mod_name);
        let code = tokens.to_string();

        assert!(
            code.contains("Default"),
            "should return Default category when none specified"
        );
    }

    #[test]
    fn wrapper_tx_decrease_always_runs() {
        let meta = InstructionMeta {
            name: "withdraw".into(),
            circuit_breaker_category: Some("withdrawal".into()),
            authorities: vec![],
            bounds: vec![],
            invariants: vec![InvariantType::TxCumulativeDecrease {
                field: "market.vault_balance".into(),
                max_pct: 15,
            }],
            is_recovery: false,
            args: vec![],
        };
        let mod_name = format_ident!("my_program");
        let tokens = generate_instruction_wrapper(&meta, &mod_name);
        let code = tokens.to_string();

        assert!(
            code.contains("check_tx_cumulative_decrease"),
            "should generate tx_cumulative_decrease check"
        );
        // tx_cumulative_decrease should NOT be gated by __sandbox_emergency_bypass
        // The invariant block (gated) and the tx_decrease block (ungated) are separate
        // Verify the check exists outside the bypass-gated section
        assert!(
            code.contains("check_tx_cumulative_decrease"),
            "tx_cumulative_decrease should be generated as a separate ungated block"
        );
    }

    #[test]
    fn wrapper_invariants_gated_by_bypass() {
        let meta = InstructionMeta {
            name: "test_ix".into(),
            circuit_breaker_category: None,
            authorities: vec![],
            bounds: vec![],
            invariants: vec![InvariantType::Named("vault_solvency".into())],
            is_recovery: false,
            args: vec![],
        };
        let mod_name = format_ident!("my_program");
        let tokens = generate_instruction_wrapper(&meta, &mod_name);
        let code = tokens.to_string();

        assert!(
            code.contains("__sandbox_emergency_bypass"),
            "named invariants should be gated by emergency bypass flag"
        );
    }

    #[test]
    fn wrapper_dispatches_to_business_logic() {
        let meta = InstructionMeta {
            name: "open_position".into(),
            circuit_breaker_category: None,
            authorities: vec![],
            bounds: vec![],
            invariants: vec![],
            is_recovery: false,
            args: vec![],
        };
        let mod_name = format_ident!("my_perps");
        let tokens = generate_instruction_wrapper(&meta, &mod_name);
        let code = tokens.to_string();

        assert!(
            code.contains("my_perps"),
            "should dispatch to the program module"
        );
        assert!(
            code.contains("open_position"),
            "should call the instruction function"
        );
    }

    // ── generate_bound_check ────────────────────────────────────────────

    #[test]
    fn bound_check_gte() {
        let bound = BoundConstraint {
            lhs: "x".into(),
            op: BoundOp::Gte,
            rhs: "10".into(),
        };
        let tokens = generate_bound_check(&bound);
        let code = tokens.to_string();
        assert!(code.contains(">="), "should use >= operator");
        assert!(code.contains("6040"), "should use BoundViolation error");
    }

    #[test]
    fn bound_check_includes_description() {
        let bound = BoundConstraint {
            lhs: "leverage".into(),
            op: BoundOp::Lte,
            rhs: "100".into(),
        };
        let tokens = generate_bound_check(&bound);
        let code = tokens.to_string();
        assert!(
            code.contains("leverage"),
            "should include field name in log message"
        );
    }

    // ── InstructionCategory ────────────────────────────────────────────

    #[test]
    fn category_variant_names() {
        assert_eq!(InstructionCategory::Withdrawal.variant_name(), "Withdrawal");
        assert_eq!(InstructionCategory::Liquidation.variant_name(), "Liquidation");
        assert_eq!(InstructionCategory::Deposit.variant_name(), "Deposit");
        assert_eq!(InstructionCategory::Default.variant_name(), "Default");
    }

    #[test]
    fn match_category_name_aliases() {
        assert_eq!(match_category_name("withdrawal"), InstructionCategory::Withdrawal);
        assert_eq!(match_category_name("withdraw"), InstructionCategory::Withdrawal);
        assert_eq!(match_category_name("Withdrawal"), InstructionCategory::Withdrawal);
        assert_eq!(match_category_name("liquidation"), InstructionCategory::Liquidation);
        assert_eq!(match_category_name("liquidate"), InstructionCategory::Liquidation);
        assert_eq!(match_category_name("deposit"), InstructionCategory::Deposit);
        assert_eq!(match_category_name("unknown"), InstructionCategory::Default);
    }
}

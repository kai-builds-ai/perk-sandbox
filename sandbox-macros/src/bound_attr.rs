//! Bound attribute parsing and code generation.
//!
//! Parses `#[bound(...)]` attributes on sandbox instructions and generates
//! pre-check code that validates instruction arguments are within range.
//!
//! Error code: 6040 (BoundViolation) on failure.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Ident, LitInt, Token,
};

// ── Types (re-exported from types.rs) ────────────────────────────────────────

pub use crate::types::{BoundConstraint, BoundOp};

// ── Parsing helpers ──────────────────────────────────────────────────────────

/// A single parsed constraint from inside the attribute.
struct SingleConstraint {
    constraint: BoundConstraint,
}

impl Parse for SingleConstraint {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // field_name
        let ident: Ident = input.parse()?;
        let field_name = ident.to_string();

        // operator: >=, >, <=, <, ==, !=
        let op = parse_op(input)?;

        // value (integer literal, possibly negative)
        let negative = if input.peek(Token![-]) {
            let _: Token![-] = input.parse()?;
            true
        } else {
            false
        };
        let lit: LitInt = input.parse()?;
        let raw: i128 = lit.base10_parse()?;
        let value = if negative { -raw } else { raw };

        Ok(SingleConstraint {
            constraint: BoundConstraint {
                field_name,
                op,
                value,
            },
        })
    }
}

/// Parse a comparison operator from the token stream.
fn parse_op(input: ParseStream) -> syn::Result<BoundOp> {
    // Order matters: check two-char operators first.
    if input.peek(Token![>=]) {
        let _: Token![>=] = input.parse()?;
        Ok(BoundOp::Gte)
    } else if input.peek(Token![<=]) {
        let _: Token![<=] = input.parse()?;
        Ok(BoundOp::Lte)
    } else if input.peek(Token![!=]) {
        let _: Token![!=] = input.parse()?;
        Ok(BoundOp::Neq)
    } else if input.peek(Token![==]) {
        let _: Token![==] = input.parse()?;
        Ok(BoundOp::Eq)
    } else if input.peek(Token![>]) {
        let _: Token![>] = input.parse()?;
        Ok(BoundOp::Gt)
    } else if input.peek(Token![<]) {
        let _: Token![<] = input.parse()?;
        Ok(BoundOp::Lt)
    } else {
        Err(input.error("expected comparison operator: >=, >, <=, <, ==, !="))
    }
}

/// Content of a `#[bound(...)]` — comma-separated constraints.
struct BoundInner {
    constraints: Vec<BoundConstraint>,
}

impl Parse for BoundInner {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let parsed: Punctuated<SingleConstraint, Token![,]> =
            Punctuated::parse_terminated(input)?;

        let constraints: Vec<BoundConstraint> =
            parsed.into_iter().map(|sc| sc.constraint).collect();

        if constraints.is_empty() {
            return Err(input.error("bound attribute requires at least one constraint"));
        }

        Ok(BoundInner { constraints })
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Parse a `#[bound(...)]` attribute into a vector of [`BoundConstraint`]s.
///
/// Supports multiple comma-separated constraints in a single attribute:
/// ```ignore
/// #[bound(leverage >= 1, leverage <= 100)]
/// ```
pub fn parse_bound_attr(attr: &syn::Attribute) -> Result<Vec<BoundConstraint>, syn::Error> {
    let inner: BoundInner = attr.parse_args()?;
    Ok(inner.constraints)
}

/// Generate the bounds pre-check code from a set of constraints.
///
/// Each constraint becomes:
/// ```ignore
/// if !(field op value) {
///     return Err(ProgramError::Custom(6040));
/// }
/// ```
///
/// The generated code references instruction arguments by name, so the
/// surrounding function must have matching parameter names.
pub fn generate_bound_checks(constraints: &[BoundConstraint]) -> TokenStream {
    let err = quote! { anchor_lang::solana_program::program_error::ProgramError::Custom(6040u32) };

    let checks: Vec<TokenStream> = constraints
        .iter()
        .map(|c| {
            let field = proc_macro2::Ident::new(&c.field_name, proc_macro2::Span::call_site());
            let value_lit = make_literal(c.value);
            let op_tokens = op_to_tokens(c.op);
            let op_str = c.op.as_str();
            let field_name_str = &c.field_name;
            let value_str = c.value.to_string();

            quote! {
                if !(#field #op_tokens #value_lit) {
                    anchor_lang::prelude::msg!(
                        "Bound violation: {} {} {} (actual: {})",
                        #field_name_str,
                        #op_str,
                        #value_str,
                        #field
                    );
                    return Err(#err);
                }
            }
        })
        .collect();

    quote! {
        {
            #(#checks)*
        }
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Convert a `BoundOp` into the corresponding Rust operator tokens.
fn op_to_tokens(op: BoundOp) -> TokenStream {
    match op {
        BoundOp::Gte => quote! { >= },
        BoundOp::Gt => quote! { > },
        BoundOp::Lte => quote! { <= },
        BoundOp::Lt => quote! { < },
        BoundOp::Eq => quote! { == },
        BoundOp::Neq => quote! { != },
    }
}

/// Create an integer literal token from an i128 value.
///
/// Uses i128 suffix for negative values, u64 suffix for non-negative.
/// The actual comparison will rely on Rust's type coercion.
fn make_literal(value: i128) -> TokenStream {
    if value < 0 {
        // Negative: emit as i64 literal
        let v = value as i64;
        quote! { #v }
    } else {
        // Non-negative: emit as a plain integer literal (Rust infers type)
        let v = value as u64;
        quote! { #v }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn parse_single_gte() {
        let attr: syn::Attribute = parse_quote! { #[bound(leverage >= 1)] };
        let constraints = parse_bound_attr(&attr).unwrap();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].field_name, "leverage");
        assert_eq!(constraints[0].op, BoundOp::Gte);
        assert_eq!(constraints[0].value, 1);
    }

    #[test]
    fn parse_single_gt() {
        let attr: syn::Attribute = parse_quote! { #[bound(collateral > 0)] };
        let constraints = parse_bound_attr(&attr).unwrap();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].field_name, "collateral");
        assert_eq!(constraints[0].op, BoundOp::Gt);
        assert_eq!(constraints[0].value, 0);
    }

    #[test]
    fn parse_multiple_constraints() {
        let attr: syn::Attribute = parse_quote! { #[bound(leverage >= 1, leverage <= 100)] };
        let constraints = parse_bound_attr(&attr).unwrap();
        assert_eq!(constraints.len(), 2);

        assert_eq!(constraints[0].field_name, "leverage");
        assert_eq!(constraints[0].op, BoundOp::Gte);
        assert_eq!(constraints[0].value, 1);

        assert_eq!(constraints[1].field_name, "leverage");
        assert_eq!(constraints[1].op, BoundOp::Lte);
        assert_eq!(constraints[1].value, 100);
    }

    #[test]
    fn parse_eq_constraint() {
        let attr: syn::Attribute = parse_quote! { #[bound(mode == 1)] };
        let constraints = parse_bound_attr(&attr).unwrap();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].op, BoundOp::Eq);
        assert_eq!(constraints[0].value, 1);
    }

    #[test]
    fn parse_neq_constraint() {
        let attr: syn::Attribute = parse_quote! { #[bound(status != 0)] };
        let constraints = parse_bound_attr(&attr).unwrap();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].op, BoundOp::Neq);
        assert_eq!(constraints[0].value, 0);
    }

    #[test]
    fn parse_lt_constraint() {
        let attr: syn::Attribute = parse_quote! { #[bound(amount < 1000000)] };
        let constraints = parse_bound_attr(&attr).unwrap();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].field_name, "amount");
        assert_eq!(constraints[0].op, BoundOp::Lt);
        assert_eq!(constraints[0].value, 1_000_000);
    }

    #[test]
    fn parse_three_constraints() {
        let attr: syn::Attribute =
            parse_quote! { #[bound(leverage >= 1, leverage <= 100, collateral > 0)] };
        let constraints = parse_bound_attr(&attr).unwrap();
        assert_eq!(constraints.len(), 3);
        assert_eq!(constraints[2].field_name, "collateral");
        assert_eq!(constraints[2].op, BoundOp::Gt);
    }

    #[test]
    fn generate_single_check_has_error_code() {
        let constraints = vec![BoundConstraint {
            field_name: "leverage".into(),
            op: BoundOp::Gte,
            value: 1,
        }];
        let tokens = generate_bound_checks(&constraints);
        let code = tokens.to_string();
        assert!(code.contains("6040"), "should reference error code 6040");
        assert!(code.contains("leverage"), "should reference the field name");
    }

    #[test]
    fn generate_multiple_checks() {
        let constraints = vec![
            BoundConstraint {
                field_name: "leverage".into(),
                op: BoundOp::Gte,
                value: 1,
            },
            BoundConstraint {
                field_name: "leverage".into(),
                op: BoundOp::Lte,
                value: 100,
            },
        ];
        let tokens = generate_bound_checks(&constraints);
        let code = tokens.to_string();
        // Both checks should appear
        let count = code.matches("6040").count();
        assert!(count >= 2, "should have two bound checks, found {}", count);
    }

    #[test]
    fn generate_check_contains_msg() {
        let constraints = vec![BoundConstraint {
            field_name: "collateral".into(),
            op: BoundOp::Gt,
            value: 0,
        }];
        let tokens = generate_bound_checks(&constraints);
        let code = tokens.to_string();
        assert!(
            code.contains("Bound violation"),
            "should emit diagnostic msg on violation"
        );
    }

    #[test]
    fn op_display() {
        assert_eq!(BoundOp::Gte.as_str(), ">=");
        assert_eq!(BoundOp::Gt.as_str(), ">");
        assert_eq!(BoundOp::Lte.as_str(), "<=");
        assert_eq!(BoundOp::Lt.as_str(), "<");
        assert_eq!(BoundOp::Eq.as_str(), "==");
        assert_eq!(BoundOp::Neq.as_str(), "!=");
    }
}

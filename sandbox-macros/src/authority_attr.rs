//! Authority attribute parsing and code generation.
//!
//! Parses `#[authority(...)]` attributes on sandbox instructions and generates
//! the pre-check code that runs on every call (including re-entrant and emergency bypass).
//!
//! Error code: 6010 (UnauthorizedSigner) on failure.

use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Ident, LitStr, Token,
};

// ── Types (re-exported from types.rs) ────────────────────────────────────────

pub use crate::types::AuthorityRequirement;

// ── Parsing helpers ──────────────────────────────────────────────────────────

/// Internal parse target for the content inside `#[authority(...)]`.
struct AuthorityInner {
    req: AuthorityRequirement,
}

impl Parse for AuthorityInner {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ident: Ident = input.parse()?;
        let name = ident.to_string();

        match name.as_str() {
            // #[authority(user)]
            "user" => Ok(AuthorityInner {
                req: AuthorityRequirement::User,
            }),

            // #[authority(signer = "KEY_NAME")]
            "signer" => {
                let _: Token![=] = input.parse()?;
                let lit: LitStr = input.parse()?;
                Ok(AuthorityInner {
                    req: AuthorityRequirement::Signer(lit.value()),
                })
            }

            // #[authority(any_of = ["KEY_1", "KEY_2"])]
            "any_of" => {
                let _: Token![=] = input.parse()?;
                let content;
                syn::bracketed!(content in input);
                let keys: Punctuated<LitStr, Token![,]> =
                    Punctuated::parse_terminated(&content)?;
                let key_names: Vec<String> = keys.iter().map(|l| l.value()).collect();
                if key_names.is_empty() {
                    return Err(syn::Error::new(
                        ident.span(),
                        "any_of requires at least one key name",
                    ));
                }
                Ok(AuthorityInner {
                    req: AuthorityRequirement::AnyOf(key_names),
                })
            }

            // #[authority(owner_of = "ctx.accounts.position")]
            "owner_of" => {
                let _: Token![=] = input.parse()?;
                let lit: LitStr = input.parse()?;
                Ok(AuthorityInner {
                    req: AuthorityRequirement::OwnerOf(lit.value()),
                })
            }

            // #[authority(cranker)] or any other role name
            other => Ok(AuthorityInner {
                req: AuthorityRequirement::Role(other.to_string()),
            }),
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Parse a `#[authority(...)]` attribute into an [`AuthorityRequirement`].
///
/// Expects the attribute's path to be `authority`. Parses the parenthesised
/// tokens to determine the variant.
pub fn parse_authority_attr(attr: &syn::Attribute) -> Result<AuthorityRequirement, syn::Error> {
    let inner: AuthorityInner = attr.parse_args()?;
    Ok(inner.req)
}

/// Generate the authority pre-check code for an instruction.
///
/// `keys_config` is the optional `[keys]` table from `sandbox.toml`,
/// mapping key names → base58-encoded pubkeys.
///
/// The generated code expects:
/// - `accounts: &[AccountInfo]` in scope (the raw account slice).
/// - For `OwnerOf`: the referenced account deserialized in the usual Anchor context.
///
/// On failure returns `Err(ProgramError::Custom(6010))`.
pub fn generate_authority_check(
    req: &AuthorityRequirement,
    keys_config: &Option<HashMap<String, String>>,
) -> TokenStream {
    // Error constant — UnauthorizedSigner
    let err = quote! { anchor_lang::solana_program::program_error::ProgramError::Custom(6010u32) };

    match req {
        // ── User: first account must be signer ──────────────────────────
        AuthorityRequirement::User => {
            quote! {
                {
                    let first = accounts.first()
                        .ok_or(#err)?;
                    if !first.is_signer {
                        return Err(#err);
                    }
                }
            }
        }

        // ── Signer: first signer must match a specific key ─────────────
        AuthorityRequirement::Signer(key_name) => {
            let pubkey_bytes = resolve_key_bytes(key_name, keys_config);
            quote! {
                {
                    let first = accounts.first()
                        .ok_or(#err)?;
                    if !first.is_signer {
                        return Err(#err);
                    }
                    let expected = anchor_lang::solana_program::pubkey::Pubkey::new_from_array(#pubkey_bytes);
                    if first.key != &expected {
                        return Err(#err);
                    }
                }
            }
        }

        // ── AnyOf: first signer matches any of the listed keys ─────────
        AuthorityRequirement::AnyOf(key_names) => {
            let key_checks: Vec<TokenStream> = key_names
                .iter()
                .map(|name| {
                    let bytes = resolve_key_bytes(name, keys_config);
                    quote! {
                        anchor_lang::solana_program::pubkey::Pubkey::new_from_array(#bytes)
                    }
                })
                .collect();

            quote! {
                {
                    let first = accounts.first()
                        .ok_or(#err)?;
                    if !first.is_signer {
                        return Err(#err);
                    }
                    let allowed: &[anchor_lang::solana_program::pubkey::Pubkey] = &[
                        #(#key_checks),*
                    ];
                    if !allowed.iter().any(|k| k == first.key) {
                        return Err(#err);
                    }
                }
            }
        }

        // ── OwnerOf: check owner/authority field on referenced account ──
        AuthorityRequirement::OwnerOf(path) => {
            let field_tokens = parse_account_path(path);
            quote! {
                {
                    let first = accounts.first()
                        .ok_or(#err)?;
                    if !first.is_signer {
                        return Err(#err);
                    }
                    let account_authority: &anchor_lang::solana_program::pubkey::Pubkey = &#field_tokens.authority;
                    if first.key != account_authority {
                        return Err(#err);
                    }
                }
            }
        }

        // ── Role: same as Signer, resolved from [keys] config ──────────
        AuthorityRequirement::Role(role_name) => {
            let pubkey_bytes = resolve_key_bytes(role_name, keys_config);
            quote! {
                {
                    let first = accounts.first()
                        .ok_or(#err)?;
                    if !first.is_signer {
                        return Err(#err);
                    }
                    let expected = anchor_lang::solana_program::pubkey::Pubkey::new_from_array(#pubkey_bytes);
                    if first.key != &expected {
                        return Err(#err);
                    }
                }
            }
        }
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Resolve a key name from the `[keys]` config into a compile-time byte array expression.
///
/// If the key is found in config, we emit a `bs58` decode at compile time.
/// If not found (config absent or key missing), we emit a compile_error so
/// the developer gets a clear message.
fn resolve_key_bytes(key_name: &str, keys_config: &Option<HashMap<String, String>>) -> TokenStream {
    if let Some(config) = keys_config {
        if let Some(base58) = config.get(key_name) {
            // Decode at macro expansion time — fail fast on bad keys.
            let decoded = bs58::decode(base58).into_vec();
            match decoded {
                Ok(bytes) if bytes.len() == 32 => {
                    let byte_literals: Vec<proc_macro2::TokenTree> = bytes
                        .iter()
                        .map(|b| {
                            proc_macro2::Literal::u8_suffixed(*b).into()
                        })
                        .collect();
                    return quote! { [#(#byte_literals),*] };
                }
                Ok(_) => {
                    let msg = format!(
                        "Key '{}' has invalid length (expected 32 bytes): '{}'",
                        key_name, base58
                    );
                    return quote! { compile_error!(#msg) };
                }
                Err(e) => {
                    let msg = format!(
                        "Key '{}' is not valid base58: '{}' ({})",
                        key_name, base58, e
                    );
                    return quote! { compile_error!(#msg) };
                }
            }
        }
    }

    // Key not in config — emit a compile_error so the developer knows to add it.
    let key_name_lit = key_name.to_string();
    let msg = format!("Key '{}' not found in [keys] config. Add it to sandbox.toml.", key_name_lit);
    quote! {
        compile_error!(#msg)
    }
}

/// Parse an account path like "ctx.accounts.position" into token references.
///
/// Strips the "ctx.accounts." prefix if present and produces a field access
/// on the `ctx.accounts` struct.
fn parse_account_path(path: &str) -> TokenStream {
    let stripped = path
        .strip_prefix("ctx.accounts.")
        .unwrap_or(path);

    let parts: Vec<&str> = stripped.split('.').collect();
    let idents: Vec<proc_macro2::Ident> = parts
        .iter()
        .map(|p| proc_macro2::Ident::new(p, proc_macro2::Span::call_site()))
        .collect();

    // Rebuild as ctx.accounts.<ident>...
    quote! { ctx.accounts.#(#idents).* }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn parse_user_authority() {
        let attr: syn::Attribute = parse_quote! { #[authority(user)] };
        let req = parse_authority_attr(&attr).unwrap();
        assert_eq!(req, AuthorityRequirement::User);
    }

    #[test]
    fn parse_signer_authority() {
        let attr: syn::Attribute = parse_quote! { #[authority(signer = "ADMIN_PUBKEY")] };
        let req = parse_authority_attr(&attr).unwrap();
        assert_eq!(req, AuthorityRequirement::Signer("ADMIN_PUBKEY".into()));
    }

    #[test]
    fn parse_any_of_authority() {
        let attr: syn::Attribute = parse_quote! { #[authority(any_of = ["KEY_A", "KEY_B"])] };
        let req = parse_authority_attr(&attr).unwrap();
        assert_eq!(
            req,
            AuthorityRequirement::AnyOf(vec!["KEY_A".into(), "KEY_B".into()])
        );
    }

    #[test]
    fn parse_owner_of_authority() {
        let attr: syn::Attribute = parse_quote! { #[authority(owner_of = "ctx.accounts.position")] };
        let req = parse_authority_attr(&attr).unwrap();
        assert_eq!(
            req,
            AuthorityRequirement::OwnerOf("ctx.accounts.position".into())
        );
    }

    #[test]
    fn parse_role_authority() {
        let attr: syn::Attribute = parse_quote! { #[authority(cranker)] };
        let req = parse_authority_attr(&attr).unwrap();
        assert_eq!(req, AuthorityRequirement::Role("cranker".into()));
    }

    #[test]
    fn parse_role_admin() {
        let attr: syn::Attribute = parse_quote! { #[authority(admin)] };
        let req = parse_authority_attr(&attr).unwrap();
        assert_eq!(req, AuthorityRequirement::Role("admin".into()));
    }

    #[test]
    fn any_of_single_key() {
        let attr: syn::Attribute = parse_quote! { #[authority(any_of = ["ONLY_KEY"])] };
        let req = parse_authority_attr(&attr).unwrap();
        assert_eq!(
            req,
            AuthorityRequirement::AnyOf(vec!["ONLY_KEY".into()])
        );
    }

    #[test]
    fn generate_user_check_produces_tokens() {
        let req = AuthorityRequirement::User;
        let tokens = generate_authority_check(&req, &None);
        let code = tokens.to_string();
        assert!(code.contains("is_signer"), "should check is_signer");
        assert!(code.contains("6010"), "should reference error code 6010");
    }

    #[test]
    fn generate_signer_check_with_config() {
        let mut keys = HashMap::new();
        // A valid 32-byte base58 key (all ones = 4vJ9JU1bJJE96...)
        keys.insert(
            "ADMIN".into(),
            "11111111111111111111111111111111".into(), // system program address
        );
        let req = AuthorityRequirement::Signer("ADMIN".into());
        let tokens = generate_authority_check(&req, &Some(keys));
        let code = tokens.to_string();
        assert!(code.contains("expected"), "should compare against expected key");
        assert!(code.contains("6010"), "should reference error code 6010");
    }

    #[test]
    fn generate_role_without_config_emits_compile_error() {
        let req = AuthorityRequirement::Role("cranker".into());
        let tokens = generate_authority_check(&req, &None);
        let code = tokens.to_string();
        assert!(
            code.contains("compile_error"),
            "should emit compile_error when key not in config"
        );
    }
}

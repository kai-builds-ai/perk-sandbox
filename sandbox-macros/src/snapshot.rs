//! Account snapshot code generation (Spec S4).
//!
//! Generates code to read account fields before and after business logic
//! for invariant comparison. Supports two strategies:
//!
//! - **Strategy A (fixed-offset):** All preceding fields are fixed-size.
//!   Direct byte read at compile-time known offset. ~200-400 CU.
//! - **Strategy B (Borsh-deser prefix):** Variable-length fields precede target.
//!   Runtime prefix parsing to find dynamic offset. ~1,000-3,000 CU.
//!
//! The generated code follows the **copy-and-drop** pattern: borrow account data,
//! copy the target bytes, DROP the borrow before returning. This ensures business
//! logic can take mutable borrows afterwards.

use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::config::{AccountConfig, FieldConfig};

// ==========================================================================
// Types
// ==========================================================================

/// Supported field types for snapshot reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Bool,
    Pubkey,
}

impl FieldType {
    /// Byte size of this field type.
    pub const fn byte_size(&self) -> usize {
        match self {
            FieldType::U8 | FieldType::I8 | FieldType::Bool => 1,
            FieldType::U16 | FieldType::I16 => 2,
            FieldType::U32 | FieldType::I32 => 4,
            FieldType::U64 | FieldType::I64 => 8,
            FieldType::Pubkey => 32,
        }
    }

    /// Generate the Rust type token for this field.
    fn rust_type(&self) -> TokenStream {
        match self {
            FieldType::U8 => quote! { u8 },
            FieldType::U16 => quote! { u16 },
            FieldType::U32 => quote! { u32 },
            FieldType::U64 => quote! { u64 },
            FieldType::I8 => quote! { i8 },
            FieldType::I16 => quote! { i16 },
            FieldType::I32 => quote! { i32 },
            FieldType::I64 => quote! { i64 },
            FieldType::Bool => quote! { bool },
            FieldType::Pubkey => quote! { anchor_lang::prelude::Pubkey },
        }
    }

    /// Generate the from_le_bytes conversion for the read buffer.
    fn from_bytes_expr(&self, buf_ident: &proc_macro2::Ident) -> TokenStream {
        match self {
            FieldType::U8 => quote! { #buf_ident[0] },
            FieldType::I8 => quote! { #buf_ident[0] as i8 },
            FieldType::Bool => quote! {
                if #buf_ident[0] > 1 {
                    return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6073).into());
                }
                #buf_ident[0] != 0
            },
            FieldType::U16 => quote! { u16::from_le_bytes(#buf_ident) },
            FieldType::I16 => quote! { i16::from_le_bytes(#buf_ident) },
            FieldType::U32 => quote! { u32::from_le_bytes(#buf_ident) },
            FieldType::I32 => quote! { i32::from_le_bytes(#buf_ident) },
            FieldType::U64 => quote! { u64::from_le_bytes(#buf_ident) },
            FieldType::I64 => quote! { i64::from_le_bytes(#buf_ident) },
            FieldType::Pubkey => {
                quote! { anchor_lang::prelude::Pubkey::new_from_array(#buf_ident) }
            }
        }
    }

    /// Generate the buffer type (e.g. `[u8; 8]`).
    fn buf_type(&self) -> TokenStream {
        let size = self.byte_size();
        quote! { [u8; #size] }
    }
}

/// A step in the Borsh prefix-skip sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BorshSkipStep {
    /// Skip a fixed number of bytes.
    Fixed(usize),
    /// Read 1-byte tag; if tag == 1, skip `inner_size` more bytes (Option<T>).
    Option(usize),
    /// Read u32 len, skip `len * element_size` bytes (Vec<T>).
    Vec(usize),
    /// Read u32 len, skip `len` bytes (String / Vec<u8>).
    String,
}

/// Strategy for reading a field's bytes from account data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotStrategy {
    /// All preceding fields are fixed-size. Offset known at compile time.
    FixedOffset(usize),
    /// Variable-length fields precede the target. Steps to skip them at runtime.
    BorshDeserPrefix(Vec<BorshSkipStep>),
}

/// A fully resolved reference to a field that needs snapshotting.
#[derive(Debug, Clone)]
pub struct FieldRef {
    /// Account name in the Context (e.g., "market").
    pub account_name: String,
    /// Field path within the account struct (e.g., "vault_balance").
    pub field_path: String,
    /// The primitive type of the field.
    pub field_type: FieldType,
    /// How to locate the field's bytes in account data.
    pub strategy: SnapshotStrategy,
    /// Size of the account discriminator in bytes (default 8 for Anchor).
    /// Used as the starting cursor position for Strategy B (Borsh prefix).
    pub discriminator_size: usize,
}

impl FieldRef {
    /// Variable-safe name: `"market.vault_balance"` -> `"market_vault_balance"`.
    fn var_slug(&self) -> String {
        format!("{}_{}", self.account_name, self.field_path).replace('.', "_")
    }
}

// ==========================================================================
// Code generation -- single field snapshot read
// ==========================================================================

/// Generate code to read a single field from account data into a local variable.
///
/// The generated block:
/// 1. Borrows account data (immutable `Ref`).
/// 2. Reads the field bytes (fixed-offset or Borsh prefix parse).
/// 3. Converts to the target Rust type.
/// 4. Drops the borrow before the block ends.
///
/// The result is bound to `let #var_name: T = { ... };`
pub fn generate_snapshot_read(field: &FieldRef, var_name: &str) -> TokenStream {
    let var_ident = format_ident!("{}", var_name);
    let account_ident = format_ident!("{}", field.account_name);
    let rust_type = field.field_type.rust_type();
    let byte_size = field.field_type.byte_size();

    match &field.strategy {
        SnapshotStrategy::FixedOffset(offset) => {
            generate_fixed_offset_read(field, &var_ident, &account_ident, &rust_type, byte_size, *offset)
        }
        SnapshotStrategy::BorshDeserPrefix(steps) => {
            generate_borsh_prefix_read(field, &var_ident, &account_ident, &rust_type, byte_size, steps)
        }
    }
}

/// Strategy A: Fixed-offset read using the runtime helper.
fn generate_fixed_offset_read(
    field: &FieldRef,
    var_ident: &proc_macro2::Ident,
    account_ident: &proc_macro2::Ident,
    rust_type: &TokenStream,
    byte_size: usize,
    offset: usize,
) -> TokenStream {
    let buf_ident = format_ident!("__buf_{}", var_ident);
    let conversion = field.field_type.from_bytes_expr(&buf_ident);
    let buf_type = field.field_type.buf_type();

    quote! {
        let #var_ident: #rust_type = {
            let mut #buf_ident: #buf_type = [0u8; #byte_size];
            perk_sandbox_runtime::snapshot::snapshot_field_fixed(
                &#account_ident.to_account_info(),
                #offset,
                &mut #buf_ident,
            )?;
            #conversion
        };
    }
}

/// Strategy B: Borsh prefix-parse read.
/// Generates inline cursor-walking code that skips variable-length fields,
/// then reads the target field bytes.
fn generate_borsh_prefix_read(
    field: &FieldRef,
    var_ident: &proc_macro2::Ident,
    account_ident: &proc_macro2::Ident,
    rust_type: &TokenStream,
    byte_size: usize,
    steps: &[BorshSkipStep],
) -> TokenStream {
    let buf_ident = format_ident!("__buf_{}", var_ident);
    let conversion = field.field_type.from_bytes_expr(&buf_ident);
    let buf_type = field.field_type.buf_type();
    let disc_size = field.discriminator_size;

    let skip_code = generate_skip_steps(steps);

    quote! {
        let #var_ident: #rust_type = {
            let mut #buf_ident: #buf_type = [0u8; #byte_size];
            {
                // Two-step binding to avoid temporary AccountInfo being dropped
                // while __data still borrows it.
                let __account_info = #account_ident.to_account_info();
                let __data = __account_info
                    .try_borrow_data()
                    .map_err(|_| anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;

                let mut __cursor: usize = #disc_size;

                #skip_code

                let __end = __cursor
                    .checked_add(#byte_size)
                    .ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;
                if __end > __data.len() {
                    return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6073).into());
                }
                #buf_ident.copy_from_slice(&__data[__cursor..__end]);
            }
            #conversion
        };
    }
}

/// Generate cursor-walking code for each BorshSkipStep.
fn generate_skip_steps(steps: &[BorshSkipStep]) -> TokenStream {
    let step_code: Vec<TokenStream> = steps
        .iter()
        .map(|step| {
            match step {
                BorshSkipStep::Fixed(n) => {
                    quote! {
                        __cursor = __cursor
                            .checked_add(#n)
                            .ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;
                    }
                }
                BorshSkipStep::Option(inner_size) => {
                    quote! {
                        {
                            if __cursor >= __data.len() {
                                return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6073).into());
                            }
                            let __tag = __data[__cursor];
                            __cursor = __cursor
                                .checked_add(1)
                                .ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;
                            match __tag {
                                0 => {},
                                1 => {
                                    __cursor = __cursor
                                        .checked_add(#inner_size)
                                        .ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;
                                },
                                _ => {
                                    // Invalid Borsh Option tag — reject (fail-closed)
                                    return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6073).into());
                                }
                            }
                        }
                    }
                }
                BorshSkipStep::Vec(element_size) => {
                    quote! {
                        {
                            let __vec_len_end = __cursor
                                .checked_add(4)
                                .ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;
                            if __vec_len_end > __data.len() {
                                return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6073).into());
                            }
                            let __vec_len = u32::from_le_bytes(
                                __data[__cursor..__vec_len_end].try_into().unwrap()
                            ) as usize;
                            __cursor = __vec_len_end;
                            let __skip = __vec_len
                                .checked_mul(#element_size)
                                .ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;
                            __cursor = __cursor
                                .checked_add(__skip)
                                .ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;
                        }
                    }
                }
                BorshSkipStep::String => {
                    quote! {
                        {
                            let __str_len_end = __cursor
                                .checked_add(4)
                                .ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;
                            if __str_len_end > __data.len() {
                                return Err(anchor_lang::solana_program::program_error::ProgramError::Custom(6073).into());
                            }
                            let __str_len = u32::from_le_bytes(
                                __data[__cursor..__str_len_end].try_into().unwrap()
                            ) as usize;
                            __cursor = __str_len_end;
                            __cursor = __cursor
                                .checked_add(__str_len)
                                .ok_or(anchor_lang::solana_program::program_error::ProgramError::Custom(6073))?;
                        }
                    }
                }
            }
        })
        .collect();

    quote! { #(#step_code)* }
}

// ==========================================================================
// Code generation -- before/after snapshot batches
// ==========================================================================

/// Generate all snapshot reads BEFORE business logic.
///
/// Produces a block of `let __sb_{account}_{field}_before: T = { ... };` bindings.
/// All borrows are acquired and dropped within each binding's block.
pub fn generate_before_snapshots(fields: &[FieldRef]) -> TokenStream {
    if fields.is_empty() {
        return quote! {};
    }

    let reads: Vec<TokenStream> = fields
        .iter()
        .map(|f| {
            let var_name = format!("__sb_{}_before", f.var_slug());
            generate_snapshot_read(f, &var_name)
        })
        .collect();

    quote! {
        #(#reads)*
    }
}

/// Generate all snapshot reads AFTER business logic.
///
/// Same fields, same strategies, but bound to `_after` variable names.
/// These read the post-mutation state for invariant comparison.
pub fn generate_after_reads(fields: &[FieldRef]) -> TokenStream {
    if fields.is_empty() {
        return quote! {};
    }

    let reads: Vec<TokenStream> = fields
        .iter()
        .map(|f| {
            let var_name = format!("__sb_{}_after", f.var_slug());
            generate_snapshot_read(f, &var_name)
        })
        .collect();

    quote! {
        #(#reads)*
    }
}

/// Generate a combined before+after snapshot pair for a set of fields.
pub fn generate_snapshot_wrapper(fields: &[FieldRef]) -> (TokenStream, TokenStream) {
    (generate_before_snapshots(fields), generate_after_reads(fields))
}

// ==========================================================================
// Field resolution helpers
// ==========================================================================

/// Resolve a field reference string like `"market.vault_balance"` into its
/// account name and field path components.
pub fn parse_field_ref(field_ref: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = field_ref.splitn(2, '.').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

/// Compute the fixed byte offset for a list of preceding fixed-size fields.
///
/// `preceding_sizes` is the byte size of each field before the target, in order.
/// The discriminator (8 bytes) is automatically included.
pub fn compute_fixed_offset(preceding_sizes: &[usize]) -> usize {
    let mut offset = 8; // Anchor discriminator
    for &size in preceding_sizes {
        offset += size;
    }
    offset
}

// ==========================================================================
// Field resolution from sandbox.toml account configs
// ==========================================================================

/// Parse a type string (e.g., "u64", "Pubkey") into a `FieldType`.
pub fn parse_field_type(type_str: &str) -> Result<FieldType, String> {
    match type_str {
        "u8" => Ok(FieldType::U8),
        "u16" => Ok(FieldType::U16),
        "u32" => Ok(FieldType::U32),
        "u64" => Ok(FieldType::U64),
        "i8" => Ok(FieldType::I8),
        "i16" => Ok(FieldType::I16),
        "i32" => Ok(FieldType::I32),
        "i64" => Ok(FieldType::I64),
        "bool" => Ok(FieldType::Bool),
        "Pubkey" => Ok(FieldType::Pubkey),
        other => Err(format!("Unknown field type: '{}'. Expected one of: u8, u16, u32, u64, i8, i16, i32, i64, bool, Pubkey", other)),
    }
}

/// Compute the fixed byte size of a Borsh-serialized type descriptor string.
///
/// Returns `Some(size)` for fixed-size types, `None` for variable-length types
/// (which should use `parse_borsh_skip_step` instead).
fn fixed_type_size(type_str: &str) -> Option<usize> {
    match type_str {
        "u8" | "i8" | "bool" => Some(1),
        "u16" | "i16" => Some(2),
        "u32" | "i32" => Some(4),
        "u64" | "i64" | "f64" => Some(8),
        "u128" | "i128" => Some(16),
        "Pubkey" => Some(32),
        s if s.starts_with('[') && s.ends_with(']') => {
            // Parse [u8; N] style arrays
            parse_array_size(s)
        }
        _ => None,
    }
}

/// Parse a `[T; N]` array type and return its total byte size.
fn parse_array_size(s: &str) -> Option<usize> {
    // Strip brackets: "[u8; 32]" -> "u8; 32"
    let inner = s.strip_prefix('[')?.strip_suffix(']')?.trim();
    let parts: Vec<&str> = inner.splitn(2, ';').collect();
    if parts.len() != 2 {
        return None;
    }
    let elem_type = parts[0].trim();
    let count: usize = parts[1].trim().parse().ok()?;
    let elem_size = fixed_type_size(elem_type)?;
    elem_size.checked_mul(count)
}

/// Parse a type descriptor string into the inner size for Option/Vec wrappers.
/// E.g., "Pubkey" -> 32, "u64" -> 8.
fn inner_size_of(type_str: &str) -> Result<usize, String> {
    fixed_type_size(type_str).ok_or_else(|| {
        format!(
            "Cannot compute inner size for '{}' — only fixed-size types are supported inside Option/Vec",
            type_str
        )
    })
}

/// Parse an "after" type descriptor string into a `BorshSkipStep`.
///
/// Supports:
/// - Fixed types ("u64", "Pubkey", "[u8; 32]") → `BorshSkipStep::Fixed(size)`
/// - `"Option<T>"` → `BorshSkipStep::Option(inner_size)`
/// - `"Vec<T>"` → `BorshSkipStep::Vec(element_size)` (or `String` for `Vec<u8>`)
/// - `"String"` → `BorshSkipStep::String`
pub fn parse_borsh_skip_step(type_str: &str) -> Result<BorshSkipStep, String> {
    let trimmed = type_str.trim();

    // String
    if trimmed == "String" {
        return Ok(BorshSkipStep::String);
    }

    // Option<T>
    if let Some(inner) = trimmed.strip_prefix("Option<").and_then(|s| s.strip_suffix('>')) {
        let inner = inner.trim();
        let size = inner_size_of(inner)?;
        return Ok(BorshSkipStep::Option(size));
    }

    // Vec<T>
    if let Some(inner) = trimmed.strip_prefix("Vec<").and_then(|s| s.strip_suffix('>')) {
        let inner = inner.trim();
        if inner == "u8" {
            // Vec<u8> has same wire format as String (u32 len + bytes)
            return Ok(BorshSkipStep::String);
        }
        let elem_size = inner_size_of(inner)?;
        return Ok(BorshSkipStep::Vec(elem_size));
    }

    // Fixed-size type
    if let Some(size) = fixed_type_size(trimmed) {
        return Ok(BorshSkipStep::Fixed(size));
    }

    Err(format!(
        "Unknown type descriptor '{}' in 'after' list. \
         Supported: u8, u16, u32, u64, i8, i16, i32, i64, bool, Pubkey, \
         [T; N], Option<T>, Vec<T>, String",
        trimmed
    ))
}

/// Build a `SnapshotStrategy` from a `FieldConfig`.
fn build_strategy(field_config: &FieldConfig) -> Result<SnapshotStrategy, String> {
    match (&field_config.offset, &field_config.after) {
        (Some(offset), None) => Ok(SnapshotStrategy::FixedOffset(*offset)),
        (None, Some(after_types)) => {
            let steps: Result<Vec<BorshSkipStep>, String> = after_types
                .iter()
                .map(|t| parse_borsh_skip_step(t))
                .collect();
            Ok(SnapshotStrategy::BorshDeserPrefix(steps?))
        }
        (Some(_), Some(_)) => Err(
            "Field config must specify either 'offset' (Strategy A) or 'after' (Strategy B), not both".to_string()
        ),
        (None, None) => Err(
            "Field config must specify either 'offset' (Strategy A) or 'after' (Strategy B)".to_string()
        ),
    }
}

/// Resolve a field path string (e.g., "market.vault_balance") to a `FieldRef`
/// using the account configs from `sandbox.toml`.
///
/// # Errors
/// Returns an error if:
/// - The field path format is invalid (missing `.`)
/// - The account name is not found in the config
/// - The field name is not found in the account's fields
/// - The field type is unrecognized
/// - The strategy config is invalid (neither offset nor after, or both)
pub fn resolve_field_ref(
    field_path: &str,
    accounts_config: &HashMap<String, AccountConfig>,
) -> Result<FieldRef, String> {
    let (account_name, field_name) = parse_field_ref(field_path).ok_or_else(|| {
        format!(
            "Invalid field path '{}': expected 'account.field' format",
            field_path
        )
    })?;

    let account = accounts_config.get(&account_name).ok_or_else(|| {
        format!(
            "Unknown account '{}' in field path '{}'. \
             Define it in sandbox.toml under [accounts.{}]",
            account_name, field_path, account_name
        )
    })?;

    let field_config = account.fields.get(&field_name).ok_or_else(|| {
        format!(
            "Unknown field '{}' in account '{}'. \
             Define it in sandbox.toml under [accounts.{}.fields]",
            field_name, account_name, account_name
        )
    })?;

    let field_type = parse_field_type(&field_config.field_type)?;
    let strategy = build_strategy(field_config)?;
    // Use discriminator length if provided, default to 8 (Anchor standard)
    let discriminator_size = match &account.discriminator {
        Some(d) if d.is_empty() => return Err(format!(
            "Account '{}' has empty discriminator — use no discriminator field or provide the full bytes",
            account_name
        )),
        Some(d) => d.len(),
        None => 8,
    };

    Ok(FieldRef {
        account_name,
        field_path: field_name,
        field_type,
        strategy,
        discriminator_size,
    })
}

/// Resolve multiple field path strings into `FieldRef`s, deduplicating.
/// Returns an error on the first unresolvable field.
pub fn resolve_field_refs(
    field_paths: &[String],
    accounts_config: &HashMap<String, AccountConfig>,
) -> Result<Vec<FieldRef>, String> {
    let mut seen = std::collections::HashSet::new();
    let mut refs = Vec::new();
    for path in field_paths {
        if seen.insert(path.clone()) {
            refs.push(resolve_field_ref(path, accounts_config)?);
        }
    }
    Ok(refs)
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AccountConfig, FieldConfig};

    fn make_fixed_field(account: &str, field: &str, ty: FieldType, offset: usize) -> FieldRef {
        FieldRef {
            account_name: account.to_string(),
            field_path: field.to_string(),
            field_type: ty,
            strategy: SnapshotStrategy::FixedOffset(offset),
            discriminator_size: 8,
        }
    }

    fn make_borsh_field(
        account: &str,
        field: &str,
        ty: FieldType,
        steps: Vec<BorshSkipStep>,
    ) -> FieldRef {
        FieldRef {
            account_name: account.to_string(),
            field_path: field.to_string(),
            field_type: ty,
            strategy: SnapshotStrategy::BorshDeserPrefix(steps),
            discriminator_size: 8,
        }
    }

    #[test]
    fn test_field_type_sizes() {
        assert_eq!(FieldType::U8.byte_size(), 1);
        assert_eq!(FieldType::U16.byte_size(), 2);
        assert_eq!(FieldType::U32.byte_size(), 4);
        assert_eq!(FieldType::U64.byte_size(), 8);
        assert_eq!(FieldType::I64.byte_size(), 8);
        assert_eq!(FieldType::Bool.byte_size(), 1);
        assert_eq!(FieldType::Pubkey.byte_size(), 32);
    }

    #[test]
    fn test_compute_fixed_offset() {
        let offset = compute_fixed_offset(&[8, 32]);
        assert_eq!(offset, 48);
    }

    #[test]
    fn test_compute_fixed_offset_empty() {
        assert_eq!(compute_fixed_offset(&[]), 8);
    }

    #[test]
    fn test_parse_field_ref() {
        let (account, field) = parse_field_ref("market.vault_balance").unwrap();
        assert_eq!(account, "market");
        assert_eq!(field, "vault_balance");
    }

    #[test]
    fn test_parse_field_ref_no_dot() {
        assert!(parse_field_ref("no_dot").is_none());
    }

    #[test]
    fn test_generate_fixed_offset_snapshot() {
        let field = make_fixed_field("market", "vault_balance", FieldType::U64, 72);
        let code = generate_snapshot_read(&field, "__sb_market_vault_balance_before");
        let code_str = code.to_string();

        assert!(code_str.contains("snapshot_field_fixed"));
        assert!(code_str.contains("market"));
        assert!(code_str.contains("72"));
        assert!(code_str.contains("u64"));
    }

    #[test]
    fn test_generate_borsh_prefix_snapshot() {
        let steps = vec![
            BorshSkipStep::Fixed(32),
            BorshSkipStep::Option(32),
        ];
        let field = make_borsh_field("market", "vault_balance", FieldType::U64, steps);
        let code = generate_snapshot_read(&field, "__sb_market_vault_balance_before");
        let code_str = code.to_string();

        assert!(code_str.contains("__cursor"));
        assert!(code_str.contains("8"));
        assert!(code_str.contains("__tag"));
        assert!(code_str.contains("u64"));
    }

    #[test]
    fn test_generate_borsh_with_vec() {
        let steps = vec![BorshSkipStep::Vec(8)];
        let field = make_borsh_field("market", "price", FieldType::U64, steps);
        let code = generate_snapshot_read(&field, "__sb_market_price_before");
        let code_str = code.to_string();

        assert!(code_str.contains("__vec_len"));
        assert!(code_str.contains("checked_mul"));
    }

    #[test]
    fn test_generate_borsh_with_string() {
        let steps = vec![BorshSkipStep::String];
        let field = make_borsh_field("market", "value", FieldType::U32, steps);
        let code = generate_snapshot_read(&field, "__sb_market_value_before");
        let code_str = code.to_string();

        assert!(code_str.contains("__str_len"));
    }

    #[test]
    fn test_generate_before_snapshots() {
        let fields = vec![
            make_fixed_field("market", "vault_balance", FieldType::U64, 72),
            make_fixed_field("market", "total_collateral", FieldType::U64, 80),
        ];
        let code = generate_before_snapshots(&fields);
        let code_str = code.to_string();

        assert!(code_str.contains("__sb_market_vault_balance_before"));
        assert!(code_str.contains("__sb_market_total_collateral_before"));
    }

    #[test]
    fn test_generate_after_reads() {
        let fields = vec![
            make_fixed_field("market", "vault_balance", FieldType::U64, 72),
        ];
        let code = generate_after_reads(&fields);
        let code_str = code.to_string();

        assert!(code_str.contains("__sb_market_vault_balance_after"));
    }

    #[test]
    fn test_empty_fields_produce_empty_output() {
        let before = generate_before_snapshots(&[]);
        let after = generate_after_reads(&[]);
        assert!(before.is_empty());
        assert!(after.is_empty());
    }

    #[test]
    fn test_pubkey_field() {
        let field = make_fixed_field("market", "authority", FieldType::Pubkey, 8);
        let code = generate_snapshot_read(&field, "__sb_market_authority_before");
        let code_str = code.to_string();
        assert!(code_str.contains("32"));
        assert!(code_str.contains("Pubkey"));
    }

    #[test]
    fn test_bool_field() {
        let field = make_fixed_field("market", "is_active", FieldType::Bool, 100);
        let code = generate_snapshot_read(&field, "__sb_market_is_active_before");
        let code_str = code.to_string();
        assert!(code_str.contains("bool"));
        assert!(code_str.contains("!= 0"));
    }

    #[test]
    fn test_var_slug() {
        let field = make_fixed_field("market", "vault_balance", FieldType::U64, 0);
        assert_eq!(field.var_slug(), "market_vault_balance");
    }

    #[test]
    fn test_snapshot_wrapper() {
        let fields = vec![
            make_fixed_field("market", "vault_balance", FieldType::U64, 72),
        ];
        let (before, after) = generate_snapshot_wrapper(&fields);
        assert!(!before.is_empty());
        assert!(!after.is_empty());
    }

    #[test]
    fn test_all_skip_step_variants_in_sequence() {
        let steps = vec![
            BorshSkipStep::Fixed(8),
            BorshSkipStep::Option(32),
            BorshSkipStep::Vec(16),
            BorshSkipStep::String,
            BorshSkipStep::Fixed(4),
        ];
        let field = make_borsh_field("account", "target", FieldType::U64, steps);
        let code = generate_snapshot_read(&field, "__sb_account_target_before");
        let code_str = code.to_string();

        assert!(code_str.contains("__tag"));
        assert!(code_str.contains("__vec_len"));
        assert!(code_str.contains("__str_len"));
        assert!(code_str.contains("checked_add"));
    }

    // ── Field resolution tests ──

    fn make_test_accounts() -> HashMap<String, AccountConfig> {
        let mut accounts = HashMap::new();

        let mut market_fields = HashMap::new();
        market_fields.insert("vault_balance".to_string(), FieldConfig {
            field_type: "u64".to_string(),
            offset: Some(72),
            after: None,
        });
        market_fields.insert("total_collateral".to_string(), FieldConfig {
            field_type: "u64".to_string(),
            offset: Some(80),
            after: None,
        });
        market_fields.insert("authority".to_string(), FieldConfig {
            field_type: "Pubkey".to_string(),
            offset: None,
            after: Some(vec!["Option<Pubkey>".to_string()]),
        });
        market_fields.insert("name".to_string(), FieldConfig {
            field_type: "u64".to_string(),
            offset: None,
            after: Some(vec!["String".to_string(), "Vec<u64>".to_string()]),
        });

        accounts.insert("market".to_string(), AccountConfig {
            account_type: "Market".to_string(),
            discriminator: None,
            fields: market_fields,
        });

        let mut position_fields = HashMap::new();
        position_fields.insert("owner".to_string(), FieldConfig {
            field_type: "Pubkey".to_string(),
            offset: Some(8),
            after: None,
        });
        position_fields.insert("collateral".to_string(), FieldConfig {
            field_type: "u64".to_string(),
            offset: Some(40),
            after: None,
        });

        accounts.insert("position".to_string(), AccountConfig {
            account_type: "UserPosition".to_string(),
            discriminator: None,
            fields: position_fields,
        });

        accounts
    }

    #[test]
    fn test_resolve_fixed_offset() {
        let accounts = make_test_accounts();
        let field_ref = resolve_field_ref("market.vault_balance", &accounts).unwrap();
        assert_eq!(field_ref.account_name, "market");
        assert_eq!(field_ref.field_path, "vault_balance");
        assert_eq!(field_ref.field_type, FieldType::U64);
        assert_eq!(field_ref.strategy, SnapshotStrategy::FixedOffset(72));
    }

    #[test]
    fn test_resolve_borsh_prefix_option() {
        let accounts = make_test_accounts();
        let field_ref = resolve_field_ref("market.authority", &accounts).unwrap();
        assert_eq!(field_ref.account_name, "market");
        assert_eq!(field_ref.field_path, "authority");
        assert_eq!(field_ref.field_type, FieldType::Pubkey);
        match &field_ref.strategy {
            SnapshotStrategy::BorshDeserPrefix(steps) => {
                assert_eq!(steps.len(), 1);
                assert_eq!(steps[0], BorshSkipStep::Option(32));
            }
            other => panic!("Expected BorshDeserPrefix, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_borsh_prefix_string_and_vec() {
        let accounts = make_test_accounts();
        let field_ref = resolve_field_ref("market.name", &accounts).unwrap();
        match &field_ref.strategy {
            SnapshotStrategy::BorshDeserPrefix(steps) => {
                assert_eq!(steps.len(), 2);
                assert_eq!(steps[0], BorshSkipStep::String);
                assert_eq!(steps[1], BorshSkipStep::Vec(8));
            }
            other => panic!("Expected BorshDeserPrefix, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_unknown_account() {
        let accounts = make_test_accounts();
        let err = resolve_field_ref("nonexistent.field", &accounts).unwrap_err();
        assert!(err.contains("Unknown account 'nonexistent'"), "got: {}", err);
    }

    #[test]
    fn test_resolve_unknown_field() {
        let accounts = make_test_accounts();
        let err = resolve_field_ref("market.nonexistent", &accounts).unwrap_err();
        assert!(err.contains("Unknown field 'nonexistent'"), "got: {}", err);
    }

    #[test]
    fn test_resolve_invalid_path_format() {
        let accounts = make_test_accounts();
        let err = resolve_field_ref("no_dot_here", &accounts).unwrap_err();
        assert!(err.contains("Invalid field path"), "got: {}", err);
    }

    #[test]
    fn test_parse_field_type_all() {
        assert_eq!(parse_field_type("u8").unwrap(), FieldType::U8);
        assert_eq!(parse_field_type("u16").unwrap(), FieldType::U16);
        assert_eq!(parse_field_type("u32").unwrap(), FieldType::U32);
        assert_eq!(parse_field_type("u64").unwrap(), FieldType::U64);
        assert_eq!(parse_field_type("i8").unwrap(), FieldType::I8);
        assert_eq!(parse_field_type("i16").unwrap(), FieldType::I16);
        assert_eq!(parse_field_type("i32").unwrap(), FieldType::I32);
        assert_eq!(parse_field_type("i64").unwrap(), FieldType::I64);
        assert_eq!(parse_field_type("bool").unwrap(), FieldType::Bool);
        assert_eq!(parse_field_type("Pubkey").unwrap(), FieldType::Pubkey);
        assert!(parse_field_type("String").is_err());
    }

    #[test]
    fn test_parse_borsh_skip_step_fixed() {
        assert_eq!(parse_borsh_skip_step("u64").unwrap(), BorshSkipStep::Fixed(8));
        assert_eq!(parse_borsh_skip_step("Pubkey").unwrap(), BorshSkipStep::Fixed(32));
        assert_eq!(parse_borsh_skip_step("bool").unwrap(), BorshSkipStep::Fixed(1));
        assert_eq!(parse_borsh_skip_step("[u8; 32]").unwrap(), BorshSkipStep::Fixed(32));
    }

    #[test]
    fn test_parse_borsh_skip_step_option() {
        assert_eq!(parse_borsh_skip_step("Option<Pubkey>").unwrap(), BorshSkipStep::Option(32));
        assert_eq!(parse_borsh_skip_step("Option<u64>").unwrap(), BorshSkipStep::Option(8));
    }

    #[test]
    fn test_parse_borsh_skip_step_vec() {
        assert_eq!(parse_borsh_skip_step("Vec<u64>").unwrap(), BorshSkipStep::Vec(8));
        assert_eq!(parse_borsh_skip_step("Vec<Pubkey>").unwrap(), BorshSkipStep::Vec(32));
    }

    #[test]
    fn test_parse_borsh_skip_step_vec_u8_is_string() {
        assert_eq!(parse_borsh_skip_step("Vec<u8>").unwrap(), BorshSkipStep::String);
    }

    #[test]
    fn test_parse_borsh_skip_step_string() {
        assert_eq!(parse_borsh_skip_step("String").unwrap(), BorshSkipStep::String);
    }

    #[test]
    fn test_parse_borsh_skip_step_unknown() {
        assert!(parse_borsh_skip_step("HashMap<u64, u64>").is_err());
    }

    #[test]
    fn test_build_strategy_both_offset_and_after_errors() {
        let config = FieldConfig {
            field_type: "u64".to_string(),
            offset: Some(8),
            after: Some(vec!["u64".to_string()]),
        };
        let err = build_strategy(&config).unwrap_err();
        assert!(err.contains("not both"), "got: {}", err);
    }

    #[test]
    fn test_build_strategy_neither_errors() {
        let config = FieldConfig {
            field_type: "u64".to_string(),
            offset: None,
            after: None,
        };
        let err = build_strategy(&config).unwrap_err();
        assert!(err.contains("must specify either"), "got: {}", err);
    }

    #[test]
    fn test_resolve_field_refs_deduplicates() {
        let accounts = make_test_accounts();
        let paths = vec![
            "market.vault_balance".to_string(),
            "market.vault_balance".to_string(),
            "position.collateral".to_string(),
        ];
        let refs = resolve_field_refs(&paths, &accounts).unwrap();
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_resolve_then_generate_snapshot() {
        let accounts = make_test_accounts();
        let field_ref = resolve_field_ref("market.vault_balance", &accounts).unwrap();
        let var_name = format!("__sb_{}_before", field_ref.var_slug());
        let code = generate_snapshot_read(&field_ref, &var_name);
        let code_str = code.to_string();
        assert!(code_str.contains("snapshot_field_fixed"));
        assert!(code_str.contains("72"));
        assert!(code_str.contains("u64"));
    }

    #[test]
    fn test_resolve_then_generate_before_after() {
        let accounts = make_test_accounts();
        let paths = vec![
            "market.vault_balance".to_string(),
            "position.collateral".to_string(),
        ];
        let field_refs = resolve_field_refs(&paths, &accounts).unwrap();
        let (before, after) = generate_snapshot_wrapper(&field_refs);
        let before_str = before.to_string();
        let after_str = after.to_string();
        assert!(before_str.contains("__sb_market_vault_balance_before"));
        assert!(before_str.contains("__sb_position_collateral_before"));
        assert!(after_str.contains("__sb_market_vault_balance_after"));
        assert!(after_str.contains("__sb_position_collateral_after"));
    }

    // ══════════════════════════════════════════════════════════════════
    // Edge case tests
    // ══════════════════════════════════════════════════════════════════

    // 1. Single-character account name
    #[test]
    fn test_resolve_single_char_account_name() {
        let mut accounts = HashMap::new();
        let mut fields = HashMap::new();
        fields.insert("x".to_string(), FieldConfig {
            field_type: "u64".to_string(),
            offset: Some(8),
            after: None,
        });
        accounts.insert("m".to_string(), AccountConfig {
            account_type: "M".to_string(),
            discriminator: None,
            fields,
        });
        let r = resolve_field_ref("m.x", &accounts).unwrap();
        assert_eq!(r.account_name, "m");
        assert_eq!(r.field_path, "x");
        assert_eq!(r.field_type, FieldType::U64);
        assert_eq!(r.strategy, SnapshotStrategy::FixedOffset(8));
    }

    // 2. Deeply nested field path "a.b.c.d" — splitn(2) keeps rest as field
    #[test]
    fn test_resolve_deeply_nested_field_path() {
        let mut accounts = HashMap::new();
        let mut fields = HashMap::new();
        // The field name after splitn(2, '.') is "b.c.d"
        fields.insert("b.c.d".to_string(), FieldConfig {
            field_type: "u32".to_string(),
            offset: Some(16),
            after: None,
        });
        accounts.insert("a".to_string(), AccountConfig {
            account_type: "A".to_string(),
            discriminator: None,
            fields,
        });
        // Should resolve: account="a", field="b.c.d"
        let r = resolve_field_ref("a.b.c.d", &accounts).unwrap();
        assert_eq!(r.account_name, "a");
        assert_eq!(r.field_path, "b.c.d");
    }

    // 2b. Deeply nested field path where field doesn't exist → error
    #[test]
    fn test_resolve_deeply_nested_field_path_missing() {
        let accounts = make_test_accounts();
        let err = resolve_field_ref("market.a.b.c", &accounts).unwrap_err();
        assert!(err.contains("Unknown field 'a.b.c'"), "got: {}", err);
    }

    // 3. Nested Option: Option<Option<u64>> — inner is not fixed-size
    #[test]
    fn test_parse_borsh_skip_nested_option() {
        let result = parse_borsh_skip_step("Option<Option<u64>>");
        assert!(result.is_err(), "Nested Option should fail: inner Option<u64> is not fixed-size");
        let err = result.unwrap_err();
        assert!(err.contains("Cannot compute inner size"), "got: {}", err);
    }

    // 4. Nested Vec: Vec<Vec<u64>> — inner is not fixed-size
    #[test]
    fn test_parse_borsh_skip_nested_vec() {
        let result = parse_borsh_skip_step("Vec<Vec<u64>>");
        assert!(result.is_err(), "Nested Vec should fail: inner Vec<u64> is not fixed-size");
        let err = result.unwrap_err();
        assert!(err.contains("Cannot compute inner size"), "got: {}", err);
    }

    // 5. Zero-length array [u8; 0]
    #[test]
    fn test_parse_borsh_skip_zero_length_array() {
        let step = parse_borsh_skip_step("[u8; 0]").unwrap();
        assert_eq!(step, BorshSkipStep::Fixed(0));
    }

    // 6. Huge array [u8; 999999999]
    #[test]
    fn test_parse_borsh_skip_huge_array() {
        let step = parse_borsh_skip_step("[u8; 999999999]").unwrap();
        assert_eq!(step, BorshSkipStep::Fixed(999_999_999));
    }

    // 7. Empty after list → BorshDeserPrefix with zero steps
    #[test]
    fn test_build_strategy_empty_after() {
        let config = FieldConfig {
            field_type: "u64".to_string(),
            offset: None,
            after: Some(vec![]),
        };
        let strategy = build_strategy(&config).unwrap();
        assert_eq!(strategy, SnapshotStrategy::BorshDeserPrefix(vec![]));
    }

    // 8. Both offset and after set → mutual exclusivity error
    #[test]
    fn test_build_strategy_both_offset_and_after() {
        let config = FieldConfig {
            field_type: "u64".to_string(),
            offset: Some(8),
            after: Some(vec!["u64".to_string()]),
        };
        let err = build_strategy(&config).unwrap_err();
        assert!(err.contains("not both"), "got: {}", err);
    }

    // 9. offset = 0 — valid (reads at the discriminator position)
    #[test]
    fn test_resolve_field_ref_offset_zero() {
        let mut accounts = HashMap::new();
        let mut fields = HashMap::new();
        fields.insert("disc".to_string(), FieldConfig {
            field_type: "u64".to_string(),
            offset: Some(0),
            after: None,
        });
        accounts.insert("acc".to_string(), AccountConfig {
            account_type: "Acc".to_string(),
            discriminator: None,
            fields,
        });
        let r = resolve_field_ref("acc.disc", &accounts).unwrap();
        assert_eq!(r.strategy, SnapshotStrategy::FixedOffset(0));
    }

    // 10. offset = usize::MAX — accepted at config level (would overflow at runtime)
    #[test]
    fn test_resolve_field_ref_offset_max() {
        let mut accounts = HashMap::new();
        let mut fields = HashMap::new();
        fields.insert("big".to_string(), FieldConfig {
            field_type: "u8".to_string(),
            offset: Some(usize::MAX),
            after: None,
        });
        accounts.insert("acc".to_string(), AccountConfig {
            account_type: "Acc".to_string(),
            discriminator: None,
            fields,
        });
        let r = resolve_field_ref("acc.big", &accounts).unwrap();
        assert_eq!(r.strategy, SnapshotStrategy::FixedOffset(usize::MAX));
    }

    // 11. parse_field_type with empty string
    #[test]
    fn test_parse_field_type_empty() {
        let err = parse_field_type("").unwrap_err();
        assert!(err.contains("Unknown field type: ''"), "got: {}", err);
    }

    // 12. parse_field_type with wrong case "U64"
    #[test]
    fn test_parse_field_type_wrong_case() {
        let err = parse_field_type("U64").unwrap_err();
        assert!(err.contains("Unknown field type: 'U64'"), "got: {}", err);
    }

    // 13. Multiple fields from same account — dedup in resolve_field_refs
    #[test]
    fn test_resolve_field_refs_dedup_same_account() {
        let accounts = make_test_accounts();
        let paths = vec![
            "market.vault_balance".to_string(),
            "market.vault_balance".to_string(),
            "market.total_collateral".to_string(),
            "market.total_collateral".to_string(),
        ];
        let refs = resolve_field_refs(&paths, &accounts).unwrap();
        assert_eq!(refs.len(), 2, "Expected dedup to 2, got {}", refs.len());
        assert_eq!(refs[0].field_path, "vault_balance");
        assert_eq!(refs[1].field_path, "total_collateral");
    }

    // 14. Fields from different accounts — no dedup
    #[test]
    fn test_resolve_field_refs_no_dedup_different_accounts() {
        let accounts = make_test_accounts();
        let paths = vec![
            "market.vault_balance".to_string(),
            "position.collateral".to_string(),
            "position.owner".to_string(),
        ];
        let refs = resolve_field_refs(&paths, &accounts).unwrap();
        assert_eq!(refs.len(), 3, "All different paths should be kept");
    }

    // 15. Very long account name / field name
    #[test]
    fn test_resolve_very_long_names() {
        let long_account = "a".repeat(256);
        let long_field = "b".repeat(256);
        let mut accounts = HashMap::new();
        let mut fields = HashMap::new();
        fields.insert(long_field.clone(), FieldConfig {
            field_type: "u64".to_string(),
            offset: Some(8),
            after: None,
        });
        accounts.insert(long_account.clone(), AccountConfig {
            account_type: "LongType".to_string(),
            discriminator: None,
            fields,
        });
        let path = format!("{}.{}", long_account, long_field);
        let r = resolve_field_ref(&path, &accounts).unwrap();
        assert_eq!(r.account_name, long_account);
        assert_eq!(r.field_path, long_field);
        assert_eq!(r.var_slug().len(), 256 + 1 + 256); // name + "_" + field
    }

    // Bonus: parse_field_ref with leading dot
    #[test]
    fn test_parse_field_ref_leading_dot() {
        let result = parse_field_ref(".field");
        // splitn(2, '.') => ["", "field"] — account name is empty
        let (account, field) = result.unwrap();
        assert_eq!(account, "");
        assert_eq!(field, "field");
    }

    // Bonus: parse_field_ref with trailing dot
    #[test]
    fn test_parse_field_ref_trailing_dot() {
        let result = parse_field_ref("account.");
        let (account, field) = result.unwrap();
        assert_eq!(account, "account");
        assert_eq!(field, "");
    }

    // Bonus: resolve_field_ref with empty account name via leading dot
    #[test]
    fn test_resolve_field_ref_empty_account() {
        let accounts = make_test_accounts();
        let err = resolve_field_ref(".vault_balance", &accounts).unwrap_err();
        assert!(err.contains("Unknown account ''"), "got: {}", err);
    }

    // Bonus: resolve_field_ref with empty field name via trailing dot
    #[test]
    fn test_resolve_field_ref_empty_field() {
        let accounts = make_test_accounts();
        let err = resolve_field_ref("market.", &accounts).unwrap_err();
        assert!(err.contains("Unknown field ''"), "got: {}", err);
    }

    // Bonus: parse_borsh_skip_step with whitespace-only string
    #[test]
    fn test_parse_borsh_skip_step_whitespace() {
        let result = parse_borsh_skip_step("   ");
        assert!(result.is_err());
    }

    // Bonus: generate code with empty BorshDeserPrefix steps
    #[test]
    fn test_generate_borsh_prefix_empty_steps() {
        let field = make_borsh_field("acc", "f", FieldType::U64, vec![]);
        let code = generate_snapshot_read(&field, "__sb_acc_f_before");
        let code_str = code.to_string();
        // Should still have cursor logic, just no skip steps
        assert!(code_str.contains("__cursor"));
        assert!(code_str.contains("u64"));
    }

    #[test]
    fn test_parse_field_config_from_toml() {
        let toml_str = r#"
[market]
type = "Market"
discriminator = [1, 2, 3, 4, 5, 6, 7, 8]

[market.fields]
vault_balance = { type = "u64", offset = 72 }
authority = { type = "Pubkey", after = ["Option<Pubkey>"] }

[position]
type = "UserPosition"

[position.fields]
owner = { type = "Pubkey", offset = 8 }
"#;
        let accounts: HashMap<String, AccountConfig> = toml::from_str(toml_str).unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts["market"].account_type, "Market");
        assert_eq!(accounts["market"].discriminator.as_ref().unwrap().len(), 8);
        assert_eq!(accounts["market"].fields["vault_balance"].offset, Some(72));
        assert_eq!(accounts["market"].fields["authority"].after.as_ref().unwrap()[0], "Option<Pubkey>");
        assert_eq!(accounts["position"].fields["owner"].field_type, "Pubkey");
    }

    // ══════════════════════════════════════════════════════════════════
    // R1 hardening edge-case tests
    // ══════════════════════════════════════════════════════════════════

    // 1. Bool field codegen: byte value > 1 must trigger error path
    #[test]
    fn test_bool_codegen_rejects_invalid_byte() {
        let field = make_fixed_field("acc", "flag", FieldType::Bool, 8);
        let code = generate_snapshot_read(&field, "__sb_acc_flag_before");
        let code_str = code.to_string();
        // The hardened Bool conversion checks buf[0] > 1 and returns error
        assert!(code_str.contains("> 1"), "Bool codegen must check for byte > 1");
        assert!(code_str.contains("6073"), "Bool codegen must return error 6073 for invalid byte");
    }

    // 2. Bool field codegen: byte value 0 → false
    #[test]
    fn test_bool_codegen_zero_is_false() {
        let field = make_fixed_field("acc", "flag", FieldType::Bool, 8);
        let code = generate_snapshot_read(&field, "__sb_acc_flag_before");
        let code_str = code.to_string();
        // The expression `buf[0] != 0` means 0 produces false
        assert!(code_str.contains("!= 0"), "Bool codegen must use != 0 for conversion");
    }

    // 3. Bool field codegen: byte value 1 → true (covered by != 0)
    #[test]
    fn test_bool_codegen_one_is_true() {
        let buf_ident = format_ident!("__buf");
        let expr = FieldType::Bool.from_bytes_expr(&buf_ident);
        let expr_str = expr.to_string();
        // After the > 1 guard, `!= 0` ensures 1 maps to true
        assert!(expr_str.contains("!= 0"), "Bool conversion uses != 0");
        assert!(expr_str.contains("> 1"), "Bool conversion guards > 1");
    }

    // 4. FieldRef with discriminator_size = 0 → cursor starts at 0
    #[test]
    fn test_field_ref_discriminator_size_zero() {
        let field = FieldRef {
            account_name: "acc".to_string(),
            field_path: "val".to_string(),
            field_type: FieldType::U64,
            strategy: SnapshotStrategy::BorshDeserPrefix(vec![BorshSkipStep::Fixed(4)]),
            discriminator_size: 0,
        };
        let code = generate_snapshot_read(&field, "__sb_acc_val_before");
        let code_str = code.to_string();
        // With disc_size=0, `let mut __cursor : usize = 0usize ;`
        assert!(code_str.contains("0usize"), "cursor must start at 0 when discriminator_size=0, got: {}", code_str);
    }

    // 5. FieldRef with discriminator_size = 4 → cursor starts at 4
    #[test]
    fn test_field_ref_discriminator_size_four() {
        let field = FieldRef {
            account_name: "acc".to_string(),
            field_path: "val".to_string(),
            field_type: FieldType::U64,
            strategy: SnapshotStrategy::BorshDeserPrefix(vec![]),
            discriminator_size: 4,
        };
        let code = generate_snapshot_read(&field, "__sb_acc_val_before");
        let code_str = code.to_string();
        assert!(code_str.contains("4usize"), "cursor must start at 4 when discriminator_size=4, got: {}", code_str);
    }

    // 6. FieldRef with discriminator_size = 16 (large discriminator)
    #[test]
    fn test_field_ref_discriminator_size_sixteen() {
        let field = FieldRef {
            account_name: "acc".to_string(),
            field_path: "val".to_string(),
            field_type: FieldType::U32,
            strategy: SnapshotStrategy::BorshDeserPrefix(vec![BorshSkipStep::Fixed(8)]),
            discriminator_size: 16,
        };
        let code = generate_snapshot_read(&field, "__sb_acc_val_before");
        let code_str = code.to_string();
        assert!(code_str.contains("16usize"), "cursor must start at 16 when discriminator_size=16, got: {}", code_str);
    }

    // 7. parse_array_size overflow: element_size * count overflows usize
    #[test]
    fn test_parse_array_size_overflow() {
        // u64 = 8 bytes, 2305843009213693952 * 8 overflows u64
        let result = parse_array_size("[u64; 2305843009213693952]");
        assert_eq!(result, None, "Should return None on overflow from checked_mul");
    }

    // 8. parse_array_size with zero-length array
    #[test]
    fn test_parse_array_size_zero_length() {
        let result = parse_array_size("[u8; 0]");
        assert_eq!(result, Some(0), "Zero-length array should have size 0");
    }

    // 9. Option skip: tag=2 triggers fail-closed reject in generated code
    #[test]
    fn test_option_skip_rejects_invalid_tag_in_codegen() {
        let steps = vec![BorshSkipStep::Option(8)];
        let code = generate_skip_steps(&steps);
        let code_str = code.to_string();
        // The match arm `_ =>` must exist for fail-closed on invalid Option tag
        assert!(code_str.contains("_ =>"), "Option skip must have catch-all arm for invalid tags (e.g. tag=2)");
        assert!(code_str.contains("6073"), "Option skip must return error 6073 on invalid tag");
        // Only tags 0 and 1 are valid
        assert!(code_str.contains("0 =>"), "Option skip must handle tag 0 (None)");
        assert!(code_str.contains("1 =>"), "Option skip must handle tag 1 (Some)");
    }

    // 10. Resolve with empty discriminator vec → disc_size = 0
    #[test]
    fn test_resolve_empty_discriminator_vec() {
        let mut accounts = HashMap::new();
        let mut fields = HashMap::new();
        fields.insert("val".to_string(), FieldConfig {
            field_type: "u64".to_string(),
            offset: None,
            after: Some(vec!["u32".to_string()]),
        });
        accounts.insert("acc".to_string(), AccountConfig {
            account_type: "Acc".to_string(),
            discriminator: Some(vec![]),  // empty discriminator
            fields,
        });
        // Empty discriminator should now be rejected (fail-closed)
        let r = resolve_field_ref("acc.val", &accounts);
        assert!(r.is_err(), "Empty discriminator should be rejected");
        assert!(r.unwrap_err().contains("empty discriminator"));
    }
}

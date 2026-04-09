//! Sandbox State PDA — manual byte-level serialization.
//!
//! Layout follows SPEC §8.2. No `#[repr(C)]`, no Borsh derives.
//! Every read is bounds-checked; every arithmetic op is checked.
//! Corruption → fail-closed → `SandboxError::PDACorrupted`.

use solana_program::pubkey::Pubkey;

use crate::error::SandboxError;

// ── Constants ──────────────────────────────────────────────────────────────

/// Current schema version. Bump on layout changes.
pub const SANDBOX_STATE_VERSION: u8 = 1;

/// 8-byte discriminator: "PRKSANDX"
pub const DISCRIMINATOR: [u8; 8] = *b"PRKSANDX";

/// Fixed header size (bytes 0..64).
pub const HEADER_SIZE: usize = 64;

// Header field offsets
pub const OFF_DISCRIMINATOR: usize = 0; // [0..8]
pub const OFF_VERSION: usize = 8; // [8]
pub const OFF_BUMP: usize = 9; // [9]
pub const OFF_TOTAL_SIZE: usize = 10; // [10..12]
pub const OFF_MODE_FLAGS: usize = 12; // [12..14]
pub const OFF_CIRCUIT_BREAKER: usize = 14; // [14..16]
pub const OFF_RATE_LIMITS: usize = 16; // [16..18]
pub const OFF_GUARD: usize = 18; // [18..20]
pub const OFF_EMERGENCY: usize = 20; // [20..22]  (alias for mode_flags in this layout)
pub const OFF_TX_ANCHOR: usize = 22; // [22..24]
pub const OFF_EVENT_COUNTERS: usize = 24; // [24..26]
pub const OFF_RESERVED_OFFSETS: usize = 26; // [26..40]
pub const OFF_RESERVED: usize = 40; // [40..64]

// Section sizes
pub const MODE_FLAGS_SIZE: usize = 60;
pub const GUARD_SIZE: usize = 2;
pub const TX_ANCHOR_HEADER_SIZE: usize = 33; // fingerprint(32) + field_count(1)
pub const ANCHOR_FIELD_SIZE: usize = 42; // pubkey(32) + field_id(2) + value(8)
pub const MAX_ANCHOR_FIELDS: usize = 16;
pub const TVL_SNAPSHOT_SIZE: usize = 24; // value(8) + slot(8) + timestamp(8)
pub const CB_PER_CATEGORY_HEADER: usize = 37; // id(1) + history_len(2) + history_index(2) + max_value(8) + max_slot(8) + max_timestamp(8) + total_writes(8)
pub const RATE_LIMIT_PER_COUNTER: usize = 13; // id(1) + count(4) + window_start_slot(8)
pub const EVENT_COUNTER_SIZE: usize = 20; // count(4) + window_start_slot(8) + window_start_timestamp(8)

// SPL Token program IDs (for downstream use)
pub const SPL_TOKEN_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

// ── Compile-time offset sanity ─────────────────────────────────────────────

/// Asserts `$cond` at compile time.
macro_rules! const_assert {
    ($name:ident, $cond:expr) => {
        #[allow(dead_code)]
        const $name: () = assert!($cond);
    };
}

// No overlap between header fields
const_assert!(HDR_DISC_BEFORE_VER, OFF_DISCRIMINATOR + 8 <= OFF_VERSION);
const_assert!(HDR_VER_BEFORE_BUMP, OFF_VERSION + 1 <= OFF_BUMP);
const_assert!(HDR_BUMP_BEFORE_TOTAL, OFF_BUMP + 1 <= OFF_TOTAL_SIZE);
const_assert!(HDR_TOTAL_BEFORE_MODE, OFF_TOTAL_SIZE + 2 <= OFF_MODE_FLAGS);
const_assert!(HDR_MODE_BEFORE_CB, OFF_MODE_FLAGS + 2 <= OFF_CIRCUIT_BREAKER);
const_assert!(HDR_CB_BEFORE_RL, OFF_CIRCUIT_BREAKER + 2 <= OFF_RATE_LIMITS);
const_assert!(HDR_RL_BEFORE_GUARD, OFF_RATE_LIMITS + 2 <= OFF_GUARD);
const_assert!(HDR_GUARD_BEFORE_EMERG, OFF_GUARD + 2 <= OFF_EMERGENCY);
const_assert!(HDR_EMERG_BEFORE_TX, OFF_EMERGENCY + 2 <= OFF_TX_ANCHOR);
const_assert!(HDR_TX_BEFORE_EC, OFF_TX_ANCHOR + 2 <= OFF_EVENT_COUNTERS);
const_assert!(HDR_EC_BEFORE_RESERVED, OFF_EVENT_COUNTERS + 2 <= OFF_RESERVED_OFFSETS);
const_assert!(HDR_RESERVED_OFFSETS_FIT, OFF_RESERVED_OFFSETS + 14 <= OFF_RESERVED);
const_assert!(HDR_RESERVED_FIT, OFF_RESERVED + 24 <= HEADER_SIZE + 1); // ends at 64
const_assert!(HDR_SIZE_64, HEADER_SIZE == 64);

// Section sizes match spec
const_assert!(MODE_FLAGS_60, MODE_FLAGS_SIZE == 60);
const_assert!(GUARD_2, GUARD_SIZE == 2);
const_assert!(TVL_24, TVL_SNAPSHOT_SIZE == 24);
const_assert!(ANCHOR_FIELD_42, ANCHOR_FIELD_SIZE == 42);

// ── Low-level read/write helpers ───────────────────────────────────────────

#[inline]
fn read_u8(data: &[u8], offset: usize) -> Result<u8, SandboxError> {
    data.get(offset).copied().ok_or(SandboxError::PDACorrupted)
}

#[inline]
fn read_bool(data: &[u8], offset: usize) -> Result<bool, SandboxError> {
    let b = read_u8(data, offset)?;
    match b {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SandboxError::PDACorrupted), // not a valid bool
    }
}

#[inline]
fn read_u16(data: &[u8], offset: usize) -> Result<u16, SandboxError> {
    let end = offset.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
    let slice = data.get(offset..end).ok_or(SandboxError::PDACorrupted)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

#[inline]
fn read_u32(data: &[u8], offset: usize) -> Result<u32, SandboxError> {
    let end = offset.checked_add(4).ok_or(SandboxError::PDACorrupted)?;
    let slice = data.get(offset..end).ok_or(SandboxError::PDACorrupted)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
fn read_u64(data: &[u8], offset: usize) -> Result<u64, SandboxError> {
    let end = offset.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
    let slice = data.get(offset..end).ok_or(SandboxError::PDACorrupted)?;
    let arr: [u8; 8] = slice.try_into().map_err(|_| SandboxError::PDACorrupted)?;
    Ok(u64::from_le_bytes(arr))
}

#[inline]
fn read_i64(data: &[u8], offset: usize) -> Result<i64, SandboxError> {
    let end = offset.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
    let slice = data.get(offset..end).ok_or(SandboxError::PDACorrupted)?;
    let arr: [u8; 8] = slice.try_into().map_err(|_| SandboxError::PDACorrupted)?;
    Ok(i64::from_le_bytes(arr))
}

#[inline]
fn read_bytes<'a>(data: &'a [u8], offset: usize, len: usize) -> Result<&'a [u8], SandboxError> {
    let end = offset.checked_add(len).ok_or(SandboxError::PDACorrupted)?;
    data.get(offset..end).ok_or(SandboxError::PDACorrupted)
}

#[inline]
fn write_u8(data: &mut [u8], offset: usize, val: u8) -> Result<(), SandboxError> {
    *data.get_mut(offset).ok_or(SandboxError::PDACorrupted)? = val;
    Ok(())
}

#[inline]
fn write_bool(data: &mut [u8], offset: usize, val: bool) -> Result<(), SandboxError> {
    write_u8(data, offset, val as u8)
}

#[inline]
fn write_u16(data: &mut [u8], offset: usize, val: u16) -> Result<(), SandboxError> {
    let end = offset.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
    let slice = data.get_mut(offset..end).ok_or(SandboxError::PDACorrupted)?;
    slice.copy_from_slice(&val.to_le_bytes());
    Ok(())
}

#[inline]
fn write_u32(data: &mut [u8], offset: usize, val: u32) -> Result<(), SandboxError> {
    let end = offset.checked_add(4).ok_or(SandboxError::PDACorrupted)?;
    let slice = data.get_mut(offset..end).ok_or(SandboxError::PDACorrupted)?;
    slice.copy_from_slice(&val.to_le_bytes());
    Ok(())
}

#[inline]
fn write_u64(data: &mut [u8], offset: usize, val: u64) -> Result<(), SandboxError> {
    let end = offset.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
    let slice = data.get_mut(offset..end).ok_or(SandboxError::PDACorrupted)?;
    slice.copy_from_slice(&val.to_le_bytes());
    Ok(())
}

#[inline]
fn write_i64(data: &mut [u8], offset: usize, val: i64) -> Result<(), SandboxError> {
    let end = offset.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
    let slice = data.get_mut(offset..end).ok_or(SandboxError::PDACorrupted)?;
    slice.copy_from_slice(&val.to_le_bytes());
    Ok(())
}

#[inline]
fn write_bytes(data: &mut [u8], offset: usize, src: &[u8]) -> Result<(), SandboxError> {
    let end = offset.checked_add(src.len()).ok_or(SandboxError::PDACorrupted)?;
    let slice = data.get_mut(offset..end).ok_or(SandboxError::PDACorrupted)?;
    slice.copy_from_slice(src);
    Ok(())
}

// ── Data structures ────────────────────────────────────────────────────────

/// Mode flags — §8.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeFlags {
    pub paused: bool,
    pub close_only: bool,
    pub liquidation_paused: bool,
    pub emergency_bypass_active: bool,
    pub paused_at_slot: u64,
    pub pause_reason: [u8; 32],
    pub cooldown_end_slot: u64,
    pub emergency_bypass_end_slot: u64,
}

impl Default for ModeFlags {
    fn default() -> Self {
        Self {
            paused: false,
            close_only: false,
            liquidation_paused: false,
            emergency_bypass_active: false,
            paused_at_slot: 0,
            pause_reason: [0u8; 32],
            cooldown_end_slot: 0,
            emergency_bypass_end_slot: 0,
        }
    }
}

/// Re-entrancy guard — §7
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReentrancyGuard {
    pub executing: bool,
    pub depth: u8,
}

/// Single anchor field: pubkey + field_id + snapshot value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorField {
    pub pubkey: [u8; 32],
    pub field_id: u16,
    pub value: u64,
}

/// Transaction anchor — §5.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionAnchor {
    pub fingerprint: [u8; 32],
    pub fields: Vec<AnchorField>,
}

impl Default for TransactionAnchor {
    fn default() -> Self {
        Self {
            fingerprint: [0u8; 32],
            fields: Vec::new(),
        }
    }
}

/// TVL ring-buffer entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TvlSnapshot {
    pub value: u64,
    pub slot: u64,
    pub timestamp: i64,
}

/// Per-category circuit breaker state — §6
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreakerCategory {
    pub category_id: u8,
    pub history_len: u16,
    pub history_index: u16,
    pub window_max_value: u64,
    pub window_max_slot: u64,
    pub window_max_timestamp: i64,
    pub total_writes: u64,
    pub history: Vec<TvlSnapshot>,
}

/// Full circuit breaker state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CircuitBreakerState {
    pub categories: Vec<CircuitBreakerCategory>,
}

/// Per-counter rate limit state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimitCounter {
    pub counter_id: u8,
    pub count: u32,
    pub window_start_slot: u64,
}

/// Full rate limit state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RateLimitState {
    pub counters: Vec<RateLimitCounter>,
}

/// Single event counter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventCounter {
    pub counter_id: u8,
    pub count: u32,
    pub window_start_slot: u64,
    pub window_start_timestamp: i64,
}

/// Full event counter state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventCounterState {
    pub counters: Vec<EventCounter>,
}

// ── SandboxState ───────────────────────────────────────────────────────────

/// Top-level PDA state. §8.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxState {
    pub version: u8,
    pub bump: u8,
    pub mode_flags: ModeFlags,
    pub guard: ReentrancyGuard,
    pub tx_anchor: TransactionAnchor,
    pub circuit_breaker: CircuitBreakerState,
    pub rate_limits: RateLimitState,
    pub event_counters: EventCounterState,
}

impl SandboxState {
    /// Construct a fresh state (version = current, everything zeroed/default).
    pub fn new(bump: u8) -> Self {
        Self {
            version: SANDBOX_STATE_VERSION,
            bump,
            mode_flags: ModeFlags::default(),
            guard: ReentrancyGuard::default(),
            tx_anchor: TransactionAnchor::default(),
            circuit_breaker: CircuitBreakerState::default(),
            rate_limits: RateLimitState::default(),
            event_counters: EventCounterState::default(),
        }
    }

    // ── PDA derivation ─────────────────────────────────────────────────

    /// Derive PDA address using stored bump. Hot path — no find_program_address.
    pub fn create_pda(
        program_id: &Pubkey,
        scope: &[u8],
        bump: u8,
    ) -> Result<Pubkey, SandboxError> {
        let seeds: &[&[u8]] = if scope.is_empty() {
            &[b"perk_sandbox", &[bump]]
        } else {
            &[b"perk_sandbox", scope, &[bump]]
        };
        Pubkey::create_program_address(seeds, program_id)
            .map_err(|_| SandboxError::PDACorrupted)
    }

    /// Find PDA (init only — never in hot path).
    pub fn find_pda(program_id: &Pubkey, scope: &[u8]) -> (Pubkey, u8) {
        if scope.is_empty() {
            Pubkey::find_program_address(&[b"perk_sandbox"], program_id)
        } else {
            Pubkey::find_program_address(&[b"perk_sandbox", scope], program_id)
        }
    }

    // ── Compute total serialized size ──────────────────────────────────

    /// Total bytes needed for serialization.
    pub fn total_size(&self) -> Result<usize, SandboxError> {
        let mut size: usize = HEADER_SIZE;

        // mode flags
        size = size.checked_add(MODE_FLAGS_SIZE).ok_or(SandboxError::PDACorrupted)?;
        // guard
        size = size.checked_add(GUARD_SIZE).ok_or(SandboxError::PDACorrupted)?;
        // tx anchor
        let anchor_fields_count = self.tx_anchor.fields.len();
        if anchor_fields_count > MAX_ANCHOR_FIELDS {
            return Err(SandboxError::PDACorrupted);
        }
        let anchor_data = ANCHOR_FIELD_SIZE
            .checked_mul(anchor_fields_count)
            .ok_or(SandboxError::PDACorrupted)?;
        size = size
            .checked_add(TX_ANCHOR_HEADER_SIZE)
            .and_then(|s| s.checked_add(anchor_data))
            .ok_or(SandboxError::PDACorrupted)?;
        // circuit breaker
        size = size.checked_add(1).ok_or(SandboxError::PDACorrupted)?; // category_count
        for cat in &self.circuit_breaker.categories {
            let hist_bytes = TVL_SNAPSHOT_SIZE
                .checked_mul(cat.history.len())
                .ok_or(SandboxError::PDACorrupted)?;
            size = size
                .checked_add(CB_PER_CATEGORY_HEADER)
                .and_then(|s| s.checked_add(hist_bytes))
                .ok_or(SandboxError::PDACorrupted)?;
        }
        // rate limits
        size = size.checked_add(1).ok_or(SandboxError::PDACorrupted)?; // counter_count
        let rl_bytes = RATE_LIMIT_PER_COUNTER
            .checked_mul(self.rate_limits.counters.len())
            .ok_or(SandboxError::PDACorrupted)?;
        size = size.checked_add(rl_bytes).ok_or(SandboxError::PDACorrupted)?;

        // event counters: 1 byte count + 21 bytes per counter (id(1) + count(4) + slot(8) + timestamp(8))
        size = size.checked_add(1).ok_or(SandboxError::PDACorrupted)?; // counter_count
        let ec_per = 1usize + EVENT_COUNTER_SIZE; // 21 bytes per counter (id + EVENT_COUNTER_SIZE)
        let ec_bytes = ec_per
            .checked_mul(self.event_counters.counters.len())
            .ok_or(SandboxError::PDACorrupted)?;
        size = size.checked_add(ec_bytes).ok_or(SandboxError::PDACorrupted)?;

        Ok(size)
    }

    // ── Serialize ──────────────────────────────────────────────────────

    /// Serialize into `data`. Caller must provide a buffer of at least `self.total_size()` bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), SandboxError> {
        let needed = self.total_size()?;
        if data.len() < needed {
            return Err(SandboxError::PDACorrupted);
        }

        let mut pos: usize = 0;

        // ── Header ──
        write_bytes(data, pos, &DISCRIMINATOR)?;
        pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;

        write_u8(data, pos, self.version)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

        write_u8(data, pos, self.bump)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

        // total_size — fill placeholder, write offset table, then come back
        let total_size_pos = pos;
        pos = pos.checked_add(2).ok_or(SandboxError::PDACorrupted)?;

        // Compute section offsets — sections laid out in order after header:
        //   mode_flags | guard | tx_anchor | circuit_breaker | rate_limits
        let mode_flags_off: u16 = HEADER_SIZE as u16;

        let guard_off_usize = HEADER_SIZE
            .checked_add(MODE_FLAGS_SIZE)
            .ok_or(SandboxError::PDACorrupted)?;
        let guard_off = u16::try_from(guard_off_usize).map_err(|_| SandboxError::PDACorrupted)?;

        let tx_anchor_off_usize = guard_off_usize
            .checked_add(GUARD_SIZE)
            .ok_or(SandboxError::PDACorrupted)?;
        let tx_anchor_off =
            u16::try_from(tx_anchor_off_usize).map_err(|_| SandboxError::PDACorrupted)?;

        let anchor_field_count = self.tx_anchor.fields.len();
        let tx_anchor_section_size = TX_ANCHOR_HEADER_SIZE
            .checked_add(
                ANCHOR_FIELD_SIZE
                    .checked_mul(anchor_field_count)
                    .ok_or(SandboxError::PDACorrupted)?,
            )
            .ok_or(SandboxError::PDACorrupted)?;

        let cb_off_usize = tx_anchor_off_usize
            .checked_add(tx_anchor_section_size)
            .ok_or(SandboxError::PDACorrupted)?;
        let cb_off = u16::try_from(cb_off_usize).map_err(|_| SandboxError::PDACorrupted)?;

        let mut cb_section_size: usize = 1; // category_count
        for cat in &self.circuit_breaker.categories {
            let hist_bytes = TVL_SNAPSHOT_SIZE
                .checked_mul(cat.history.len())
                .ok_or(SandboxError::PDACorrupted)?;
            cb_section_size = cb_section_size
                .checked_add(CB_PER_CATEGORY_HEADER)
                .and_then(|s| s.checked_add(hist_bytes))
                .ok_or(SandboxError::PDACorrupted)?;
        }

        let rl_off_usize = cb_off_usize
            .checked_add(cb_section_size)
            .ok_or(SandboxError::PDACorrupted)?;
        let rl_off = u16::try_from(rl_off_usize).map_err(|_| SandboxError::PDACorrupted)?;

        let rl_section_size = 1usize
            .checked_add(
                RATE_LIMIT_PER_COUNTER
                    .checked_mul(self.rate_limits.counters.len())
                    .ok_or(SandboxError::PDACorrupted)?,
            )
            .ok_or(SandboxError::PDACorrupted)?;

        let ec_off_usize = rl_off_usize
            .checked_add(rl_section_size)
            .ok_or(SandboxError::PDACorrupted)?;
        let ec_off = u16::try_from(ec_off_usize).map_err(|_| SandboxError::PDACorrupted)?;

        // Now write total_size
        let total_size_u16 = u16::try_from(needed).map_err(|_| SandboxError::PDACorrupted)?;
        write_u16(data, total_size_pos, total_size_u16)?;

        // Offset table
        write_u16(data, OFF_MODE_FLAGS, mode_flags_off)?;
        write_u16(data, OFF_CIRCUIT_BREAKER, cb_off)?;
        write_u16(data, OFF_RATE_LIMITS, rl_off)?;
        write_u16(data, OFF_GUARD, guard_off)?;
        write_u16(data, OFF_EMERGENCY, mode_flags_off)?; // emergency shares mode_flags section
        write_u16(data, OFF_TX_ANCHOR, tx_anchor_off)?;
        write_u16(data, OFF_EVENT_COUNTERS, ec_off)?;

        // Reserved offsets zeroed
        for i in 0..7u16 {
            let roff = OFF_RESERVED_OFFSETS
                .checked_add((i as usize).checked_mul(2).ok_or(SandboxError::PDACorrupted)?)
                .ok_or(SandboxError::PDACorrupted)?;
            write_u16(data, roff, 0)?;
        }
        // Reserved bytes zeroed
        for i in 0..24usize {
            let roff = OFF_RESERVED.checked_add(i).ok_or(SandboxError::PDACorrupted)?;
            write_u8(data, roff, 0)?;
        }

        // ── Mode Flags Section ──
        pos = mode_flags_off as usize;
        write_bool(data, pos, self.mode_flags.paused)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
        write_bool(data, pos, self.mode_flags.close_only)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
        write_bool(data, pos, self.mode_flags.liquidation_paused)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
        write_bool(data, pos, self.mode_flags.emergency_bypass_active)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
        write_u64(data, pos, self.mode_flags.paused_at_slot)?;
        pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
        write_bytes(data, pos, &self.mode_flags.pause_reason)?;
        pos = pos.checked_add(32).ok_or(SandboxError::PDACorrupted)?;
        write_u64(data, pos, self.mode_flags.cooldown_end_slot)?;
        pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
        write_u64(data, pos, self.mode_flags.emergency_bypass_end_slot)?;
        pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;

        // ── Guard Section ──
        debug_assert_eq!(pos, guard_off as usize);
        write_bool(data, pos, self.guard.executing)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
        write_u8(data, pos, self.guard.depth)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

        // ── TX Anchor Section ──
        debug_assert_eq!(pos, tx_anchor_off as usize);
        write_bytes(data, pos, &self.tx_anchor.fingerprint)?;
        pos = pos.checked_add(32).ok_or(SandboxError::PDACorrupted)?;
        let fc = u8::try_from(anchor_field_count).map_err(|_| SandboxError::PDACorrupted)?;
        write_u8(data, pos, fc)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

        for field in &self.tx_anchor.fields {
            write_bytes(data, pos, &field.pubkey)?;
            pos = pos.checked_add(32).ok_or(SandboxError::PDACorrupted)?;
            write_u16(data, pos, field.field_id)?;
            pos = pos.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
            write_u64(data, pos, field.value)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
        }

        // ── Circuit Breaker Section ──
        debug_assert_eq!(pos, cb_off as usize);
        let cat_count =
            u8::try_from(self.circuit_breaker.categories.len()).map_err(|_| SandboxError::PDACorrupted)?;
        write_u8(data, pos, cat_count)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

        for cat in &self.circuit_breaker.categories {
            write_u8(data, pos, cat.category_id)?;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
            write_u16(data, pos, cat.history_len)?;
            pos = pos.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
            write_u16(data, pos, cat.history_index)?;
            pos = pos.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
            write_u64(data, pos, cat.window_max_value)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
            write_u64(data, pos, cat.window_max_slot)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
            write_i64(data, pos, cat.window_max_timestamp)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
            write_u64(data, pos, cat.total_writes)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;

            if cat.history.len() != cat.history_len as usize {
                return Err(SandboxError::PDACorrupted);
            }
            for snap in &cat.history {
                write_u64(data, pos, snap.value)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                write_u64(data, pos, snap.slot)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                write_i64(data, pos, snap.timestamp)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
            }
        }

        // ── Rate Limits Section ──
        debug_assert_eq!(pos, rl_off as usize);
        let counter_count =
            u8::try_from(self.rate_limits.counters.len()).map_err(|_| SandboxError::PDACorrupted)?;
        write_u8(data, pos, counter_count)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

        for ctr in &self.rate_limits.counters {
            write_u8(data, pos, ctr.counter_id)?;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
            write_u32(data, pos, ctr.count)?;
            pos = pos.checked_add(4).ok_or(SandboxError::PDACorrupted)?;
            write_u64(data, pos, ctr.window_start_slot)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
        }

        // ── Event Counters Section ──
        debug_assert_eq!(pos, ec_off as usize);
        let ec_count =
            u8::try_from(self.event_counters.counters.len()).map_err(|_| SandboxError::PDACorrupted)?;
        write_u8(data, pos, ec_count)?;
        pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

        for ec in &self.event_counters.counters {
            write_u8(data, pos, ec.counter_id)?;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
            write_u32(data, pos, ec.count)?;
            pos = pos.checked_add(4).ok_or(SandboxError::PDACorrupted)?;
            write_u64(data, pos, ec.window_start_slot)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
            write_i64(data, pos, ec.window_start_timestamp)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
        }

        debug_assert_eq!(pos, needed);
        Ok(())
    }

    // ── Deserialize ────────────────────────────────────────────────────

    /// Deserialize from raw PDA data. Validates discriminator, version, and all offsets first.
    pub fn deserialize(data: &[u8]) -> Result<Self, SandboxError> {
        // Minimum: must have full header
        if data.len() < HEADER_SIZE {
            return Err(SandboxError::PDACorrupted);
        }

        // Discriminator
        let disc = read_bytes(data, OFF_DISCRIMINATOR, 8)?;
        if disc != DISCRIMINATOR {
            return Err(SandboxError::SandboxStateNotInitialized);
        }

        // Version
        let version = read_u8(data, OFF_VERSION)?;
        if version != SANDBOX_STATE_VERSION {
            return Err(SandboxError::SandboxStateVersionMismatch);
        }

        let bump = read_u8(data, OFF_BUMP)?;
        let total_size = read_u16(data, OFF_TOTAL_SIZE)? as usize;

        if data.len() < total_size {
            return Err(SandboxError::PDACorrupted);
        }

        // Validate offsets
        Self::validate_offsets(data)?;

        // Read section offsets
        let mode_off = read_u16(data, OFF_MODE_FLAGS)? as usize;
        let guard_off = read_u16(data, OFF_GUARD)? as usize;
        let tx_anchor_off = read_u16(data, OFF_TX_ANCHOR)? as usize;
        let cb_off = read_u16(data, OFF_CIRCUIT_BREAKER)? as usize;
        let rl_off = read_u16(data, OFF_RATE_LIMITS)? as usize;
        let ec_off = read_u16(data, OFF_EVENT_COUNTERS)? as usize;

        // ── Mode Flags ──
        let mode_flags = if mode_off == 0 {
            ModeFlags::default()
        } else {
            let mut pos = mode_off;
            let end = pos.checked_add(MODE_FLAGS_SIZE).ok_or(SandboxError::PDACorrupted)?;
            if end > data.len() {
                return Err(SandboxError::PDACorrupted);
            }
            let paused = read_bool(data, pos)?;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
            let close_only = read_bool(data, pos)?;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
            let liquidation_paused = read_bool(data, pos)?;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
            let emergency_bypass_active = read_bool(data, pos)?;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
            let paused_at_slot = read_u64(data, pos)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
            let reason_bytes = read_bytes(data, pos, 32)?;
            let mut pause_reason = [0u8; 32];
            pause_reason.copy_from_slice(reason_bytes);
            pos = pos.checked_add(32).ok_or(SandboxError::PDACorrupted)?;
            let cooldown_end_slot = read_u64(data, pos)?;
            pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
            let emergency_bypass_end_slot = read_u64(data, pos)?;
            // pos advances past this section — intentionally not read after this point

            ModeFlags {
                paused,
                close_only,
                liquidation_paused,
                emergency_bypass_active,
                paused_at_slot,
                pause_reason,
                cooldown_end_slot,
                emergency_bypass_end_slot,
            }
        };

        // ── Guard ──
        let guard = if guard_off == 0 {
            ReentrancyGuard::default()
        } else {
            let end = guard_off
                .checked_add(GUARD_SIZE)
                .ok_or(SandboxError::PDACorrupted)?;
            if end > data.len() {
                return Err(SandboxError::PDACorrupted);
            }
            let executing = read_bool(data, guard_off)?;
            let depth = read_u8(
                data,
                guard_off.checked_add(1).ok_or(SandboxError::PDACorrupted)?,
            )?;
            ReentrancyGuard { executing, depth }
        };

        // ── TX Anchor ──
        let tx_anchor = if tx_anchor_off == 0 {
            TransactionAnchor::default()
        } else {
            let mut pos = tx_anchor_off;
            // Need at least the header
            let hdr_end = pos
                .checked_add(TX_ANCHOR_HEADER_SIZE)
                .ok_or(SandboxError::PDACorrupted)?;
            if hdr_end > data.len() {
                return Err(SandboxError::PDACorrupted);
            }
            let fp_bytes = read_bytes(data, pos, 32)?;
            let mut fingerprint = [0u8; 32];
            fingerprint.copy_from_slice(fp_bytes);
            pos = pos.checked_add(32).ok_or(SandboxError::PDACorrupted)?;
            let field_count = read_u8(data, pos)? as usize;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

            if field_count > MAX_ANCHOR_FIELDS {
                return Err(SandboxError::PDACorrupted);
            }
            let fields_bytes = ANCHOR_FIELD_SIZE
                .checked_mul(field_count)
                .ok_or(SandboxError::PDACorrupted)?;
            let fields_end = pos.checked_add(fields_bytes).ok_or(SandboxError::PDACorrupted)?;
            if fields_end > data.len() {
                return Err(SandboxError::PDACorrupted);
            }

            let mut fields = Vec::with_capacity(field_count);
            for _ in 0..field_count {
                let pk_bytes = read_bytes(data, pos, 32)?;
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(pk_bytes);
                pos = pos.checked_add(32).ok_or(SandboxError::PDACorrupted)?;
                let field_id = read_u16(data, pos)?;
                pos = pos.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
                let value = read_u64(data, pos)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                fields.push(AnchorField {
                    pubkey,
                    field_id,
                    value,
                });
            }

            TransactionAnchor {
                fingerprint,
                fields,
            }
        };

        // ── Circuit Breaker ──
        let circuit_breaker = if cb_off == 0 {
            CircuitBreakerState::default()
        } else {
            let mut pos = cb_off;
            if pos.checked_add(1).ok_or(SandboxError::PDACorrupted)? > data.len() {
                return Err(SandboxError::PDACorrupted);
            }
            let cat_count = read_u8(data, pos)? as usize;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

            let mut categories = Vec::with_capacity(cat_count);
            for _ in 0..cat_count {
                let hdr_end = pos
                    .checked_add(CB_PER_CATEGORY_HEADER)
                    .ok_or(SandboxError::PDACorrupted)?;
                if hdr_end > data.len() {
                    return Err(SandboxError::PDACorrupted);
                }

                let category_id = read_u8(data, pos)?;
                pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
                let history_len = read_u16(data, pos)?;
                pos = pos.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
                let history_index = read_u16(data, pos)?;
                pos = pos.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
                let window_max_value = read_u64(data, pos)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                let window_max_slot = read_u64(data, pos)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                let window_max_timestamp = read_i64(data, pos)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                let total_writes = read_u64(data, pos)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;

                let hist_bytes = TVL_SNAPSHOT_SIZE
                    .checked_mul(history_len as usize)
                    .ok_or(SandboxError::PDACorrupted)?;
                let hist_end = pos.checked_add(hist_bytes).ok_or(SandboxError::PDACorrupted)?;
                if hist_end > data.len() {
                    return Err(SandboxError::PDACorrupted);
                }

                let mut history = Vec::with_capacity(history_len as usize);
                for _ in 0..history_len {
                    let value = read_u64(data, pos)?;
                    pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                    let slot = read_u64(data, pos)?;
                    pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                    let timestamp = read_i64(data, pos)?;
                    pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                    history.push(TvlSnapshot {
                        value,
                        slot,
                        timestamp,
                    });
                }

                categories.push(CircuitBreakerCategory {
                    category_id,
                    history_len,
                    history_index,
                    window_max_value,
                    window_max_slot,
                    window_max_timestamp,
                    total_writes,
                    history,
                });
            }
            CircuitBreakerState { categories }
        };

        // ── Rate Limits ──
        let rate_limits = if rl_off == 0 {
            RateLimitState::default()
        } else {
            let mut pos = rl_off;
            if pos.checked_add(1).ok_or(SandboxError::PDACorrupted)? > data.len() {
                return Err(SandboxError::PDACorrupted);
            }
            let counter_count = read_u8(data, pos)? as usize;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

            let counters_bytes = RATE_LIMIT_PER_COUNTER
                .checked_mul(counter_count)
                .ok_or(SandboxError::PDACorrupted)?;
            let counters_end = pos.checked_add(counters_bytes).ok_or(SandboxError::PDACorrupted)?;
            if counters_end > data.len() {
                return Err(SandboxError::PDACorrupted);
            }

            let mut counters = Vec::with_capacity(counter_count);
            for _ in 0..counter_count {
                let counter_id = read_u8(data, pos)?;
                pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
                let count = read_u32(data, pos)?;
                pos = pos.checked_add(4).ok_or(SandboxError::PDACorrupted)?;
                let window_start_slot = read_u64(data, pos)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                counters.push(RateLimitCounter {
                    counter_id,
                    count,
                    window_start_slot,
                });
            }
            RateLimitState { counters }
        };

        // ── Event Counters ──
        let event_counters = if ec_off == 0 {
            EventCounterState::default()
        } else {
            let mut pos = ec_off;
            if pos.checked_add(1).ok_or(SandboxError::PDACorrupted)? > data.len() {
                return Err(SandboxError::PDACorrupted);
            }
            let counter_count = read_u8(data, pos)? as usize;
            pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;

            let per_counter = 1usize + EVENT_COUNTER_SIZE; // 21
            let counters_bytes = per_counter
                .checked_mul(counter_count)
                .ok_or(SandboxError::PDACorrupted)?;
            let counters_end = pos.checked_add(counters_bytes).ok_or(SandboxError::PDACorrupted)?;
            if counters_end > data.len() {
                return Err(SandboxError::PDACorrupted);
            }

            let mut counters = Vec::with_capacity(counter_count);
            for _ in 0..counter_count {
                let counter_id = read_u8(data, pos)?;
                pos = pos.checked_add(1).ok_or(SandboxError::PDACorrupted)?;
                let count = read_u32(data, pos)?;
                pos = pos.checked_add(4).ok_or(SandboxError::PDACorrupted)?;
                let window_start_slot = read_u64(data, pos)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                let window_start_timestamp = read_i64(data, pos)?;
                pos = pos.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
                counters.push(EventCounter {
                    counter_id,
                    count,
                    window_start_slot,
                    window_start_timestamp,
                });
            }
            EventCounterState { counters }
        };

        Ok(Self {
            version,
            bump,
            mode_flags,
            guard,
            tx_anchor,
            circuit_breaker,
            rate_limits,
            event_counters,
        })
    }

    // ── Offset validation (§8.3) ───────────────────────────────────────

    /// Validate that all section offsets are within bounds and don't overlap the header.
    /// Note: checks for identical offset values only, not range overlaps.
    /// Full range-overlap validation would require section sizes at validation time.
    /// The serialize/deserialize cycle ensures correct layout in practice.
    pub fn validate_offsets(data: &[u8]) -> Result<(), SandboxError> {
        if data.len() < HEADER_SIZE {
            return Err(SandboxError::PDACorrupted);
        }

        let total_size = read_u16(data, OFF_TOTAL_SIZE)? as usize;
        if total_size > data.len() {
            return Err(SandboxError::PDACorrupted);
        }

        let offsets = [
            read_u16(data, OFF_MODE_FLAGS)?,
            read_u16(data, OFF_CIRCUIT_BREAKER)?,
            read_u16(data, OFF_RATE_LIMITS)?,
            read_u16(data, OFF_GUARD)?,
            read_u16(data, OFF_EMERGENCY)?,
            read_u16(data, OFF_TX_ANCHOR)?,
            read_u16(data, OFF_EVENT_COUNTERS)?,
        ];

        for &offset in &offsets {
            if offset == 0 {
                continue; // not present
            }
            let off = offset as usize;
            // Must not encroach on header
            if off < HEADER_SIZE {
                return Err(SandboxError::PDACorrupted);
            }
            // Must be within total_size
            if off >= total_size {
                return Err(SandboxError::PDACorrupted);
            }
        }

        // Check that non-zero, non-duplicate offsets don't point to the same spot
        // (emergency_offset can equal mode_flags_offset by design, so skip that pair)
        let mode_off = offsets[0];
        let cb_off = offsets[1];
        let rl_off = offsets[2];
        let guard_off = offsets[3];
        // offsets[4] = emergency, intentionally same as mode_flags
        let tx_off = offsets[5];

        let ec_off = offsets[6];
        let unique_section_offsets: [u16; 6] = [mode_off, cb_off, rl_off, guard_off, tx_off, ec_off];
        for i in 0..unique_section_offsets.len() {
            if unique_section_offsets[i] == 0 {
                continue;
            }
            for j in (i + 1)..unique_section_offsets.len() {
                if unique_section_offsets[j] == 0 {
                    continue;
                }
                if unique_section_offsets[i] == unique_section_offsets[j] {
                    return Err(SandboxError::PDACorrupted);
                }
            }
        }

        Ok(())
    }
}

// ── Step [10] PDA Write-Back Helpers ───────────────────────────────────────
//
// Low-level writers for persisting runtime state changes back to the
// sandbox PDA after business logic + invariants + circuit breakers.
// All writes are bounds-checked. Corruption → fail-closed.

/// Write mode flags back to PDA data at the given section offset.
/// Called after circuit breakers may have set deferred actions (pause, close_only, etc.).
///
/// Layout (§8.2 mode flags section):
///   +0:  paused: bool (1)
///   +1:  close_only: bool (1)
///   +2:  liquidation_paused: bool (1)
///   +3:  emergency_bypass_active: bool (1)
///   +4:  paused_at_slot: u64 (8)
///   +12: pause_reason: [u8; 32] (32)
///   +44: cooldown_end_slot: u64 (8)
///   +52: emergency_bypass_end_slot: u64 (8)
pub fn write_mode_flags(
    data: &mut [u8],
    offset: usize,
    paused: bool,
    close_only: bool,
    liquidation_paused: bool,
    emergency_bypass_active: bool,
) -> Result<(), SandboxError> {
    let end = offset.checked_add(MODE_FLAGS_SIZE).ok_or(SandboxError::PDACorrupted)?;
    if end > data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    write_bool(data, offset, paused)?;
    write_bool(data, offset + 1, close_only)?;
    write_bool(data, offset + 2, liquidation_paused)?;
    write_bool(data, offset + 3, emergency_bypass_active)?;
    // Remaining fields (paused_at_slot, pause_reason, cooldown/bypass slots)
    // are only mutated by explicit admin instructions, not by step [10].
    Ok(())
}

/// Write a single mode flag bool at a specific sub-offset within the mode flags section.
/// sub_offset: 0=paused, 1=close_only, 2=liquidation_paused, 3=emergency_bypass_active
pub fn write_mode_flag_single(
    data: &mut [u8],
    section_offset: usize,
    sub_offset: usize,
    value: bool,
) -> Result<(), SandboxError> {
    if sub_offset > 3 {
        return Err(SandboxError::PDACorrupted);
    }
    let abs_offset = section_offset.checked_add(sub_offset).ok_or(SandboxError::PDACorrupted)?;
    if abs_offset >= data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    write_bool(data, abs_offset, value)
}

/// Write the `paused_at_slot` field in mode flags section.
pub fn write_paused_at_slot(
    data: &mut [u8],
    section_offset: usize,
    slot: u64,
) -> Result<(), SandboxError> {
    let offset = section_offset.checked_add(4).ok_or(SandboxError::PDACorrupted)?;
    write_u64(data, offset, slot)
}

/// Write the emergency bypass end slot in mode flags section.
pub fn write_emergency_bypass_end_slot(
    data: &mut [u8],
    section_offset: usize,
    slot: u64,
) -> Result<(), SandboxError> {
    let offset = section_offset.checked_add(52).ok_or(SandboxError::PDACorrupted)?;
    write_u64(data, offset, slot)
}

/// Read a section offset from the PDA header. Returns 0 if section is not present.
pub fn read_section_offset(data: &[u8], header_field_offset: usize) -> Result<usize, SandboxError> {
    if data.len() < header_field_offset + 2 {
        return Err(SandboxError::PDACorrupted);
    }
    Ok(read_u16(data, header_field_offset)? as usize)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_populated_state() -> SandboxState {
        let mut state = SandboxState::new(254);
        state.mode_flags.paused = true;
        state.mode_flags.close_only = false;
        state.mode_flags.liquidation_paused = true;
        state.mode_flags.emergency_bypass_active = false;
        state.mode_flags.paused_at_slot = 123_456_789;
        state.mode_flags.pause_reason[0] = b'T';
        state.mode_flags.pause_reason[1] = b'E';
        state.mode_flags.pause_reason[2] = b'S';
        state.mode_flags.pause_reason[3] = b'T';
        state.mode_flags.cooldown_end_slot = 999_999;
        state.mode_flags.emergency_bypass_end_slot = 1_000_000;

        state.guard = ReentrancyGuard {
            executing: true,
            depth: 3,
        };

        state.tx_anchor = TransactionAnchor {
            fingerprint: [0xCC; 32],
            fields: vec![
                AnchorField {
                    pubkey: [0xAA; 32],
                    field_id: 1,
                    value: 500_000,
                },
                AnchorField {
                    pubkey: [0xBB; 32],
                    field_id: 2,
                    value: 1_000_000,
                },
            ],
        };

        state.circuit_breaker = CircuitBreakerState {
            categories: vec![CircuitBreakerCategory {
                category_id: 1,
                history_len: 2,
                history_index: 1,
                window_max_value: 10_000_000,
                window_max_slot: 100,
                window_max_timestamp: 1_700_000_050,
                total_writes: 42,
                history: vec![
                    TvlSnapshot {
                        value: 5_000_000,
                        slot: 90,
                        timestamp: 1_700_000_000,
                    },
                    TvlSnapshot {
                        value: 6_000_000,
                        slot: 95,
                        timestamp: 1_700_000_100,
                    },
                ],
            }],
        };

        state.rate_limits = RateLimitState {
            counters: vec![
                RateLimitCounter {
                    counter_id: 0,
                    count: 5,
                    window_start_slot: 80,
                },
                RateLimitCounter {
                    counter_id: 1,
                    count: 12,
                    window_start_slot: 85,
                },
            ],
        };

        state.event_counters = EventCounterState {
            counters: vec![
                EventCounter {
                    counter_id: 0,
                    count: 10,
                    window_start_slot: 50,
                    window_start_timestamp: 1_700_000_000,
                },
                EventCounter {
                    counter_id: 1,
                    count: 3,
                    window_start_slot: 60,
                    window_start_timestamp: 1_700_000_100,
                },
            ],
        };

        state
    }

    #[test]
    fn round_trip_empty_state() {
        let state = SandboxState::new(255);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();
        let decoded = SandboxState::deserialize(&buf).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn round_trip_populated_state() {
        let state = make_populated_state();
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();
        let decoded = SandboxState::deserialize(&buf).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn discriminator_check() {
        let state = SandboxState::new(1);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        // Corrupt discriminator
        buf[0] = b'X';
        let err = SandboxState::deserialize(&buf).unwrap_err();
        assert_eq!(err, SandboxError::SandboxStateNotInitialized);
    }

    #[test]
    fn version_mismatch() {
        let state = SandboxState::new(1);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        // Set version to 99
        buf[OFF_VERSION] = 99;
        let err = SandboxState::deserialize(&buf).unwrap_err();
        assert_eq!(err, SandboxError::SandboxStateVersionMismatch);
    }

    #[test]
    fn truncated_buffer() {
        let state = make_populated_state();
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        // Chop off last 10 bytes — total_size won't match
        let err = SandboxState::deserialize(&buf[..size - 10]).unwrap_err();
        assert_eq!(err, SandboxError::PDACorrupted);
    }

    #[test]
    fn offset_overlaps_header() {
        let state = SandboxState::new(1);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        // Point mode_flags offset into the header
        buf[OFF_MODE_FLAGS] = 10; // offset = 10, inside header
        buf[OFF_MODE_FLAGS + 1] = 0;
        let err = SandboxState::deserialize(&buf).unwrap_err();
        assert_eq!(err, SandboxError::PDACorrupted);
    }

    #[test]
    fn offset_past_end() {
        let state = SandboxState::new(1);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        // Point guard offset past total_size
        let bad_off = (size as u16).to_le_bytes();
        buf[OFF_GUARD] = bad_off[0];
        buf[OFF_GUARD + 1] = bad_off[1];
        let err = SandboxState::deserialize(&buf).unwrap_err();
        assert_eq!(err, SandboxError::PDACorrupted);
    }

    #[test]
    fn too_small_buffer() {
        let err = SandboxState::deserialize(&[0u8; 10]).unwrap_err();
        assert_eq!(err, SandboxError::PDACorrupted);
    }

    #[test]
    fn invalid_bool_corrupted() {
        let state = SandboxState::new(1);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        // Mode flags section starts at HEADER_SIZE; first byte is `paused` bool
        let mode_off = read_u16(&buf, OFF_MODE_FLAGS).unwrap() as usize;
        buf[mode_off] = 2; // invalid bool
        let err = SandboxState::deserialize(&buf).unwrap_err();
        assert_eq!(err, SandboxError::PDACorrupted);
    }

    #[test]
    fn serialize_into_too_small_buffer() {
        let state = make_populated_state();
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size - 1];
        let err = state.serialize(&mut buf).unwrap_err();
        assert_eq!(err, SandboxError::PDACorrupted);
    }

    #[test]
    fn pda_derivation_deterministic() {
        let program_id = Pubkey::new_unique();
        let (expected, bump) = SandboxState::find_pda(&program_id, &[]);
        let derived = SandboxState::create_pda(&program_id, &[], bump).unwrap();
        assert_eq!(expected, derived);
    }

    #[test]
    fn pda_derivation_with_scope() {
        let program_id = Pubkey::new_unique();
        let scope = Pubkey::new_unique();
        let (expected, bump) = SandboxState::find_pda(&program_id, scope.as_ref());
        let derived = SandboxState::create_pda(&program_id, scope.as_ref(), bump).unwrap();
        assert_eq!(expected, derived);
    }

    #[test]
    fn max_anchor_fields_fits() {
        let mut state = SandboxState::new(1);
        state.tx_anchor.fields = (0..MAX_ANCHOR_FIELDS)
            .map(|i| AnchorField {
                pubkey: [i as u8; 32],
                field_id: i as u16,
                value: i as u64 * 1000,
            })
            .collect();
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();
        let decoded = SandboxState::deserialize(&buf).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn too_many_anchor_fields_rejected() {
        let mut state = SandboxState::new(1);
        state.tx_anchor.fields = (0..MAX_ANCHOR_FIELDS + 1)
            .map(|i| AnchorField {
                pubkey: [i as u8; 32],
                field_id: i as u16,
                value: 0,
            })
            .collect();
        let err = state.total_size().unwrap_err();
        assert_eq!(err, SandboxError::PDACorrupted);
    }

    #[test]
    fn validate_offsets_on_good_data() {
        let state = make_populated_state();
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();
        assert!(SandboxState::validate_offsets(&buf).is_ok());
    }

    #[test]
    fn circuit_breaker_multiple_categories() {
        let mut state = SandboxState::new(1);
        state.circuit_breaker.categories = vec![
            CircuitBreakerCategory {
                category_id: 0,
                history_len: 1,
                history_index: 0,
                window_max_value: 100,
                window_max_slot: 10,
                window_max_timestamp: 100,
                total_writes: 1,
                history: vec![TvlSnapshot {
                    value: 50,
                    slot: 5,
                    timestamp: 100,
                }],
            },
            CircuitBreakerCategory {
                category_id: 1,
                history_len: 3,
                history_index: 2,
                window_max_value: 200,
                window_max_slot: 20,
                window_max_timestamp: 400,
                total_writes: 3,
                history: vec![
                    TvlSnapshot { value: 60, slot: 10, timestamp: 200 },
                    TvlSnapshot { value: 70, slot: 15, timestamp: 300 },
                    TvlSnapshot { value: 80, slot: 18, timestamp: 400 },
                ],
            },
        ];
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();
        let decoded = SandboxState::deserialize(&buf).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn token_program_ids_valid() {
        // Just ensure the constants are valid pubkeys (no panic on construction)
        assert_ne!(SPL_TOKEN_PROGRAM_ID, Pubkey::default());
        assert_ne!(TOKEN_2022_PROGRAM_ID, Pubkey::default());
        assert_ne!(SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID);
    }

    // ── Step [10] write-back tests ──

    #[test]
    fn write_mode_flags_round_trip() {
        let mut state = SandboxState::new(1);
        state.mode_flags.paused = false;
        state.mode_flags.close_only = false;
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        let mode_off = read_u16(&buf, OFF_MODE_FLAGS).unwrap() as usize;
        assert!(mode_off >= HEADER_SIZE);

        // Write new flags
        write_mode_flags(&mut buf, mode_off, true, true, false, false).unwrap();

        // Verify via deserialization
        let decoded = SandboxState::deserialize(&buf).unwrap();
        assert!(decoded.mode_flags.paused);
        assert!(decoded.mode_flags.close_only);
        assert!(!decoded.mode_flags.liquidation_paused);
        assert!(!decoded.mode_flags.emergency_bypass_active);
    }

    #[test]
    fn write_mode_flag_single_each_field() {
        let state = SandboxState::new(1);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        let mode_off = read_u16(&buf, OFF_MODE_FLAGS).unwrap() as usize;

        // Set each flag individually
        write_mode_flag_single(&mut buf, mode_off, 0, true).unwrap(); // paused
        write_mode_flag_single(&mut buf, mode_off, 2, true).unwrap(); // liq_paused

        let decoded = SandboxState::deserialize(&buf).unwrap();
        assert!(decoded.mode_flags.paused);
        assert!(!decoded.mode_flags.close_only);
        assert!(decoded.mode_flags.liquidation_paused);
        assert!(!decoded.mode_flags.emergency_bypass_active);
    }

    #[test]
    fn write_mode_flag_single_rejects_bad_offset() {
        let state = SandboxState::new(1);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        let mode_off = read_u16(&buf, OFF_MODE_FLAGS).unwrap() as usize;
        // sub_offset 4 is out of range (only 0-3 are bools)
        let err = write_mode_flag_single(&mut buf, mode_off, 4, true).unwrap_err();
        assert_eq!(err, SandboxError::PDACorrupted);
    }

    #[test]
    fn write_paused_at_slot_persists() {
        let state = SandboxState::new(1);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        let mode_off = read_u16(&buf, OFF_MODE_FLAGS).unwrap() as usize;
        write_paused_at_slot(&mut buf, mode_off, 999_888_777).unwrap();

        let decoded = SandboxState::deserialize(&buf).unwrap();
        assert_eq!(decoded.mode_flags.paused_at_slot, 999_888_777);
    }

    #[test]
    fn write_emergency_bypass_end_slot_persists() {
        let state = SandboxState::new(1);
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        let mode_off = read_u16(&buf, OFF_MODE_FLAGS).unwrap() as usize;
        write_emergency_bypass_end_slot(&mut buf, mode_off, 42_000_000).unwrap();

        let decoded = SandboxState::deserialize(&buf).unwrap();
        assert_eq!(decoded.mode_flags.emergency_bypass_end_slot, 42_000_000);
    }

    #[test]
    fn write_mode_flags_on_truncated_buffer_fails() {
        let mut buf = vec![0u8; HEADER_SIZE + 10]; // too small for mode flags section
        // mode_flags at HEADER_SIZE, but only 10 bytes available (need 60)
        let err = write_mode_flags(&mut buf, HEADER_SIZE, true, false, false, false).unwrap_err();
        assert_eq!(err, SandboxError::PDACorrupted);
    }

    #[test]
    fn read_section_offset_works() {
        let state = make_populated_state();
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        let mode_off = read_section_offset(&buf, OFF_MODE_FLAGS).unwrap();
        assert!(mode_off >= HEADER_SIZE);
        let guard_off = read_section_offset(&buf, OFF_GUARD).unwrap();
        assert!(guard_off > mode_off);
    }

    #[test]
    fn deferred_flag_merge_only_sets_never_clears() {
        let mut state = SandboxState::new(1);
        state.mode_flags.paused = true; // already paused
        state.mode_flags.close_only = false;
        let size = state.total_size().unwrap();
        let mut buf = vec![0u8; size];
        state.serialize(&mut buf).unwrap();

        let mode_off = read_u16(&buf, OFF_MODE_FLAGS).unwrap() as usize;

        // Simulate deferred close_only, but NOT paused
        // Merge: paused stays true (was already set), close_only becomes true
        let cur_paused = buf[mode_off] != 0;
        let cur_close = buf[mode_off + 1] != 0;
        let deferred_pause = false;
        let deferred_close = true;
        write_mode_flags(
            &mut buf, mode_off,
            cur_paused || deferred_pause,
            cur_close || deferred_close,
            false, false,
        ).unwrap();

        let decoded = SandboxState::deserialize(&buf).unwrap();
        assert!(decoded.mode_flags.paused, "paused must stay true");
        assert!(decoded.mode_flags.close_only, "close_only must become true");
    }
}

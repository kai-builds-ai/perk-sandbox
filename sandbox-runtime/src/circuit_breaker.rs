// circuit_breaker.rs — Instruction-type-aware circuit breakers for PERK Sandbox
//
// Three distinct breaker types (spec §6):
//   1. TvlCliffBreaker   — windowed per-category TVL cliff detection
//   2. EventCountBreaker  — rapid event counter (liquidations, withdrawals)
//   3. PerTxThreshold     — single-tx large outflow check (stateless)
//
// Plus: GlobalAggregateBreaker — read-only per-tx protocol-wide check (§8.6)
//
// All arithmetic is checked. Overflow = fail-closed.
// All buffer access is bounds-checked.
// Dual-window: slot AND timestamp, always use the more conservative (smaller) window.

use crate::error::SandboxError;

// ─── Instruction Categories ────────────────────────────────────────────────

/// Every instruction declares a category. Breakers track per-category budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InstructionCategory {
    Withdrawal = 0,
    Liquidation = 1,
    Deposit = 2,
    Default = 255,
}

impl InstructionCategory {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Withdrawal,
            1 => Self::Liquidation,
            2 => Self::Deposit,
            255 => Self::Default,
            _ => Self::Default,
        }
    }
}

// ─── Ring Buffer Utilities ─────────────────────────────────────────────────

/// A single TVL snapshot stored in the ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TvlSnapshot {
    pub value: u64,
    pub slot: u64,
    pub timestamp: i64,
}

impl TvlSnapshot {
    pub const SERIALIZED_SIZE: usize = 8 + 8 + 8; // 24 bytes

    pub fn serialize(&self, buf: &mut [u8]) -> Result<(), SandboxError> {
        if buf.len() < Self::SERIALIZED_SIZE {
            return Err(SandboxError::PDACorrupted);
        }
        buf[0..8].copy_from_slice(&self.value.to_le_bytes());
        buf[8..16].copy_from_slice(&self.slot.to_le_bytes());
        buf[16..24].copy_from_slice(&self.timestamp.to_le_bytes());
        Ok(())
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, SandboxError> {
        if buf.len() < Self::SERIALIZED_SIZE {
            return Err(SandboxError::PDACorrupted);
        }
        Ok(Self {
            value: u64::from_le_bytes(
                buf[0..8].try_into().map_err(|_| SandboxError::PDACorrupted)?,
            ),
            slot: u64::from_le_bytes(
                buf[8..16].try_into().map_err(|_| SandboxError::PDACorrupted)?,
            ),
            timestamp: i64::from_le_bytes(
                buf[16..24].try_into().map_err(|_| SandboxError::PDACorrupted)?,
            ),
        })
    }
}

/// Push a snapshot into a ring buffer at `data[offset..]`.
/// `history_len` is capacity, `history_index` is the next write position (wraps).
/// Returns the new history_index.
pub fn ring_buffer_push(
    data: &mut [u8],
    offset: usize,
    history_len: u16,
    history_index: u16,
    snapshot: &TvlSnapshot,
) -> Result<u16, SandboxError> {
    if history_len == 0 {
        return Err(SandboxError::PDACorrupted);
    }
    let idx = history_index % history_len; // bounds-safe
    let start = offset
        .checked_add((idx as usize).checked_mul(TvlSnapshot::SERIALIZED_SIZE).ok_or(SandboxError::PDACorrupted)?)
        .ok_or(SandboxError::PDACorrupted)?;
    let end = start
        .checked_add(TvlSnapshot::SERIALIZED_SIZE)
        .ok_or(SandboxError::PDACorrupted)?;
    if end > data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    snapshot.serialize(&mut data[start..end])?;
    // The stored index is the absolute counter. We only need the ring position.
    // Use wrapping_add to prevent permanent DoS after 65K writes.
    let next = history_index.wrapping_add(1);
    Ok(next % history_len)
}

/// Read the oldest entry in the ring buffer.
/// If the buffer isn't full yet (`total_writes < history_len`), oldest is index 0.
pub fn ring_buffer_oldest(
    data: &[u8],
    offset: usize,
    history_len: u16,
    history_index: u16,
    total_writes: u64,
) -> Result<TvlSnapshot, SandboxError> {
    if history_len == 0 {
        return Err(SandboxError::PDACorrupted);
    }
    let oldest_idx = if total_writes < history_len as u64 {
        0u16
    } else {
        history_index % history_len // next write pos IS the oldest
    };
    let start = offset
        .checked_add((oldest_idx as usize).checked_mul(TvlSnapshot::SERIALIZED_SIZE).ok_or(SandboxError::PDACorrupted)?)
        .ok_or(SandboxError::PDACorrupted)?;
    let end = start
        .checked_add(TvlSnapshot::SERIALIZED_SIZE)
        .ok_or(SandboxError::PDACorrupted)?;
    if end > data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    TvlSnapshot::deserialize(&data[start..end])
}

/// Read entry at a specific index in the ring buffer.
pub fn ring_buffer_read(
    data: &[u8],
    offset: usize,
    history_len: u16,
    index: u16,
) -> Result<TvlSnapshot, SandboxError> {
    if index >= history_len {
        return Err(SandboxError::PDACorrupted);
    }
    let start = offset
        .checked_add((index as usize).checked_mul(TvlSnapshot::SERIALIZED_SIZE).ok_or(SandboxError::PDACorrupted)?)
        .ok_or(SandboxError::PDACorrupted)?;
    let end = start
        .checked_add(TvlSnapshot::SERIALIZED_SIZE)
        .ok_or(SandboxError::PDACorrupted)?;
    if end > data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    TvlSnapshot::deserialize(&data[start..end])
}

// ─── Shared Window Utilities ───────────────────────────────────────────────

/// Check if a window has expired using dual-window logic.
/// Returns `true` if the entry is OUTSIDE the window (expired).
/// Dual-window: BOTH conditions must be within range; if EITHER says expired,
/// the entry is treated as expired (more conservative = smaller effective window).
pub fn window_expired(
    current_slot: u64,
    current_timestamp: i64,
    entry_slot: u64,
    entry_timestamp: i64,
    window_slots: u64,
    window_seconds: i64,
) -> bool {
    // Slot-based check: has the slot window elapsed?
    let slot_expired = current_slot.saturating_sub(entry_slot) > window_slots;
    // Time-based check: has the wall-clock window elapsed?
    let time_expired = current_timestamp.saturating_sub(entry_timestamp) > window_seconds;
    // Conservative: expired if EITHER window says so
    slot_expired || time_expired
}

/// Recalculate high-water-mark from the ring buffer when the stored HWM's slot
/// has fallen outside the current window.
pub fn recalculate_hwm_if_stale(
    data: &[u8],
    buffer_offset: usize,
    history_len: u16,
    total_writes: u64,
    current_slot: u64,
    current_timestamp: i64,
    window_slots: u64,
    window_seconds: i64,
    hwm_slot: u64,
    hwm_timestamp: i64,
) -> Result<(u64, u64, i64), SandboxError> {
    // If HWM is still within the window, no recalculation needed
    if !window_expired(
        current_slot,
        current_timestamp,
        hwm_slot,
        hwm_timestamp,
        window_slots,
        window_seconds,
    ) {
        // Return a sentinel — caller should keep existing values
        return Ok((u64::MAX, 0, 0)); // sentinel: u64::MAX means "keep existing"
    }

    // Scan the buffer to find the new max within the current window
    let entries = core::cmp::min(total_writes, history_len as u64) as u16;
    let mut max_val: u64 = 0;
    let mut max_slot: u64 = 0;
    let mut max_ts: i64 = 0;

    for i in 0..entries {
        let snap = ring_buffer_read(data, buffer_offset, history_len, i)?;
        if !window_expired(
            current_slot,
            current_timestamp,
            snap.slot,
            snap.timestamp,
            window_slots,
            window_seconds,
        ) {
            if snap.value > max_val {
                max_val = snap.value;
                max_slot = snap.slot;
                max_ts = snap.timestamp;
            }
        }
    }

    Ok((max_val, max_slot, max_ts))
}

// ─── PDA Field Access (read_u64 / write_u64) ──────────────────────────────

/// Read a u64 from PDA data at the given offset. Bounds-checked.
pub fn read_u64(data: &[u8], offset: usize) -> Result<u64, SandboxError> {
    let end = offset.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
    if end > data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    Ok(u64::from_le_bytes(
        data[offset..end]
            .try_into()
            .map_err(|_| SandboxError::PDACorrupted)?,
    ))
}

/// Write a u64 to PDA data at the given offset. Bounds-checked.
pub fn write_u64(data: &mut [u8], offset: usize, value: u64) -> Result<(), SandboxError> {
    let end = offset.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
    if end > data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    data[offset..end].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Read a u16 from PDA data at the given offset. Bounds-checked.
pub fn read_u16(data: &[u8], offset: usize) -> Result<u16, SandboxError> {
    let end = offset.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
    if end > data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    Ok(u16::from_le_bytes(
        data[offset..end]
            .try_into()
            .map_err(|_| SandboxError::PDACorrupted)?,
    ))
}

/// Write a u16 to PDA data at the given offset. Bounds-checked.
pub fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<(), SandboxError> {
    let end = offset.checked_add(2).ok_or(SandboxError::PDACorrupted)?;
    if end > data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    data[offset..end].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Read an i64 from PDA data at the given offset. Bounds-checked.
pub fn read_i64(data: &[u8], offset: usize) -> Result<i64, SandboxError> {
    let end = offset.checked_add(8).ok_or(SandboxError::PDACorrupted)?;
    if end > data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    Ok(i64::from_le_bytes(
        data[offset..end]
            .try_into()
            .map_err(|_| SandboxError::PDACorrupted)?,
    ))
}

/// Read a u8 from PDA data at the given offset. Bounds-checked.
pub fn read_u8(data: &[u8], offset: usize) -> Result<u8, SandboxError> {
    if offset >= data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    Ok(data[offset])
}

/// Write a u8 to PDA data at the given offset. Bounds-checked.
pub fn write_u8(data: &mut [u8], offset: usize, value: u8) -> Result<(), SandboxError> {
    if offset >= data.len() {
        return Err(SandboxError::PDACorrupted);
    }
    data[offset] = value;
    Ok(())
}

// ─── Circuit Breaker Actions ───────────────────────────────────────────────

/// What happens when a breaker fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerAction {
    /// Reject the current transaction — returns Err, tx reverts, attacker gets nothing.
    RejectCurrent,
    /// Current tx succeeds; set paused mode for next tx.
    Pause,
    /// Current tx succeeds; set close-only mode for next tx.
    CloseOnly,
    /// Current tx succeeds; pause liquidations for next tx.
    PauseLiquidations,
}

/// Result of evaluating a breaker: either the tx continues or a mode flag is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerResult {
    /// No breaker fired.
    Ok,
    /// Breaker fired with a deferred action — set this mode flag.
    SetMode(BreakerAction),
}

// ─── Per-Category Budget Config ────────────────────────────────────────────

/// Configuration for a single category's TVL cliff budget.
#[derive(Debug, Clone, Copy)]
pub struct CategoryBudget {
    pub category: InstructionCategory,
    /// Maximum decrease as basis points (e.g., 1500 = 15%).
    pub max_decrease_bps: u64,
}

/// List of instructions exempt from TVL cliff checking.
pub struct ExemptInstructions {
    pub categories: &'static [InstructionCategory],
}

impl ExemptInstructions {
    pub fn is_exempt(&self, cat: InstructionCategory) -> bool {
        self.categories.iter().any(|&c| c == cat)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BREAKER TYPE 1: TVL Cliff (windowed, per-category)
// ═══════════════════════════════════════════════════════════════════════════

/// PDA layout for a single category's TVL cliff state:
///   [0..2]   history_len: u16 (capacity)
///   [2..4]   history_index: u16 (next write position)
///   [4..12]  window_max_value: u64 (high-water mark)
///   [12..20] window_max_slot: u64
///   [20..28] window_max_timestamp: i64
///   [28..36] total_writes: u64
///   [36..]   ring buffer: TvlSnapshot * history_len
pub const TVL_HEADER_SIZE: usize = 36;

/// Evaluate the TVL cliff breaker for a given category.
///
/// `pda_data`: mutable slice of the full PDA
/// `section_offset`: byte offset where this category's TVL cliff section starts
/// `current_value`: the vault balance after business logic
/// `current_slot`: current slot
/// `current_timestamp`: current unix timestamp
/// `window_slots`: slot-based window size
/// `window_seconds`: time-based window size
/// `budget`: the category's max decrease budget
/// `action`: what to do if the breaker fires
///
/// Returns: Ok(BreakerResult) on success, Err on reject_current.
pub fn tvl_cliff_check(
    pda_data: &mut [u8],
    section_offset: usize,
    before_value: u64,
    current_value: u64,
    current_slot: u64,
    current_timestamp: i64,
    window_slots: u64,
    window_seconds: i64,
    budget: &CategoryBudget,
    action: BreakerAction,
) -> Result<BreakerResult, SandboxError> {
    let off = section_offset;

    // Read header fields
    let history_len = read_u16(pda_data, off)?;
    let history_index = read_u16(pda_data, off + 2)?;
    let mut hwm_value = read_u64(pda_data, off + 4)?;
    let mut hwm_slot = read_u64(pda_data, off + 12)?;
    let hwm_ts = read_i64(pda_data, off + 20)?;
    let total_writes = read_u64(pda_data, off + 28)?;

    let buffer_offset = off
        .checked_add(TVL_HEADER_SIZE)
        .ok_or(SandboxError::PDACorrupted)?;

    // Recalculate HWM if stale (outside current window)
    let (new_hwm, new_hwm_slot, new_hwm_ts) = recalculate_hwm_if_stale(
        pda_data,
        buffer_offset,
        history_len,
        total_writes,
        current_slot,
        current_timestamp,
        window_slots,
        window_seconds,
        hwm_slot,
        hwm_ts,
    )?;

    if new_hwm != u64::MAX {
        // HWM was recalculated
        hwm_value = new_hwm;
        hwm_slot = new_hwm_slot;
        write_u64(pda_data, off + 4, hwm_value)?;
        write_u64(pda_data, off + 12, hwm_slot)?;
        // Write timestamp as u64 (reinterpreted)
        let ts_bytes = new_hwm_ts.to_le_bytes();
        pda_data[off + 20..off + 28].copy_from_slice(&ts_bytes);
    }

    // R3-1 FIX: When HWM decays to zero on a cold market, use before_value
    // as the floor. This ensures the CURRENT drain is evaluated, not just
    // future drains. before_value is the pre-business-logic vault balance.
    if hwm_value == 0 && before_value > 0 {
        hwm_value = before_value;
        write_u64(pda_data, off + 4, before_value)?;
        write_u64(pda_data, off + 12, current_slot)?;
        let ts_bytes = current_timestamp.to_le_bytes();
        pda_data[off + 20..off + 28].copy_from_slice(&ts_bytes);
    }

    // Check if decrease exceeds budget
    let breaker_fired = if hwm_value > 0 && current_value < hwm_value {
        let decrease = hwm_value
            .checked_sub(current_value)
            .ok_or(SandboxError::CircuitBreakerTriggered)?;
        // decrease_bps = decrease * 10000 / hwm_value (use u128 to prevent overflow)
        let decrease_bps = (decrease as u128)
            .checked_mul(10_000)
            .ok_or(SandboxError::CircuitBreakerTriggered)?
            .checked_div(hwm_value as u128)
            .ok_or(SandboxError::CircuitBreakerTriggered)?;
        decrease_bps > budget.max_decrease_bps as u128
    } else {
        false
    };

    // Push current snapshot into ring buffer
    let snapshot = TvlSnapshot {
        value: current_value,
        slot: current_slot,
        timestamp: current_timestamp,
    };
    let new_index = ring_buffer_push(pda_data, buffer_offset, history_len, history_index, &snapshot)?;

    // Update header: index, total_writes
    write_u16(pda_data, off + 2, new_index)?;
    let new_total = total_writes
        .checked_add(1)
        .ok_or(SandboxError::CircuitBreakerTriggered)?;
    write_u64(pda_data, off + 28, new_total)?;

    // Update HWM if new value is higher
    if current_value > hwm_value {
        write_u64(pda_data, off + 4, current_value)?;
        write_u64(pda_data, off + 12, current_slot)?;
        let ts_bytes = current_timestamp.to_le_bytes();
        pda_data[off + 20..off + 28].copy_from_slice(&ts_bytes);
    }

    if breaker_fired {
        match action {
            BreakerAction::RejectCurrent => Err(SandboxError::CircuitBreakerTriggered),
            other => Ok(BreakerResult::SetMode(other)),
        }
    } else {
        Ok(BreakerResult::Ok)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BREAKER TYPE 2: Event Counter (rapid liquidations / withdrawals)
// ═══════════════════════════════════════════════════════════════════════════

/// PDA layout for event counter:
///   [0..4]   count: u32
///   [4..12]  window_start_slot: u64
///   [12..20] window_start_timestamp: i64
pub const EVENT_COUNTER_SIZE: usize = 20;

/// Check and increment an event counter breaker.
///
/// If the window has expired, resets the counter.
/// If count exceeds max_count, fires the breaker.
pub fn event_counter_check(
    pda_data: &mut [u8],
    section_offset: usize,
    current_slot: u64,
    current_timestamp: i64,
    window_slots: u64,
    window_seconds: i64,
    max_count: u32,
    action: BreakerAction,
) -> Result<BreakerResult, SandboxError> {
    let off = section_offset;

    // Validate section fits
    if off.checked_add(EVENT_COUNTER_SIZE).ok_or(SandboxError::PDACorrupted)? > pda_data.len() {
        return Err(SandboxError::PDACorrupted);
    }

    let mut count = u32::from_le_bytes(
        pda_data[off..off + 4]
            .try_into()
            .map_err(|_| SandboxError::PDACorrupted)?,
    );
    let window_start_slot = read_u64(pda_data, off + 4)?;
    let window_start_ts = read_i64(pda_data, off + 12)?;

    // Check if window expired — if so, reset
    if window_expired(
        current_slot,
        current_timestamp,
        window_start_slot,
        window_start_ts,
        window_slots,
        window_seconds,
    ) {
        count = 0;
        write_u64(pda_data, off + 4, current_slot)?;
        let ts_bytes = current_timestamp.to_le_bytes();
        pda_data[off + 12..off + 20].copy_from_slice(&ts_bytes);
    }

    // Increment
    count = count
        .checked_add(1)
        .ok_or(SandboxError::CircuitBreakerTriggered)?;
    pda_data[off..off + 4].copy_from_slice(&count.to_le_bytes());

    // Check threshold
    if count > max_count {
        match action {
            BreakerAction::RejectCurrent => Err(SandboxError::CircuitBreakerTriggered),
            other => Ok(BreakerResult::SetMode(other)),
        }
    } else {
        Ok(BreakerResult::Ok)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BREAKER TYPE 3: Per-TX Threshold (large single outflow)
// ═══════════════════════════════════════════════════════════════════════════

/// Stateless per-transaction check. No PDA state needed.
///
/// `before_value`: field value before business logic
/// `after_value`: field value after business logic
/// `max_decrease_bps`: maximum allowed decrease in basis points
/// `action`: what to do if breaker fires
pub fn per_tx_threshold_check(
    before_value: u64,
    after_value: u64,
    max_decrease_bps: u64,
    action: BreakerAction,
) -> Result<BreakerResult, SandboxError> {
    if before_value == 0 {
        // Nothing to decrease from
        return Ok(BreakerResult::Ok);
    }

    if after_value >= before_value {
        // No decrease
        return Ok(BreakerResult::Ok);
    }

    let decrease = before_value
        .checked_sub(after_value)
        .ok_or(SandboxError::CircuitBreakerTriggered)?;
    let decrease_bps = (decrease as u128)
        .checked_mul(10_000)
        .ok_or(SandboxError::CircuitBreakerTriggered)?
        .checked_div(before_value as u128)
        .ok_or(SandboxError::CircuitBreakerTriggered)?;

    if decrease_bps > max_decrease_bps as u128 {
        match action {
            BreakerAction::RejectCurrent => Err(SandboxError::CircuitBreakerTriggered),
            other => Ok(BreakerResult::SetMode(other)),
        }
    } else {
        Ok(BreakerResult::Ok)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Global Aggregate Breaker (§8.6) — READ-ONLY, per-transaction
// ═══════════════════════════════════════════════════════════════════════════

/// Read-only global aggregate circuit breaker.
///
/// Sums `vault_balance` across all market accounts provided.
/// Compares against the transaction anchor total.
/// No PDA write. No global write-lock. Per-transaction check only.
///
/// `market_balances`: vault_balance read from each market account in the tx
/// `anchor_total`: sum of vault_balance at transaction anchor time
/// `max_decrease_bps`: protocol-wide max decrease in basis points
pub fn global_aggregate_check(
    market_balances: &[u64],
    anchor_total: u64,
    max_decrease_bps: u64,
) -> Result<(), SandboxError> {
    if anchor_total == 0 {
        return Ok(());
    }

    // Sum current balances with checked arithmetic
    let mut current_total: u64 = 0;
    for &balance in market_balances {
        current_total = current_total
            .checked_add(balance)
            .ok_or(SandboxError::CircuitBreakerTriggered)?;
    }

    if current_total >= anchor_total {
        return Ok(());
    }

    let decrease = anchor_total
        .checked_sub(current_total)
        .ok_or(SandboxError::CircuitBreakerTriggered)?;
    let decrease_bps = (decrease as u128)
        .checked_mul(10_000)
        .ok_or(SandboxError::CircuitBreakerTriggered)?
        .checked_div(anchor_total as u128)
        .ok_or(SandboxError::CircuitBreakerTriggered)?;

    if decrease_bps > max_decrease_bps as u128 {
        Err(SandboxError::CircuitBreakerTriggered)
    } else {
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Mode Flag Helpers (for deferred actions)
// ═══════════════════════════════════════════════════════════════════════════

/// Mode flags stored in the PDA. Spec §8.2: mode flags section layout.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModeFlags {
    pub paused: bool,
    pub close_only: bool,
    pub liquidation_paused: bool,
    pub emergency_bypass_active: bool,
}

/// Apply a deferred breaker action to mode flags.
/// Called when a breaker fires with pause/close_only/pause_liquidations.
/// The current tx succeeds; the flag restricts NEXT transactions.
pub fn apply_deferred_action(flags: &mut ModeFlags, action: BreakerAction) {
    match action {
        BreakerAction::Pause => flags.paused = true,
        BreakerAction::CloseOnly => flags.close_only = true,
        BreakerAction::PauseLiquidations => flags.liquidation_paused = true,
        BreakerAction::RejectCurrent => {} // handled by Err path, not here
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a PDA buffer with a TVL cliff section for testing.
    fn make_tvl_section(history_len: u16) -> (Vec<u8>, usize) {
        let buf_size =
            TVL_HEADER_SIZE + (history_len as usize) * TvlSnapshot::SERIALIZED_SIZE;
        let mut data = vec![0u8; buf_size];
        // Write history_len
        data[0..2].copy_from_slice(&history_len.to_le_bytes());
        // history_index = 0, hwm = 0, total_writes = 0
        (data, 0)
    }

    /// Helper: create an event counter section.
    fn make_event_counter_section() -> (Vec<u8>, usize) {
        let data = vec![0u8; EVENT_COUNTER_SIZE];
        (data, 0)
    }

    #[test]
    fn test_tvl_cliff_triggers_at_threshold() {
        let (mut data, off) = make_tvl_section(10);
        let budget = CategoryBudget {
            category: InstructionCategory::Withdrawal,
            max_decrease_bps: 1500, // 15%
        };

        // First: record a high value
        let result = tvl_cliff_check(
            &mut data, off, 1_000_000, 1_000_000, 100, 1000, 1500, 600, &budget, BreakerAction::RejectCurrent,
        );
        assert_eq!(result.unwrap(), BreakerResult::Ok);

        // Second: drop by 16% — should trigger
        let result = tvl_cliff_check(
            &mut data, off, 840_000, 840_000, 101, 1001, 1500, 600, &budget, BreakerAction::RejectCurrent,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SandboxError::CircuitBreakerTriggered);
    }

    #[test]
    fn test_tvl_cliff_within_budget_ok() {
        let (mut data, off) = make_tvl_section(10);
        let budget = CategoryBudget {
            category: InstructionCategory::Withdrawal,
            max_decrease_bps: 1500,
        };

        // Record high
        tvl_cliff_check(
            &mut data, off, 1_000_000, 1_000_000, 100, 1000, 1500, 600, &budget, BreakerAction::RejectCurrent,
        )
        .unwrap();

        // Drop by 14% — within budget
        let result = tvl_cliff_check(
            &mut data, off, 860_000, 860_000, 101, 1001, 1500, 600, &budget, BreakerAction::RejectCurrent,
        );
        assert_eq!(result.unwrap(), BreakerResult::Ok);
    }

    #[test]
    fn test_category_isolation() {
        // Withdrawal breaker shouldn't affect liquidation breaker
        let (mut w_data, w_off) = make_tvl_section(10);
        let (mut l_data, l_off) = make_tvl_section(10);

        let w_budget = CategoryBudget {
            category: InstructionCategory::Withdrawal,
            max_decrease_bps: 1500,
        };
        let l_budget = CategoryBudget {
            category: InstructionCategory::Liquidation,
            max_decrease_bps: 2500,
        };

        // Record high on both
        tvl_cliff_check(
            &mut w_data, w_off, 1_000_000, 1_000_000, 100, 1000, 1500, 600, &w_budget, BreakerAction::RejectCurrent,
        ).unwrap();
        tvl_cliff_check(
            &mut l_data, l_off, 1_000_000, 1_000_000, 100, 1000, 1500, 600, &l_budget, BreakerAction::RejectCurrent,
        ).unwrap();

        // Drop 20% on withdrawal — should fire
        let w_result = tvl_cliff_check(
            &mut w_data, w_off, 800_000, 800_000, 101, 1001, 1500, 600, &w_budget, BreakerAction::RejectCurrent,
        );
        assert!(w_result.is_err());

        // Drop 20% on liquidation — within its 25% budget, should pass
        let l_result = tvl_cliff_check(
            &mut l_data, l_off, 800_000, 800_000, 101, 1001, 1500, 600, &l_budget, BreakerAction::RejectCurrent,
        );
        assert_eq!(l_result.unwrap(), BreakerResult::Ok);
    }

    #[test]
    fn test_hwm_tracking() {
        let (mut data, off) = make_tvl_section(10);
        let budget = CategoryBudget {
            category: InstructionCategory::Withdrawal,
            max_decrease_bps: 1500,
        };

        // Push increasing values
        tvl_cliff_check(&mut data, off, 500_000, 500_000, 100, 1000, 1500, 600, &budget, BreakerAction::RejectCurrent).unwrap();
        tvl_cliff_check(&mut data, off, 800_000, 800_000, 101, 1001, 1500, 600, &budget, BreakerAction::RejectCurrent).unwrap();
        tvl_cliff_check(&mut data, off, 1_000_000, 1_000_000, 102, 1002, 1500, 600, &budget, BreakerAction::RejectCurrent).unwrap();

        // Verify HWM is the peak (1_000_000)
        let hwm = read_u64(&data, off + 4).unwrap();
        assert_eq!(hwm, 1_000_000);

        // Drop from HWM: 16% = should trigger
        let result = tvl_cliff_check(
            &mut data, off, 839_000, 839_000, 103, 1003, 1500, 600, &budget, BreakerAction::RejectCurrent,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_hwm_recalculation_on_window_expiry() {
        let (mut data, off) = make_tvl_section(10);
        let budget = CategoryBudget {
            category: InstructionCategory::Withdrawal,
            max_decrease_bps: 1500,
        };

        // Record HWM at slot 100
        tvl_cliff_check(&mut data, off, 1_000_000, 1_000_000, 100, 1000, 100, 600, &budget, BreakerAction::RejectCurrent).unwrap();
        // Record lower value at slot 150
        tvl_cliff_check(&mut data, off, 900_000, 900_000, 150, 1050, 100, 600, &budget, BreakerAction::RejectCurrent).unwrap();

        // Now at slot 250 — slot 100 entry is outside window (250-100=150 > 100 slots)
        // HWM should be recalculated; slot 150 entry (900k) is the new HWM
        // 800k is ~11% decrease from 900k — within 15% budget
        let result = tvl_cliff_check(
            &mut data, off, 800_000, 800_000, 250, 1200, 100, 600, &budget, BreakerAction::RejectCurrent,
        );
        assert_eq!(result.unwrap(), BreakerResult::Ok);
    }

    #[test]
    fn test_dual_window_more_conservative() {
        // Slot window says in-window, but timestamp says expired
        // Should treat as expired (more conservative)
        let expired = window_expired(
            200,   // current_slot
            2000,  // current_timestamp
            100,   // entry_slot (only 100 slots ago — within 150 slot window)
            1000,  // entry_timestamp (1000 seconds ago — outside 600 second window)
            150,   // window_slots
            600,   // window_seconds
        );
        assert!(expired, "Should be expired because timestamp window says so");

        // Timestamp says in-window, but slot says expired
        let expired2 = window_expired(
            300,   // current_slot
            1100,  // current_timestamp
            100,   // entry_slot (200 slots ago — outside 150 slot window)
            1000,  // entry_timestamp (100 seconds ago — within 600 second window)
            150,   // window_slots
            600,   // window_seconds
        );
        assert!(expired2, "Should be expired because slot window says so");

        // Both say in-window
        let not_expired = window_expired(200, 1100, 150, 1000, 150, 600);
        assert!(!not_expired, "Both windows say in-range");
    }

    #[test]
    fn test_event_counter_triggers() {
        let (mut data, off) = make_event_counter_section();

        for i in 0..20u32 {
            let result = event_counter_check(
                &mut data,
                off,
                100 + i as u64,
                1000 + i as i64,
                150,
                600,
                20,
                BreakerAction::PauseLiquidations,
            );
            assert_eq!(result.unwrap(), BreakerResult::Ok, "Event {} should pass", i);
        }

        // 21st event should trigger
        let result = event_counter_check(
            &mut data, off, 120, 1020, 150, 600, 20, BreakerAction::PauseLiquidations,
        );
        assert_eq!(
            result.unwrap(),
            BreakerResult::SetMode(BreakerAction::PauseLiquidations)
        );
    }

    #[test]
    fn test_event_counter_window_reset() {
        let (mut data, off) = make_event_counter_section();

        // Fill to max
        for i in 0..20u32 {
            event_counter_check(
                &mut data, off, 100 + i as u64, 1000 + i as i64, 150, 600, 20,
                BreakerAction::PauseLiquidations,
            ).unwrap();
        }

        // Jump past window (slot-based) — count should reset
        let result = event_counter_check(
            &mut data, off, 500, 2000, 150, 600, 20, BreakerAction::PauseLiquidations,
        );
        assert_eq!(result.unwrap(), BreakerResult::Ok);

        // Count should be 1 now (just the one we did)
        let count = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        assert_eq!(count, 1);
    }

    #[test]
    fn test_per_tx_threshold() {
        // 20% drop, 15% budget — should fire
        let result =
            per_tx_threshold_check(1_000_000, 800_000, 1500, BreakerAction::RejectCurrent);
        assert!(result.is_err());

        // 10% drop, 15% budget — should pass
        let result =
            per_tx_threshold_check(1_000_000, 900_000, 1500, BreakerAction::RejectCurrent);
        assert_eq!(result.unwrap(), BreakerResult::Ok);

        // Increase — should pass
        let result =
            per_tx_threshold_check(1_000_000, 1_100_000, 1500, BreakerAction::RejectCurrent);
        assert_eq!(result.unwrap(), BreakerResult::Ok);

        // Zero before — should pass
        let result = per_tx_threshold_check(0, 100_000, 1500, BreakerAction::RejectCurrent);
        assert_eq!(result.unwrap(), BreakerResult::Ok);
    }

    #[test]
    fn test_global_aggregate_check() {
        // 5 markets, each had 1M. Now total dropped 20% from 5M to 4M.
        let balances = [800_000u64, 800_000, 800_000, 800_000, 800_000];
        let anchor_total = 5_000_000u64;

        // 25% budget — 20% drop should pass
        assert!(global_aggregate_check(&balances, anchor_total, 2500).is_ok());

        // 15% budget — 20% drop should fire
        assert!(global_aggregate_check(&balances, anchor_total, 1500).is_err());
    }

    #[test]
    fn test_global_aggregate_zero_anchor() {
        let balances = [100u64, 200];
        assert!(global_aggregate_check(&balances, 0, 1500).is_ok());
    }

    #[test]
    fn test_deferred_action_sets_mode() {
        let mut flags = ModeFlags::default();
        assert!(!flags.paused);
        assert!(!flags.close_only);
        assert!(!flags.liquidation_paused);

        apply_deferred_action(&mut flags, BreakerAction::Pause);
        assert!(flags.paused);

        apply_deferred_action(&mut flags, BreakerAction::CloseOnly);
        assert!(flags.close_only);

        apply_deferred_action(&mut flags, BreakerAction::PauseLiquidations);
        assert!(flags.liquidation_paused);
    }

    #[test]
    fn test_ring_buffer_bounds_check() {
        // Buffer too small
        let mut data = vec![0u8; 10];
        let snap = TvlSnapshot {
            value: 100,
            slot: 1,
            timestamp: 1,
        };
        let result = ring_buffer_push(&mut data, 0, 1, 0, &snap);
        assert!(result.is_err());
    }

    #[test]
    fn test_exempt_instructions() {
        let exempt = ExemptInstructions {
            categories: &[InstructionCategory::Liquidation],
        };
        assert!(exempt.is_exempt(InstructionCategory::Liquidation));
        assert!(!exempt.is_exempt(InstructionCategory::Withdrawal));
        assert!(!exempt.is_exempt(InstructionCategory::Default));
    }

    #[test]
    fn test_f1_hwm_zero_decay_bypass_blocked() {
        // R3-1: When all ring buffer entries expire, HWM decays to 0.
        // The R2 fix used current_value (post-drain) as the floor, which
        // meant the FIRST drain after cold market was unprotected.
        // R3 fix: use before_value (pre-business-logic balance) as the floor.
        let (mut data, off) = make_tvl_section(4);
        let budget = CategoryBudget {
            category: InstructionCategory::Withdrawal,
            max_decrease_bps: 1500, // 15%
        };

        // Record a high value at slot 100, timestamp 1000
        // Use a short window: 50 slots, 300 seconds
        tvl_cliff_check(
            &mut data, off, 1_000_000, 1_000_000, 100, 1000, 50, 300, &budget, BreakerAction::RejectCurrent,
        ).unwrap();

        // Verify HWM is 1_000_000
        assert_eq!(read_u64(&data, off + 4).unwrap(), 1_000_000);

        // Now jump far into the future: slot 500, timestamp 5000
        // All entries are expired (500-100=400 > 50 slot window)
        // HWM decays to 0. Attacker tries to drain 80%.
        // before_value = 1_000_000 (vault before withdrawal)
        // current_value = 200_000 (vault after withdrawal)
        // R3 fix sets HWM = before_value = 1_000_000
        // Decrease = 800K from 1M = 80% > 15% budget → REJECT
        let result = tvl_cliff_check(
            &mut data, off, 1_000_000, 200_000, 500, 5000, 50, 300, &budget, BreakerAction::RejectCurrent,
        );
        assert!(result.is_err(), "R3: First drain after cold market must be caught");
        assert_eq!(result.unwrap_err(), SandboxError::CircuitBreakerTriggered);
    }

    #[test]
    fn test_r3_staircase_drain_blocked() {
        // Proves that repeated cold-market drains are caught on EVERY cycle,
        // not just the second one. Attacker pattern:
        //   1. Wait for cold market (HWM → 0)
        //   2. Drain a chunk
        //   3. Wait for cold again
        //   4. Drain again
        // Each drain must be caught.
        let (mut data, off) = make_tvl_section(4);
        let budget = CategoryBudget {
            category: InstructionCategory::Withdrawal,
            max_decrease_bps: 1500, // 15%
        };

        // === Cycle 1: Vault starts at 1M ===
        tvl_cliff_check(
            &mut data, off, 1_000_000, 1_000_000, 100, 1000, 50, 300, &budget, BreakerAction::RejectCurrent,
        ).unwrap();

        // Cold market: jump far ahead, all entries expire
        // Attacker tries to drain 50% (1M → 500K)
        let result = tvl_cliff_check(
            &mut data, off, 1_000_000, 500_000, 500, 5000, 50, 300, &budget, BreakerAction::RejectCurrent,
        );
        assert!(result.is_err(), "Cycle 1: 50% drain must be caught");

        // === Cycle 2: Vault still at 1M (tx was rejected), deposit brings it back ===
        // Record the vault at 1M again in a new window
        let (mut data2, off2) = make_tvl_section(4);
        tvl_cliff_check(
            &mut data2, off2, 1_000_000, 1_000_000, 600, 6000, 50, 300, &budget, BreakerAction::RejectCurrent,
        ).unwrap();

        // Cold market again
        // Attacker tries 30% drain (1M → 700K)
        let result = tvl_cliff_check(
            &mut data2, off2, 1_000_000, 700_000, 1000, 10000, 50, 300, &budget, BreakerAction::RejectCurrent,
        );
        assert!(result.is_err(), "Cycle 2: 30% drain must be caught");

        // === Cycle 3: Smaller vault, still caught ===
        let (mut data3, off3) = make_tvl_section(4);
        tvl_cliff_check(
            &mut data3, off3, 500_000, 500_000, 1100, 11000, 50, 300, &budget, BreakerAction::RejectCurrent,
        ).unwrap();

        // Cold market, 20% drain (500K → 400K)
        let result = tvl_cliff_check(
            &mut data3, off3, 500_000, 400_000, 1500, 15000, 50, 300, &budget, BreakerAction::RejectCurrent,
        );
        assert!(result.is_err(), "Cycle 3: 20% drain must be caught");
    }

    #[test]
    fn test_overflow_fail_closed() {
        // near-overflow multiplication in per_tx_threshold_check
        let result = per_tx_threshold_check(
            u64::MAX,
            0,
            1500,
            BreakerAction::RejectCurrent,
        );
        // decrease * 10000 overflows → fail-closed
        assert!(result.is_err());
    }
}

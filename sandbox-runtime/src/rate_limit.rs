// rate_limit.rs — Per-signer and global rate limiting for PERK Sandbox
//
// Spec §4 pre-checks: rate limits run on EVERY call including re-entrant and
// emergency bypass. Window-based reset with checked arithmetic.
//
// PDA layout per counter:
//   [0]      counter_id: u8
//   [1..5]   count: u32
//   [5..13]  window_start_slot: u64
//
// Per-signer counters are keyed by truncated pubkey hash to fit PDA space.

use crate::error::SandboxError;

/// Size of a single rate limit counter in PDA bytes.
pub const COUNTER_SIZE: usize = 13; // 1 (id) + 4 (count) + 8 (window_start_slot)

/// A rate limit counter (in-memory representation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitCounter {
    pub counter_id: u8,
    pub count: u32,
    pub window_start_slot: u64,
}

impl RateLimitCounter {
    /// Deserialize from PDA data at offset.
    pub fn read(data: &[u8], offset: usize) -> Result<Self, SandboxError> {
        let end = offset
            .checked_add(COUNTER_SIZE)
            .ok_or(SandboxError::PDACorrupted)?;
        if end > data.len() {
            return Err(SandboxError::PDACorrupted);
        }
        let counter_id = data[offset];
        let count = u32::from_le_bytes(
            data[offset + 1..offset + 5]
                .try_into()
                .map_err(|_| SandboxError::PDACorrupted)?,
        );
        let window_start_slot = u64::from_le_bytes(
            data[offset + 5..offset + 13]
                .try_into()
                .map_err(|_| SandboxError::PDACorrupted)?,
        );
        Ok(Self {
            counter_id,
            count,
            window_start_slot,
        })
    }

    /// Serialize to PDA data at offset.
    pub fn write(&self, data: &mut [u8], offset: usize) -> Result<(), SandboxError> {
        let end = offset
            .checked_add(COUNTER_SIZE)
            .ok_or(SandboxError::PDACorrupted)?;
        if end > data.len() {
            return Err(SandboxError::PDACorrupted);
        }
        data[offset] = self.counter_id;
        data[offset + 1..offset + 5].copy_from_slice(&self.count.to_le_bytes());
        data[offset + 5..offset + 13].copy_from_slice(&self.window_start_slot.to_le_bytes());
        Ok(())
    }
}

/// Check whether the rate limit is exceeded.
///
/// If `current_slot > window_start + window_slots`, the window has expired
/// and the counter should be treated as reset (count = 0).
///
/// Does NOT modify state — this is a read-only check.
/// Call `increment_counter` after business logic succeeds.
pub fn check_rate_limit(
    counter: &RateLimitCounter,
    max_count: u32,
    window_slots: u64,
    current_slot: u64,
) -> Result<(), SandboxError> {
    // If window has expired, counter is effectively 0 — always passes
    let window_end = counter
        .window_start_slot
        .checked_add(window_slots)
        .ok_or(SandboxError::RateLimitExceeded)?; // overflow = fail-closed
    if current_slot > window_end {
        return Ok(());
    }

    // Within window — check count
    if counter.count >= max_count {
        return Err(SandboxError::RateLimitExceeded);
    }

    Ok(())
}

/// Increment the counter. Called AFTER business logic succeeds.
///
/// If the window has expired, resets count to 1 and starts a new window.
/// Otherwise increments the existing count.
///
/// Writes directly to PDA data at the given offset.
pub fn increment_counter(
    data: &mut [u8],
    offset: usize,
    window_slots: u64,
    current_slot: u64,
) -> Result<(), SandboxError> {
    let mut counter = RateLimitCounter::read(data, offset)?;

    let window_end = counter
        .window_start_slot
        .checked_add(window_slots)
        .ok_or(SandboxError::RateLimitExceeded)?;

    if current_slot > window_end {
        // Window expired — start fresh
        counter.count = 1;
        counter.window_start_slot = current_slot;
    } else {
        // Within window — increment
        counter.count = counter
            .count
            .checked_add(1)
            .ok_or(SandboxError::RateLimitExceeded)?; // overflow = fail-closed
    }

    counter.write(data, offset)
}

/// Compute a truncated hash of a signer pubkey for per-signer counter lookup.
///
/// Returns a u8 index (0-255) suitable for indexing into a fixed array of counters.
/// For denser keying, use `signer_hash_u16`.
pub fn signer_hash_u8(pubkey_bytes: &[u8; 32]) -> u8 {
    // FNV-1a inspired 8-bit hash for better distribution
    let mut h: u8 = 0x47; // offset basis
    for &b in pubkey_bytes.iter() {
        h ^= b;
        h = h.wrapping_mul(0x65); // prime multiplier
    }
    h
}

/// Compute a 16-bit hash of a signer pubkey for per-signer counter lookup.
/// Provides 65536 buckets — low collision rate for typical signer counts.
pub fn signer_hash_u16(pubkey_bytes: &[u8; 32]) -> u16 {
    // FNV-1a inspired 16-bit hash
    let mut h: u16 = 0x811C; // offset basis (truncated)
    for &b in pubkey_bytes.iter() {
        h ^= b as u16;
        h = h.wrapping_mul(0x0101); // FNV prime approximation for 16-bit
    }
    h
}

/// Find a per-signer counter in the PDA's rate limit section.
///
/// `section_offset`: start of rate limit section
/// `counter_count`: number of counters in the section
/// `signer_id`: the counter_id to look for (from signer_hash_u8)
///
/// Returns the offset of the matching counter, or None if not found.
pub fn find_counter(
    data: &[u8],
    section_offset: usize,
    counter_count: u8,
    signer_id: u8,
) -> Result<Option<usize>, SandboxError> {
    for i in 0..counter_count as usize {
        let off = section_offset
            .checked_add(i.checked_mul(COUNTER_SIZE).ok_or(SandboxError::PDACorrupted)?)
            .ok_or(SandboxError::PDACorrupted)?;
        let end = off
            .checked_add(COUNTER_SIZE)
            .ok_or(SandboxError::PDACorrupted)?;
        if end > data.len() {
            return Err(SandboxError::PDACorrupted);
        }
        if data[off] == signer_id {
            return Ok(Some(off));
        }
    }
    Ok(None)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_counter_data(id: u8, count: u32, window_start: u64) -> Vec<u8> {
        let mut data = vec![0u8; COUNTER_SIZE];
        let c = RateLimitCounter {
            counter_id: id,
            count,
            window_start_slot: window_start,
        };
        c.write(&mut data, 0).unwrap();
        data
    }

    #[test]
    fn test_check_within_limit() {
        let counter = RateLimitCounter {
            counter_id: 0,
            count: 5,
            window_start_slot: 100,
        };
        // max 10, window 150 slots, current slot 200 (within window: 100+150=250 > 200)
        assert!(check_rate_limit(&counter, 10, 150, 200).is_ok());
    }

    #[test]
    fn test_check_at_limit() {
        let counter = RateLimitCounter {
            counter_id: 0,
            count: 10,
            window_start_slot: 100,
        };
        // count == max → rejected
        assert_eq!(
            check_rate_limit(&counter, 10, 150, 200).unwrap_err(),
            SandboxError::RateLimitExceeded
        );
    }

    #[test]
    fn test_check_window_expired_resets() {
        let counter = RateLimitCounter {
            counter_id: 0,
            count: 100, // way over any limit
            window_start_slot: 100,
        };
        // current_slot 300 > window_end 250 → window expired, treated as 0
        assert!(check_rate_limit(&counter, 10, 150, 300).is_ok());
    }

    #[test]
    fn test_increment_within_window() {
        let mut data = make_counter_data(1, 5, 100);
        increment_counter(&mut data, 0, 150, 200).unwrap();
        let c = RateLimitCounter::read(&data, 0).unwrap();
        assert_eq!(c.count, 6);
        assert_eq!(c.window_start_slot, 100); // unchanged
    }

    #[test]
    fn test_increment_window_expired() {
        let mut data = make_counter_data(1, 99, 100);
        // slot 300 > window_end 250 → reset
        increment_counter(&mut data, 0, 150, 300).unwrap();
        let c = RateLimitCounter::read(&data, 0).unwrap();
        assert_eq!(c.count, 1); // reset to 1
        assert_eq!(c.window_start_slot, 300); // new window
    }

    #[test]
    fn test_increment_overflow_fail_closed() {
        let mut data = make_counter_data(1, u32::MAX, 100);
        let result = increment_counter(&mut data, 0, 150, 200);
        assert_eq!(result.unwrap_err(), SandboxError::RateLimitExceeded);
    }

    #[test]
    fn test_find_counter_found() {
        // 3 counters
        let mut data = vec![0u8; COUNTER_SIZE * 3];
        RateLimitCounter { counter_id: 10, count: 0, window_start_slot: 0 }
            .write(&mut data, 0).unwrap();
        RateLimitCounter { counter_id: 20, count: 0, window_start_slot: 0 }
            .write(&mut data, COUNTER_SIZE).unwrap();
        RateLimitCounter { counter_id: 30, count: 0, window_start_slot: 0 }
            .write(&mut data, COUNTER_SIZE * 2).unwrap();

        let found = find_counter(&data, 0, 3, 20).unwrap();
        assert_eq!(found, Some(COUNTER_SIZE));

        let not_found = find_counter(&data, 0, 3, 99).unwrap();
        assert_eq!(not_found, None);
    }

    #[test]
    fn test_signer_hash_deterministic() {
        let key = [42u8; 32];
        assert_eq!(signer_hash_u8(&key), signer_hash_u8(&key));
        assert_eq!(signer_hash_u16(&key), signer_hash_u16(&key));
    }

    #[test]
    fn test_signer_hash_different_keys() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        // Different keys should (usually) produce different hashes
        // Not guaranteed but extremely likely for these inputs
        assert_ne!(signer_hash_u8(&key_a), signer_hash_u8(&key_b));
    }

    #[test]
    fn test_counter_roundtrip() {
        let mut data = vec![0u8; COUNTER_SIZE];
        let original = RateLimitCounter {
            counter_id: 42,
            count: 1234,
            window_start_slot: 999_999,
        };
        original.write(&mut data, 0).unwrap();
        let read_back = RateLimitCounter::read(&data, 0).unwrap();
        assert_eq!(original, read_back);
    }

    #[test]
    fn test_bounds_check_on_read() {
        let data = vec![0u8; 5]; // too small
        let result = RateLimitCounter::read(&data, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_bounds_check_on_write() {
        let mut data = vec![0u8; 5]; // too small
        let c = RateLimitCounter {
            counter_id: 0,
            count: 0,
            window_start_slot: 0,
        };
        assert!(c.write(&mut data, 0).is_err());
    }
}

//! Integration tests for the PERK Sandbox pipeline.
//!
//! These tests verify that the #[sandbox_program] macro generates valid code
//! and that the runtime components work together end-to-end.
//!
//! Test categories:
//!   1. PDA state lifecycle (init → serialize → deserialize → validate)
//!   2. Circuit breaker full flow (push → HWM → check → deferred action)
//!   3. TX anchor full flow (fingerprint → write → read → cumulative decrease)
//!   4. Guard lifecycle (enter → reenter → exit → exit → clean)
//!   5. Rate limit full flow (check → increment → window expire → reset)
//!   6. Oracle freshness + deviation end-to-end

use perk_sandbox_runtime::{
    circuit_breaker::{
        self, BreakerAction, BreakerResult, CategoryBudget, InstructionCategory, TvlSnapshot,
    },
    guard,
    oracle::{self, OracleLayout, OracleReading},
    rate_limit::{self, RateLimitCounter},
    state::SandboxState,
    tx_anchor::{self, ANCHOR_SECTION_SIZE, FIELD_SIZE, MAX_ANCHOR_FIELDS},
};
use solana_program::pubkey::Pubkey;

// ============================================================================
// 1. PDA State Full Lifecycle
// ============================================================================

#[test]
fn pda_lifecycle_init_serialize_deserialize_validate() {
    // Create a fully populated state
    let mut state = SandboxState::new(254);
    state.mode_flags.paused = true;
    state.mode_flags.close_only = false;
    state.mode_flags.liquidation_paused = true;
    state.mode_flags.emergency_bypass_active = false;
    state.mode_flags.paused_at_slot = 123_456;
    state.mode_flags.cooldown_end_slot = 999_999;

    state.guard = perk_sandbox_runtime::state::ReentrancyGuard {
        executing: false,
        depth: 0,
    };

    state.circuit_breaker = perk_sandbox_runtime::state::CircuitBreakerState {
        categories: vec![perk_sandbox_runtime::state::CircuitBreakerCategory {
            category_id: 0,
            history_len: 4,
            history_index: 0,
            window_max_value: 1_000_000,
            window_max_slot: 100,
            window_max_timestamp: 1_700_000_000,
            total_writes: 0,
            history: vec![
                perk_sandbox_runtime::state::TvlSnapshot { value: 0, slot: 0, timestamp: 0 },
                perk_sandbox_runtime::state::TvlSnapshot { value: 0, slot: 0, timestamp: 0 },
                perk_sandbox_runtime::state::TvlSnapshot { value: 0, slot: 0, timestamp: 0 },
                perk_sandbox_runtime::state::TvlSnapshot { value: 0, slot: 0, timestamp: 0 },
            ],
        }],
    };

    state.rate_limits = perk_sandbox_runtime::state::RateLimitState {
        counters: vec![
            perk_sandbox_runtime::state::RateLimitCounter {
                counter_id: 0,
                count: 0,
                window_start_slot: 0,
            },
        ],
    };

    // Serialize
    let size = state.total_size().unwrap();
    let mut buf = vec![0u8; size];
    state.serialize(&mut buf).unwrap();

    // Validate offsets
    SandboxState::validate_offsets(&buf).unwrap();

    // Deserialize
    let decoded = SandboxState::deserialize(&buf).unwrap();
    assert_eq!(state, decoded);

    // Verify individual fields survived the round trip
    assert!(decoded.mode_flags.paused);
    assert!(decoded.mode_flags.liquidation_paused);
    assert_eq!(decoded.mode_flags.paused_at_slot, 123_456);
    assert_eq!(decoded.circuit_breaker.categories.len(), 1);
    assert_eq!(decoded.circuit_breaker.categories[0].history_len, 4);
    assert_eq!(decoded.rate_limits.counters.len(), 1);
}

// ============================================================================
// 2. Circuit Breaker Full Flow
// ============================================================================

#[test]
fn circuit_breaker_full_flow_deposit_then_drain() {
    // Simulate: vault starts at 1M, deposit to 1.5M, then drain to 800K
    // Budget: 15% max decrease. HWM should track 1.5M, drain = 46.7% → FIRE

    let history_len: u16 = 4;
    let tvl_header = 36usize; // TVL_HEADER_SIZE
    let snap_size = 24usize;  // TvlSnapshot::SERIALIZED_SIZE
    let section_size = tvl_header + (history_len as usize) * snap_size;
    let mut pda = vec![0u8; section_size];

    // Write initial history_len
    pda[0..2].copy_from_slice(&history_len.to_le_bytes());

    let budget = CategoryBudget {
        category: InstructionCategory::Withdrawal,
        max_decrease_bps: 1500, // 15%
    };

    // Step 1: Deposit — vault goes from 1M to 1.5M
    let result = circuit_breaker::tvl_cliff_check(
        &mut pda, 0,
        1_000_000, // before
        1_500_000, // current (deposit increased it)
        100, 1_700_000_000,
        2500, 600,
        &budget,
        BreakerAction::Pause,
    ).unwrap();
    assert_eq!(result, BreakerResult::Ok, "deposit should not trigger breaker");

    // Step 2: Drain — vault goes from 1.5M to 800K
    let result = circuit_breaker::tvl_cliff_check(
        &mut pda, 0,
        1_500_000, // before
        800_000,   // current (drained)
        101, 1_700_000_001,
        2500, 600,
        &budget,
        BreakerAction::Pause,
    ).unwrap();
    // HWM is 1.5M from the deposit. Decrease = 700K/1.5M = 46.7% > 15%
    assert_eq!(result, BreakerResult::SetMode(BreakerAction::Pause),
        "drain past HWM threshold must trigger deferred pause");
}

#[test]
fn circuit_breaker_reject_current_returns_err() {
    let history_len: u16 = 2;
    let section_size = 36 + 2 * 24;
    let mut pda = vec![0u8; section_size];
    pda[0..2].copy_from_slice(&history_len.to_le_bytes());

    let budget = CategoryBudget {
        category: InstructionCategory::Withdrawal,
        max_decrease_bps: 500, // 5%
    };

    // First call to establish HWM
    circuit_breaker::tvl_cliff_check(
        &mut pda, 0,
        1_000_000, 1_000_000,
        100, 1_700_000_000,
        2500, 600,
        &budget,
        BreakerAction::RejectCurrent,
    ).unwrap();

    // Drain 20% → should reject
    let result = circuit_breaker::tvl_cliff_check(
        &mut pda, 0,
        1_000_000, 800_000,
        101, 1_700_000_001,
        2500, 600,
        &budget,
        BreakerAction::RejectCurrent,
    );
    assert!(result.is_err(), "20% drain with 5% budget must return Err on RejectCurrent");
}

#[test]
fn circuit_breaker_cold_market_hwm_floor() {
    // R3-1 fix: after window expiry, HWM decays to 0.
    // before_value should be used as the floor.
    let history_len: u16 = 2;
    let section_size = 36 + 2 * 24;
    let mut pda = vec![0u8; section_size];
    pda[0..2].copy_from_slice(&history_len.to_le_bytes());

    let budget = CategoryBudget {
        category: InstructionCategory::Withdrawal,
        max_decrease_bps: 1500, // 15%
    };

    // First call: establish baseline at slot 100
    circuit_breaker::tvl_cliff_check(
        &mut pda, 0,
        1_000_000, 1_000_000,
        100, 1_700_000_000,
        100, 60, // short window
        &budget,
        BreakerAction::Pause,
    ).unwrap();

    // Wait for window to expire (slot 300, well past 100 + 100 = 200)
    // Drain 20%: before=1M, current=800K
    let result = circuit_breaker::tvl_cliff_check(
        &mut pda, 0,
        1_000_000, 800_000,
        300, 1_700_000_200,
        100, 60,
        &budget,
        BreakerAction::Pause,
    ).unwrap();

    // R3-1 fix: HWM was 0 (expired), set to before_value=1M.
    // Decrease = 200K/1M = 20% > 15% → fire
    assert_eq!(result, BreakerResult::SetMode(BreakerAction::Pause),
        "cold market drain must be caught by R3-1 HWM floor");
}

// ============================================================================
// 3. TX Anchor Full Flow
// ============================================================================

#[test]
fn tx_anchor_fingerprint_write_fields_read_roundtrip() {
    let mut pda = vec![0u8; ANCHOR_SECTION_SIZE];
    let fingerprint = [0xABu8; 32];

    let pk1 = Pubkey::new_unique();
    let pk2 = Pubkey::new_unique();
    let fields = vec![(pk1, 1_000_000u64), (pk2, 500_000u64)];

    // Write fingerprint + fields
    tx_anchor::write_anchor_snapshot(&mut pda, &fingerprint, &fields);

    // Verify not first invocation (fingerprint matches)
    assert!(!tx_anchor::is_first_sandbox_invocation(&pda, &fingerprint));

    // Verify IS first with different fingerprint
    assert!(tx_anchor::is_first_sandbox_invocation(&pda, &[0xCDu8; 32]));

    // Read back
    let read = tx_anchor::read_anchor_snapshot(&pda).unwrap();
    assert_eq!(read.len(), 2);
    assert_eq!(read[0], (pk1, 1_000_000));
    assert_eq!(read[1], (pk2, 500_000));
}

#[test]
fn tx_anchor_fields_only_preserves_fingerprint() {
    let mut pda = vec![0u8; ANCHOR_SECTION_SIZE];
    let fingerprint = [0x42u8; 32];

    // Write initial snapshot
    tx_anchor::write_anchor_snapshot(
        &mut pda, &fingerprint,
        &[(Pubkey::new_unique(), 100)],
    );

    // Update fields only — fingerprint must survive
    let new_pk = Pubkey::new_unique();
    tx_anchor::write_anchor_fields_only(
        &mut pda,
        &[(new_pk, 999)],
    );

    // Fingerprint check still works
    assert!(!tx_anchor::is_first_sandbox_invocation(&pda, &fingerprint),
        "fingerprint must survive write_anchor_fields_only");

    let read = tx_anchor::read_anchor_snapshot(&pda).unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0], (new_pk, 999));
}

#[test]
fn tx_cumulative_decrease_catches_drain() {
    // Anchor value: 1M. Current: 800K. Max decrease: 15%.
    // Actual decrease: 20% → should fail.
    let result = tx_anchor::check_tx_cumulative_decrease(1_000_000, 800_000, 15);
    assert!(result.is_err(), "20% drain with 15% limit must fail");

    // Within budget: 1M → 860K = 14%
    let result = tx_anchor::check_tx_cumulative_decrease(1_000_000, 860_000, 15);
    assert!(result.is_ok(), "14% drain with 15% limit must pass");
}

#[test]
fn tx_cumulative_decrease_zero_means_no_decrease() {
    // max_pct=0: ANY decrease is rejected
    let result = tx_anchor::check_tx_cumulative_decrease(1_000_000, 999_999, 0);
    assert!(result.is_err(), "max_pct=0 must reject any decrease");

    // No decrease: OK
    let result = tx_anchor::check_tx_cumulative_decrease(1_000_000, 1_000_000, 0);
    assert!(result.is_ok(), "no decrease with max_pct=0 must pass");
}

// ============================================================================
// 4. Guard Full Lifecycle
// ============================================================================

#[test]
fn guard_lifecycle_enter_reenter_exit_clean() {
    let mut guard_data = vec![0u8; 2]; // executing(1) + depth(1)

    // Initial state: not executing, depth 0
    assert_eq!(guard_data[0], 0, "executing must be false");
    assert_eq!(guard::read_depth(&guard_data).unwrap(), 0);

    // Enter (Guard mode) — should allow, set executing + depth 1
    let action = guard::check_reentrancy(&guard_data, guard::ReentrancyMode::Guard).unwrap();
    assert_eq!(action, guard::ReentrancyAction::Normal);
    guard::set_executing(&mut guard_data).unwrap();
    guard::increment_depth(&mut guard_data).unwrap();
    assert_eq!(guard_data[0], 1, "executing must be true");
    assert_eq!(guard::read_depth(&guard_data).unwrap(), 1);

    // Re-enter (Guard mode) — should allow as InnerCall, depth 2
    let action = guard::check_reentrancy(&guard_data, guard::ReentrancyMode::Guard).unwrap();
    assert_eq!(action, guard::ReentrancyAction::InnerCall);
    guard::increment_depth(&mut guard_data).unwrap();
    assert_eq!(guard::read_depth(&guard_data).unwrap(), 2);

    // Re-enter in Reject mode — should block
    let action = guard::check_reentrancy(&guard_data, guard::ReentrancyMode::Reject).unwrap();
    assert_eq!(action, guard::ReentrancyAction::Blocked);

    // Exit inner call — depth 1
    let new_depth = guard::decrement_depth(&mut guard_data).unwrap();
    assert_eq!(new_depth, 1);

    // Exit outer call — depth 0, clear executing
    let new_depth = guard::decrement_depth(&mut guard_data).unwrap();
    assert_eq!(new_depth, 0);
    guard::clear_executing(&mut guard_data).unwrap();

    // Clean state
    assert_eq!(guard_data[0], 0, "executing must be cleared");
    assert_eq!(guard::read_depth(&guard_data).unwrap(), 0);
}

#[test]
fn guard_reject_mode_blocks_reentry() {
    let mut guard_data = vec![0u8; 2];

    // Enter
    guard::set_executing(&mut guard_data).unwrap();
    guard::increment_depth(&mut guard_data).unwrap();

    // Reject mode blocks
    let action = guard::check_reentrancy(&guard_data, guard::ReentrancyMode::Reject).unwrap();
    assert_eq!(action, guard::ReentrancyAction::Blocked);
}

// ============================================================================
// 5. Rate Limit Full Flow
// ============================================================================

#[test]
fn rate_limit_check_increment_expire_reset() {
    let mut data = vec![0u8; rate_limit::COUNTER_SIZE];
    let counter = RateLimitCounter {
        counter_id: 0,
        count: 0,
        window_start_slot: 100,
    };
    counter.write(&mut data, 0).unwrap();

    // Check: within window, count 0 < max 5 → pass
    let c = RateLimitCounter::read(&data, 0).unwrap();
    assert!(rate_limit::check_rate_limit(&c, 5, 1000, 200).is_ok());

    // Increment 5 times
    for _ in 0..5 {
        rate_limit::increment_counter(&mut data, 0, 1000, 200).unwrap();
    }
    let c = RateLimitCounter::read(&data, 0).unwrap();
    assert_eq!(c.count, 5);

    // Check: count 5 >= max 5 → REJECTED
    assert!(rate_limit::check_rate_limit(&c, 5, 1000, 200).is_err());

    // Window expires (slot 1200 > 100 + 1000 = 1100)
    let c_expired = RateLimitCounter { count: 5, ..c };
    assert!(rate_limit::check_rate_limit(&c_expired, 5, 1000, 1200).is_ok(),
        "expired window should reset");

    // Increment after expiry — resets counter
    rate_limit::increment_counter(&mut data, 0, 1000, 1200).unwrap();
    let c = RateLimitCounter::read(&data, 0).unwrap();
    assert_eq!(c.count, 1, "counter must reset to 1 after window expiry");
    assert_eq!(c.window_start_slot, 1200, "window must restart at current slot");
}

// ============================================================================
// 6. Oracle Freshness + Deviation
// ============================================================================

#[test]
fn oracle_end_to_end_freshness_and_deviation() {
    use solana_program::{clock::Epoch, system_program};

    let layout = OracleLayout {
        price_offset: 16,
        price_size: 8,
        slot_offset: 24,
        timestamp_offset: Some(32),
    };

    // Build fake oracle account data
    let mut data = vec![0u8; 256];
    let price: u64 = 50_000_000; // $50
    let slot: u64 = 995;
    let timestamp: i64 = 1_700_000_000;
    data[16..24].copy_from_slice(&price.to_le_bytes());
    data[24..32].copy_from_slice(&slot.to_le_bytes());
    data[32..40].copy_from_slice(&timestamp.to_le_bytes());

    let key = Pubkey::new_unique();
    let owner = system_program::id();
    let mut lamports = 1_000_000u64;

    let info = solana_program::account_info::AccountInfo::new(
        &key, false, false, &mut lamports, &mut data, &owner, false, Epoch::default(),
    );

    // Read oracle
    let reading = oracle::read_oracle(&info, &layout, None).unwrap();
    assert_eq!(reading.price, 50_000_000);
    assert_eq!(reading.last_slot, 995);
    assert_eq!(reading.last_timestamp, Some(1_700_000_000));

    // Freshness check: oracle at slot 995, current slot 1000, max staleness 10 → OK
    assert!(oracle::check_oracle_freshness(&info, &layout, 10, 1000, None).is_ok());

    // Freshness check: oracle at slot 995, current slot 1010, max staleness 10 → STALE
    assert!(oracle::check_oracle_freshness(&info, &layout, 10, 1010, None).is_err());

    // Deviation check: last known $50, current $50, max 200 bps → OK (0% deviation)
    assert!(oracle::check_oracle_deviation(&info, &layout, 200, 50_000_000, None).is_ok());

    // Deviation check: last known $48, current $50, max 200 bps → 4.17% = 416 bps > 200 → FAIL
    assert!(oracle::check_oracle_deviation(&info, &layout, 200, 48_000_000, None).is_err());

    // Deviation check: last known $49.5, current $50, max 200 bps → 1.01% = 101 bps < 200 → OK
    assert!(oracle::check_oracle_deviation(&info, &layout, 200, 49_500_000, None).is_ok());
}

#[test]
fn oracle_wrong_owner_rejected() {
    use solana_program::{clock::Epoch, system_program};

    let layout = OracleLayout {
        price_offset: 0,
        price_size: 8,
        slot_offset: 8,
        timestamp_offset: None,
    };

    let mut data = vec![0u8; 64];
    data[0..8].copy_from_slice(&100u64.to_le_bytes());
    data[8..16].copy_from_slice(&50u64.to_le_bytes());

    let key = Pubkey::new_unique();
    let owner = system_program::id();
    let expected = Pubkey::new_unique(); // different from actual owner
    let mut lamports = 0u64;

    let info = solana_program::account_info::AccountInfo::new(
        &key, false, false, &mut lamports, &mut data, &owner, false, Epoch::default(),
    );

    assert!(oracle::read_oracle(&info, &layout, Some(&expected)).is_err(),
        "wrong owner must be rejected");
    assert!(oracle::read_oracle(&info, &layout, Some(&owner)).is_ok(),
        "correct owner must be accepted");
}

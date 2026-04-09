use solana_program::program_error::ProgramError;

/// All sandbox error codes start at 6000 to avoid collision with Anchor (0-5999).
/// These codes are a stable API — frontends key on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SandboxError {
    // ── Mode errors (6000-6009) ──
    ProgramPaused = 6000,
    CloseOnlyMode = 6001,
    LiquidationPaused = 6002,
    EmergencyBypassActive = 6003,

    // ── Authority errors (6010-6019) ──
    UnauthorizedSigner = 6010,
    UnknownInstruction = 6011,

    // ── Oracle errors (6020-6029) ──
    OracleStale = 6020,
    OracleDeviation = 6021,

    // ── Rate limit errors (6030-6039) ──
    RateLimitExceeded = 6030,

    // ── Bound errors (6040-6049) ──
    BoundViolation = 6040,

    // ── Invariant errors (6050-6059) ──
    InvariantViolation = 6050,
    TxCumulativeDecreaseExceeded = 6051,

    // ── System errors (6060-6079) ──
    InsufficientCU = 6060,
    SandboxStateNotInitialized = 6070,
    PDACorrupted = 6071,
    SandboxStateVersionMismatch = 6072,
    SnapshotFailed = 6073,

    // ── Re-entrancy errors (6080-6089) ──
    ReentrancyDetected = 6080,

    // ── Circuit breaker errors (6090-6099) ──
    CircuitBreakerTriggered = 6090,
}

impl From<SandboxError> for ProgramError {
    fn from(e: SandboxError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl SandboxError {
    /// Returns whether this error type is retryable by the client.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ProgramPaused
                | Self::CloseOnlyMode
                | Self::LiquidationPaused
                | Self::EmergencyBypassActive
                | Self::OracleStale
                | Self::OracleDeviation
                | Self::RateLimitExceeded
                | Self::InsufficientCU
                | Self::SnapshotFailed
                | Self::CircuitBreakerTriggered
        )
    }

    /// Human-readable error message for logging.
    pub const fn message(&self) -> &'static str {
        match self {
            Self::ProgramPaused => "Program paused for safety",
            Self::CloseOnlyMode => "Only exits allowed right now",
            Self::LiquidationPaused => "Liquidations temporarily paused",
            Self::EmergencyBypassActive => "Emergency maintenance in progress",
            Self::UnauthorizedSigner => "Not authorized for this action",
            Self::UnknownInstruction => "Unrecognized instruction",
            Self::OracleStale => "Price data outdated",
            Self::OracleDeviation => "Price moving too fast",
            Self::RateLimitExceeded => "Too many requests, try again soon",
            Self::BoundViolation => "Input value out of range",
            Self::InvariantViolation => "Safety invariant violated",
            Self::TxCumulativeDecreaseExceeded => "Transaction exceeds cumulative decrease limit",
            Self::InsufficientCU => "Insufficient compute for safety checks",
            Self::SandboxStateNotInitialized => "Sandbox state not initialized",
            Self::PDACorrupted => "Sandbox state corrupted",
            Self::SandboxStateVersionMismatch => "Sandbox version mismatch",
            Self::SnapshotFailed => "Account snapshot failed",
            Self::ReentrancyDetected => "Recursive call blocked",
            Self::CircuitBreakerTriggered => "Safety limit reached",
        }
    }
}

//! Safe and bounded error definitions for canonical market types.

use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MarketTypeError {
    // --- Existing primitive errors (backwards compatibility) ---
    #[error("basis points out of range: {0}")]
    BpsOutOfRange(u16),
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("price numerator must be greater than zero")]
    ZeroPriceNumerator,
    #[error("price denominator must be greater than zero")]
    ZeroPriceDenominator,
    #[error("version must be greater than zero")]
    ZeroVersion,

    // --- Identity errors ---
    #[error("address must not be empty")]
    EmptyAddress,
    #[error("base and quote assets must be distinct")]
    SameAssetPair,
    #[error("assets or entities must belong to the same chain")]
    ChainMismatch,

    // --- Sequence errors ---
    #[error("sequence must be greater than zero")]
    ZeroSequence,
    #[error("invalid sequence range: start {start} > end {end}")]
    InvalidSequenceRange { start: u64, end: u64 },
    #[error("sequence gap detected: expected {expected}, received {received}")]
    SequenceGap { expected: u64, received: u64 },
    #[error("missing snapshot baseline: stream is uninitialized")]
    MissingBaselineSnapshot,
    #[error("stream resync required: {reason}")]
    ResyncRequired { reason: &'static str },
    #[error("target mismatch for sequenced stream")]
    TargetMismatch,

    // --- Freshness & timestamp errors ---
    #[error("timestamp must be greater than zero: {0}")]
    InvalidTimestamp(i64),
    #[error("policy staleness duration out of bounds: {0}ms")]
    PolicyStalenessOutOfRange(u64),
    #[error("policy future skew duration out of bounds: {0}ms")]
    PolicySkewOutOfRange(u64),

    // --- Normalized numbers errors ---
    #[error("price must be finite")]
    NonFinitePrice,
    #[error("price must be non-negative")]
    NegativePrice,
    #[error("price must be greater than zero")]
    ZeroPrice,
    #[error("quantity must be finite")]
    NonFiniteQuantity,
    #[error("quantity must be non-negative")]
    NegativeQuantity,
    #[error("quantity must be greater than zero")]
    ZeroQuantity,

    // --- Candle / OHLCV errors ---
    #[error("invalid candle window: open {open_ms} >= close {close_ms}")]
    InvalidCandleWindow { open_ms: i64, close_ms: i64 },
    #[error("candle window duration {duration_ms}ms exceeds maximum {max_ms}ms")]
    CandleWindowExceeded { duration_ms: u64, max_ms: u64 },
    #[error("invalid candle bounds: {reason}")]
    InvalidCandleBounds { reason: &'static str },
    #[error("invalid candle timeframe: {0}")]
    InvalidCandleTimeframe(String),

    // --- Orderbook / Depth errors ---
    #[error("depth levels count {count} exceeds maximum {max}")]
    DepthLevelsExceeded { count: usize, max: usize },
    #[error("depth levels on side '{side}' are not strictly sorted")]
    UnsortedDepthLevels { side: &'static str },
    #[error("duplicate price level on side '{side}'")]
    DuplicateDepthPriceLevel { side: &'static str },
    #[error("crossed or locked order book: best bid >= best ask")]
    CrossedOrderBook,
    #[error("empty depth levels: at least one level required")]
    EmptyDepthLevels,

    // --- Pool state errors ---
    #[error("decimals {decimals} exceeds maximum {max}")]
    DecimalsExceeded { decimals: u8, max: u8 },
    #[error("pool tokens must be distinct")]
    SamePoolTokens,
    #[error("invalid tick spacing: {0}")]
    InvalidTickSpacing(u32),
    #[error("tick index {tick} out of range [{min}, {max}]")]
    TickOutOfRange { tick: i32, min: i32, max: i32 },
    #[error("tick {tick} is not aligned with tick spacing {spacing}")]
    TickSpacingMismatch { tick: i32, spacing: u32 },
    #[error("CLMM ticks count {count} exceeds maximum {max}")]
    ClmmTicksExceeded { count: usize, max: usize },
    #[error("CLMM ticks are not strictly sorted by index")]
    UnsortedClmmTicks,
    #[error("duplicate CLMM tick index {0}")]
    DuplicateClmmTick(i32),
    #[error("invalid tick liquidity for tick {0}: |net| > gross")]
    InvalidTickLiquidity(i32),
    #[error("invalid bin step {0} bps")]
    InvalidBinStep(u16),
    #[error("bin id {bin_id} out of range [{min}, {max}]")]
    BinOutOfRange { bin_id: i32, min: i32, max: i32 },
    #[error("bin count {count} exceeds maximum {max}")]
    BinsExceeded { count: usize, max: usize },
    #[error("bins are not strictly sorted by id")]
    UnsortedBins,
    #[error("duplicate bin id {0}")]
    DuplicateBin(i32),
    #[error("bin {0} has zero reserves for both token 0 and token 1")]
    EmptyBin(i32),
    #[error("bin reserve side violation for bin {bin_id} relative to active bin {active_bin_id}")]
    BinReserveSideViolation { bin_id: i32, active_bin_id: i32 },
    #[error("pool kind mismatch: expected {expected}, received {received}")]
    PoolKindMismatch {
        expected: &'static str,
        received: &'static str,
    },

    // --- Feed boundary & mapper errors ---
    #[error("source label must not be empty")]
    EmptySourceLabel,
    #[error("source label length {len} exceeds maximum {max}")]
    SourceLabelTooLong { len: usize, max: usize },
    #[error("invalid source label: {0}")]
    InvalidSourceLabel(&'static str),
    #[error("source chain family {source_family} does not match target chain {target_chain}")]
    SourceChainFamilyMismatch {
        source_family: &'static str,
        target_chain: &'static str,
    },
    #[error("sequence overlap detected: start {start} <= current {current} < end {end}")]
    SequenceOverlap { start: u64, end: u64, current: u64 },
    #[error("stale sequence: received {sequence} <= current {current}")]
    StaleSequence { sequence: u64, current: u64 },
    #[error("duplicate sequence: {0}")]
    DuplicateSequence(u64),
    #[error("unsupported feed payload for target: {0}")]
    UnsupportedPayloadForTarget(&'static str),
    #[error("injected source error: {0}")]
    InjectedSourceError(&'static str),
    #[error("feed batch count {count} exceeds maximum {max}")]
    FeedBatchExceeded { count: usize, max: usize },

    // --- Aggregation errors ---
    #[error("arithmetic overflow during aggregation: {0}")]
    ArithmeticOverflow(&'static str),
    #[error("retained windows count {count} exceeds maximum {max}")]
    RetainedWindowsExceeded { count: usize, max: usize },
    #[error("window alignment mismatch: timestamp {timestamp_ms} does not align with window duration {duration_ms}ms")]
    WindowAlignmentMismatch { timestamp_ms: i64, duration_ms: u64 },
    #[error("candle timestamp {candle_open_ms} is stale or overlaps existing window close {current_close_ms}")]
    StaleCandleWindow {
        candle_open_ms: i64,
        current_close_ms: i64,
    },
    #[error("aggregated buckets count {count} exceeds maximum {max}")]
    AggregatedBucketsExceeded { count: usize, max: usize },

    // --- Consumer batching & backpressure errors ---
    #[error("consumer queue capacity {count} exceeds maximum {max}")]
    ConsumerQueueCapacityExceeded { count: usize, max: usize },
    #[error("consumer batch size {size} exceeds maximum {max}")]
    ConsumerBatchSizeExceeded { size: usize, max: usize },
    #[error("invalid consumer configuration: {reason}")]
    InvalidConsumerConfig { reason: &'static str },
    #[error("unacknowledged batch {batch_id} is currently in flight")]
    UnacknowledgedBatchPending { batch_id: u64 },
    #[error("invalid batch acknowledgement: expected batch {expected}, received {received}")]
    InvalidBatchAcknowledgement { expected: u64, received: u64 },
    #[error("no pending in-flight batch to acknowledge")]
    NoPendingBatchToAcknowledge,
}

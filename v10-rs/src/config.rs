//! Configuration for the V10 streaming codec

/// Magic bytes for V10 Streaming format
pub const MAGIC: &[u8] = b"V10S";

/// Format version
pub const VERSION: u8 = 1;

/// Line format types
pub const FMT_JSON: u8 = 0;
pub const FMT_TEXT: u8 = 1;

/// Chunk encoding types
pub const CHUNK_RAW: u8 = 0;
pub const CHUNK_V10_JSON: u8 = 1;
pub const CHUNK_V10_TEXT: u8 = 2;

/// JSON variable encoding types
pub const VAR_RAW: u8 = 0;
pub const VAR_DICT: u8 = 1;
pub const VAR_DELTA_INT: u8 = 2;

/// Smart column encoding types (for TEXT variable columns)
pub const COL_RAW: u8 = 0;           // Newline-separated values (no embedded newlines)
pub const COL_DICT: u8 = 1;
pub const COL_TS_CLF: u8 = 2;
pub const COL_TS_CLF_FRAG: u8 = 3;
pub const COL_TS_ISO: u8 = 4;
pub const COL_PREFIX_ID: u8 = 5;
pub const COL_NUMERIC: u8 = 6;
pub const COL_TEXT_DELTA: u8 = 7;
pub const COL_IPV4: u8 = 8;
pub const COL_PATH: u8 = 9;
pub const COL_RAW_LENPREFIX: u8 = 10; // Length-prefixed values (handles embedded newlines)
pub const COL_SPARSE: u8 = 11;        // Sparse encoding: bitmap + dense values

/// Multi-space marker for whitespace preservation
/// Use a control character (U+001E - Record Separator) that's unlikely in logs
/// and fits in a single Latin-1 byte (0x1E)
pub const MULTI_SPACE_PREFIX: char = '\x1E';

/// Configuration for the streaming codec
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    /// Lines per chunk (default 10000)
    pub chunk_size: usize,
    /// Initial chunk size for faster startup (default 1000)
    pub initial_chunk_size: usize,
    /// zstd compression level (default 3)
    pub zstd_level: i32,
    /// zstd long distance matching window log (default 27 = 128MB)
    pub zstd_window_log: u32,
    /// Maximum templates to track
    pub max_templates: usize,
    /// Maximum JSON schema keys to track
    pub max_schema_keys: usize,
    /// Maximum dictionary entries per JSON key
    pub max_dict_entries: usize,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            chunk_size: 10000,
            initial_chunk_size: 1000,
            zstd_level: 3,
            zstd_window_log: 27,
            max_templates: 10000,
            max_schema_keys: 1000,
            max_dict_entries: 50000,
        }
    }
}

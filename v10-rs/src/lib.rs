//! V10 Streaming Log Compressor - High Performance Rust Implementation
//!
//! Features:
//! - True zstd streaming compression
//! - Drain-like template mining with whitespace preservation
//! - JSON columnar encoding with schema learning
//! - Smart column encoding (timestamps, IPv4, numeric, etc.)
//! - Cross-chunk template learning
//! - Format bitmap for mixed JSON/TEXT chunks

pub mod varint;
pub mod config;
pub mod drain;
pub mod column;
pub mod json_encoder;
pub mod text_encoder;
pub mod encoder;
pub mod decoder;

// Re-export main types
pub use config::StreamingConfig;
pub use encoder::StreamingEncoder;
pub use decoder::StreamingDecoder;

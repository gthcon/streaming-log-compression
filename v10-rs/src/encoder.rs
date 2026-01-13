//! Streaming encoder for V10 format
//!
//! Full-featured V10 streaming encoder with:
//! - Format detection (JSON vs TEXT)
//! - Drain template mining with cross-chunk learning
//! - JSON columnar encoding with schema learning
//! - Smart column encoding (timestamps, IPs, etc.)
//! - Whitespace preservation for lossless roundtrip

use crate::config::{StreamingConfig, MAGIC, VERSION, FMT_JSON, FMT_TEXT, CHUNK_V10_JSON, CHUNK_V10_TEXT, CHUNK_RAW};
use crate::drain::DrainState;
use crate::text_encoder::TextChunkEncoder;
use crate::json_encoder::JsonChunkEncoder;
use crate::varint;
use std::collections::HashSet;
use std::io::{self, BufRead, Read, Write};

/// Line format detection result
#[derive(Clone, Copy, PartialEq, Debug)]
enum LineFormat {
    Json,
    Text,
}

/// Streaming encoder with full V10 features
pub struct StreamingEncoder<W: Write> {
    writer: zstd::stream::write::Encoder<'static, W>,
    config: StreamingConfig,
    drain: Option<DrainState>,  // Persistent drain for cross-chunk learning
    written_template_ids: HashSet<i32>,  // Track templates already written (for incremental writing)
    chunk_lines: Vec<(LineFormat, String)>,
    chunk_idx: usize,
    total_bytes: usize,
    has_trailing_newline: bool,
}

impl<W: Write> StreamingEncoder<W> {
    pub fn new(writer: W) -> Self {
        Self::with_config(writer, StreamingConfig::default())
    }

    pub fn with_config(writer: W, config: StreamingConfig) -> Self {
        let mut encoder = zstd::stream::write::Encoder::new(writer, config.zstd_level).unwrap();
        encoder.long_distance_matching(true).unwrap();
        encoder.window_log(config.zstd_window_log).unwrap();

        Self {
            writer: encoder,
            config: config.clone(),
            drain: Some(DrainState::new(config)),
            written_template_ids: HashSet::new(),
            chunk_lines: Vec::new(),
            chunk_idx: 0,
            total_bytes: 0,
            has_trailing_newline: true,
        }
    }

    /// Encode from a reader, processing line by line
    pub fn encode_stream<R: Read>(&mut self, reader: R) -> io::Result<usize> {
        // Write header
        self.write_header()?;

        let mut buf_reader = io::BufReader::new(reader);
        let mut line_buf = Vec::new();
        let mut last_byte_was_newline = true;

        loop {
            line_buf.clear();
            let bytes_read = buf_reader.read_until(b'\n', &mut line_buf)?;
            if bytes_read == 0 {
                break; // EOF
            }

            self.total_bytes += bytes_read;
            last_byte_was_newline = line_buf.last() == Some(&b'\n');

            // Remove trailing newline
            if line_buf.last() == Some(&b'\n') {
                line_buf.pop();
            }

            // Convert bytes to string using Latin-1 (ISO-8859-1) encoding
            // This preserves all bytes 0x00-0xFF as Unicode codepoints U+0000-U+00FF
            let line: String = line_buf.iter().map(|&b| b as char).collect();
            self.add_line(line)?;
        }

        self.has_trailing_newline = last_byte_was_newline;

        // Flush remaining
        if !self.chunk_lines.is_empty() {
            self.flush_chunk()?;
        }

        // Write end marker: chunk_type=0, chunk_len=0
        self.writer.write_all(&[0])?;  // chunk_type = 0 (end marker)
        varint::write_varint(&mut self.writer, 0)?;  // chunk_len = 0

        // Write trailing newline flag
        self.writer.write_all(&[if self.has_trailing_newline { 1 } else { 0 }])?;

        Ok(self.total_bytes)
    }

    fn write_header(&mut self) -> io::Result<()> {
        self.writer.write_all(MAGIC)?;
        self.writer.write_all(&[VERSION])?;

        // Write config
        varint::write_varint(&mut self.writer, self.config.chunk_size as u64)?;
        varint::write_varint(&mut self.writer, self.config.initial_chunk_size as u64)?;

        // Write compression parameters (for decoder reference)
        self.writer.write_all(&[self.config.zstd_level as u8])?;
        self.writer.write_all(&[self.config.zstd_window_log as u8])?;

        Ok(())
    }

    fn detect_format(line: &str) -> LineFormat {
        // Check if line starts with '{' (possibly with leading whitespace)
        let trimmed = line.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            // Check for unicode escapes which we can't preserve losslessly
            // JSON columnar encoding normalizes \uXXXX to UTF-8 bytes
            if trimmed.contains("\\u") {
                return LineFormat::Text;
            }
            // Verify it's valid JSON
            if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
                return LineFormat::Json;
            }
        }
        LineFormat::Text
    }

    fn add_line(&mut self, line: String) -> io::Result<()> {
        let format = Self::detect_format(&line);
        self.chunk_lines.push((format, line));

        let chunk_size = if self.chunk_idx == 0 {
            self.config.initial_chunk_size
        } else {
            self.config.chunk_size
        };

        if self.chunk_lines.len() >= chunk_size {
            self.flush_chunk()?;
        }

        Ok(())
    }

    fn flush_chunk(&mut self) -> io::Result<()> {
        if self.chunk_lines.is_empty() {
            return Ok(());
        }

        // Count formats
        let json_count = self.chunk_lines.iter().filter(|(f, _)| *f == LineFormat::Json).count();
        let text_count = self.chunk_lines.len() - json_count;

        // Decide encoding strategy
        let (chunk_type, chunk_data) = if json_count > 0 && text_count > 0 {
            // Mixed format - encode with format bitmap
            self.encode_mixed_chunk()?
        } else if json_count > text_count {
            // All JSON
            (CHUNK_V10_JSON, self.encode_json_chunk()?)
        } else {
            // All TEXT
            (CHUNK_V10_TEXT, self.encode_text_chunk()?)
        };

        // Write chunk type
        self.writer.write_all(&[chunk_type])?;

        // Write chunk length
        varint::write_varint(&mut self.writer, chunk_data.len() as u64)?;

        // Write chunk data
        self.writer.write_all(&chunk_data)?;

        self.chunk_lines.clear();
        self.chunk_idx += 1;

        Ok(())
    }

    fn encode_json_chunk(&mut self) -> io::Result<Vec<u8>> {
        let mut encoder = JsonChunkEncoder::new(self.config.clone());

        for (_, line) in &self.chunk_lines {
            encoder.add_line(line);
        }

        Ok(encoder.encode())
    }

    fn encode_text_chunk(&mut self) -> io::Result<Vec<u8>> {
        // Take drain and written_template_ids for cross-chunk learning
        let drain = self.drain.take().unwrap_or_else(|| DrainState::new(self.config.clone()));
        let written_ids = std::mem::take(&mut self.written_template_ids);
        let mut encoder = TextChunkEncoder::with_drain_and_written(drain, written_ids, self.config.clone());

        for (_, line) in &self.chunk_lines {
            encoder.add_line(line);
        }

        let data = encoder.encode();

        // Return drain and updated written_template_ids for next chunk
        self.drain = Some(encoder.drain.clone());
        self.written_template_ids = encoder.written_template_ids.clone();

        Ok(data)
    }

    fn encode_mixed_chunk(&mut self) -> io::Result<(u8, Vec<u8>)> {
        let mut output = Vec::new();

        // Write format bitmap (run-length encoded)
        let mut rle: Vec<(LineFormat, usize)> = Vec::new();
        for (format, _) in &self.chunk_lines {
            if let Some(last) = rle.last_mut() {
                if last.0 == *format {
                    last.1 += 1;
                    continue;
                }
            }
            rle.push((*format, 1));
        }

        varint::write_varint(&mut output, rle.len() as u64)?;
        for (format, count) in &rle {
            let format_byte = if *format == LineFormat::Json { FMT_JSON } else { FMT_TEXT };
            output.push(format_byte);
            varint::write_varint(&mut output, *count as u64)?;
        }

        // Separate lines by format
        let json_lines: Vec<_> = self.chunk_lines.iter()
            .filter(|(f, _)| *f == LineFormat::Json)
            .map(|(_, l)| l.as_str())
            .collect();

        let text_lines: Vec<_> = self.chunk_lines.iter()
            .filter(|(f, _)| *f == LineFormat::Text)
            .map(|(_, l)| l.as_str())
            .collect();

        // Encode JSON section
        if !json_lines.is_empty() {
            let mut json_encoder = JsonChunkEncoder::new(self.config.clone());
            for line in &json_lines {
                json_encoder.add_line(line);
            }
            let json_data = json_encoder.encode();
            varint::write_varint(&mut output, json_data.len() as u64)?;
            output.extend_from_slice(&json_data);
        } else {
            varint::write_varint(&mut output, 0u64)?;
        }

        // Encode TEXT section
        if !text_lines.is_empty() {
            let drain = self.drain.take().unwrap_or_else(|| DrainState::new(self.config.clone()));
            let written_ids = std::mem::take(&mut self.written_template_ids);
            let mut text_encoder = TextChunkEncoder::with_drain_and_written(drain, written_ids, self.config.clone());
            for line in &text_lines {
                text_encoder.add_line(line);
            }
            let text_data = text_encoder.encode();
            self.drain = Some(text_encoder.drain.clone());
            self.written_template_ids = text_encoder.written_template_ids.clone();

            varint::write_varint(&mut output, text_data.len() as u64)?;
            output.extend_from_slice(&text_data);
        } else {
            varint::write_varint(&mut output, 0u64)?;
        }

        Ok((CHUNK_RAW, output)) // Use CHUNK_RAW to indicate mixed format
    }

    pub fn finish(self) -> io::Result<W> {
        self.writer.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_basic() {
        let input = "Error at line 123\nError at line 456\nWarning: test\n";
        let mut output = Vec::new();

        {
            let mut encoder = StreamingEncoder::new(&mut output);
            encoder.encode_stream(input.as_bytes()).unwrap();
            encoder.finish().unwrap();
        }

        assert!(!output.is_empty());
    }

    #[test]
    fn test_format_detection() {
        assert_eq!(StreamingEncoder::<Vec<u8>>::detect_format(r#"{"key": "value"}"#), LineFormat::Json);
        assert_eq!(StreamingEncoder::<Vec<u8>>::detect_format("Error at line 123"), LineFormat::Text);
        assert_eq!(StreamingEncoder::<Vec<u8>>::detect_format("  { partial json"), LineFormat::Text);
    }

    #[test]
    fn test_encode_json() {
        let input = r#"{"level":"INFO","msg":"Hello"}
{"level":"WARN","msg":"World"}
"#;
        let mut output = Vec::new();

        {
            let mut encoder = StreamingEncoder::new(&mut output);
            encoder.encode_stream(input.as_bytes()).unwrap();
            encoder.finish().unwrap();
        }

        assert!(!output.is_empty());
    }
}

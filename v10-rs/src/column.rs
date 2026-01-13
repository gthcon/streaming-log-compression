//! Smart column encoding for variable values
//!
//! Supports multiple encoding strategies:
//! - Raw: Simple length-prefixed strings
//! - Dictionary: Bit-packed indices into unique values
//! - CLF Timestamp: Delta-encoded timestamps
//! - Prefix-ID: Delta-encoded numeric suffixes (e.g., blk-123)
//! - Numeric: Delta-encoded integers
//! - Text-Delta: V4-style text delta with R prefix fallback

use crate::config::*;
use crate::varint;
use std::collections::HashMap;
use std::io::{self, Write};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref CLF_TIMESTAMP_RE: Regex = Regex::new(
        r"^\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]?$"
    ).unwrap();

    // ISO 8601 timestamp: 2023-10-15T14:30:00Z or 2023-10-15T14:30:00.123Z or with offset
    static ref ISO_TIMESTAMP_RE: Regex = Regex::new(
        r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-]\d{2}):?(\d{2}))?$"
    ).unwrap();

    static ref PREFIX_ID_RE: Regex = Regex::new(
        r#"^"?([a-zA-Z][a-zA-Z0-9]*)[-_](-?\d+)"?,?$"#
    ).unwrap();

    static ref NUMERIC_RE: Regex = Regex::new(r"^-?\d+$").unwrap();

    static ref IPV4_RE: Regex = Regex::new(
        r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    ).unwrap();

    // URL path pattern: starts with /, contains word chars, dots, dashes, slashes
    static ref URL_PATH_RE: Regex = Regex::new(r"^/[\w./-]*$").unwrap();
}

const MONTHS: &[(&str, u32)] = &[
    ("Jan", 1), ("Feb", 2), ("Mar", 3), ("Apr", 4), ("May", 5), ("Jun", 6),
    ("Jul", 7), ("Aug", 8), ("Sep", 9), ("Oct", 10), ("Nov", 11), ("Dec", 12),
];

fn month_to_num(name: &str) -> u32 {
    MONTHS.iter().find(|(n, _)| *n == name).map(|(_, v)| *v).unwrap_or(1)
}

fn num_to_month(num: u32) -> &'static str {
    MONTHS.iter().find(|(_, v)| *v == num).map(|(n, _)| *n).unwrap_or("Jan")
}

/// Analyze column and determine best encoding type
pub fn analyze_column(values: &[&str]) -> (ColumnType, f64) {
    let present: Vec<_> = values.iter().filter(|v| !v.is_empty()).collect();
    if present.is_empty() {
        return (ColumnType::Raw, 1.0);
    }

    let n = present.len();
    let threshold = 0.9;

    // Check if there are empty strings - specialized encodings can't handle them
    // because they'd be decoded as default values (0, 0.0.0.0, etc.)
    let has_empty = values.iter().any(|v| v.is_empty());

    // Skip specialized encodings if there are empty strings
    if !has_empty {
        // Check for CLF timestamp fragments
        let clf_frag_count = present.iter().filter(|v| {
            v.starts_with('[') && !v.ends_with(']') && parse_clf_timestamp(&format!("{}]", v)).is_some()
        }).count();
        if clf_frag_count >= (n as f64 * threshold) as usize {
            return (ColumnType::TimestampClfFragment, clf_frag_count as f64 / n as f64);
        }

        // Check for full CLF timestamps
        let clf_count = present.iter().filter(|v| parse_clf_timestamp(v).is_some()).count();
        if clf_count >= (n as f64 * threshold) as usize {
            return (ColumnType::TimestampClf, clf_count as f64 / n as f64);
        }

        // Check for prefix-ID pattern
        // Only use if ALL numbers fit in i64 range (no lossy encoding)
        let prefix_captures: Vec<_> = present.iter()
            .filter_map(|v| PREFIX_ID_RE.captures(v))
            .collect();
        let all_parseable = prefix_captures.iter()
            .all(|c| c.get(2).unwrap().as_str().parse::<i64>().is_ok());
        if all_parseable && prefix_captures.len() >= (n as f64 * threshold) as usize {
            let prefixes: std::collections::HashSet<_> = prefix_captures.iter()
                .map(|c| c.get(1).unwrap().as_str().to_string())
                .collect();
            if prefixes.len() == 1 {
                return (ColumnType::PrefixId, prefix_captures.len() as f64 / n as f64);
            }
        }

        // Check for ISO timestamps
        let iso_count = present.iter().filter(|v| ISO_TIMESTAMP_RE.is_match(v)).count();
        if iso_count >= (n as f64 * threshold) as usize {
            return (ColumnType::TimestampIso, iso_count as f64 / n as f64);
        }

        // Check for IPv4 addresses
        let ipv4_count = present.iter().filter(|v| {
            if let Some(caps) = IPV4_RE.captures(v) {
                // Validate octets are 0-255
                (1..=4).all(|i| {
                    caps.get(i)
                        .and_then(|m| m.as_str().parse::<u16>().ok())
                        .map(|n| n <= 255)
                        .unwrap_or(false)
                })
            } else {
                false
            }
        }).count();
        if ipv4_count >= (n as f64 * threshold) as usize {
            return (ColumnType::IPv4, ipv4_count as f64 / n as f64);
        }

        // Check for numeric strings (including those with STRING_TYPE_MARKER prefix from JSON)
        let numeric_count = present.iter().filter(|v| {
            let s = if v.starts_with('\x01') { &v[1..] } else { *v };
            NUMERIC_RE.is_match(s) && !(s.starts_with('0') && s.len() > 1 && !s.starts_with("0-"))
        }).count();
        if numeric_count >= (n as f64 * threshold) as usize {
            return (ColumnType::Numeric, numeric_count as f64 / n as f64);
        }

        // Check for URL paths (e.g., /mnt/hadoop/dfs/data/...)
        // Only use if ALL paths can be encoded losslessly (no consecutive slashes)
        let all_valid_paths = present.iter().all(|v| {
            URL_PATH_RE.is_match(v) && !v.contains("//")
        });
        if all_valid_paths && present.len() == values.len() {
            return (ColumnType::Path, 1.0);
        }
    }

    // Check for low cardinality (dictionary encoding)
    let unique: std::collections::HashSet<_> = values.iter().collect();
    if unique.len() <= 256 {
        return (ColumnType::Dictionary, 1.0);
    }

    (ColumnType::Raw, 1.0)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ColumnType {
    Raw,
    Dictionary,
    TimestampClf,
    TimestampClfFragment,
    TimestampIso,
    PrefixId,
    Numeric,
    IPv4,
    Path,
}

/// Parse CLF timestamp to seconds since epoch
fn parse_clf_timestamp(s: &str) -> Option<(i64, ClfFormat)> {
    let caps = CLF_TIMESTAMP_RE.captures(s)?;

    let day: u32 = caps.get(1)?.as_str().parse().ok()?;
    let month = month_to_num(caps.get(2)?.as_str());
    let year: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(5)?.as_str().parse().ok()?;
    let second: u32 = caps.get(6)?.as_str().parse().ok()?;
    let tz = caps.get(7).map(|m| m.as_str().to_string()).unwrap_or_default();

    // Calculate seconds since epoch
    let mut days: i64 = 0;
    for y in 1970..year {
        let is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        days += if is_leap { 366 } else { 365 };
    }

    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    for m in 0..(month - 1) as usize {
        days += days_in_month[m] as i64;
        if m == 1 && is_leap {
            days += 1;
        }
    }
    days += (day - 1) as i64;

    let seconds = days * 86400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64;

    let format = ClfFormat {
        tz,
        has_brackets: s.starts_with('['),
        has_close: s.ends_with(']'),
    };

    Some((seconds, format))
}

/// Reconstruct CLF timestamp from seconds
fn reconstruct_clf_timestamp(seconds: i64, format: &ClfFormat) -> String {
    let mut days = seconds / 86400;
    let rem = seconds % 86400;
    let h = rem / 3600;
    let rem = rem % 3600;
    let mi = rem / 60;
    let s = rem % 60;

    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let mut month = 1u32;
    for m in 0..12 {
        let mut dim = days_in_month[m] as i64;
        if m == 1 && is_leap {
            dim = 29;
        }
        if days < dim {
            month = (m + 1) as u32;
            break;
        }
        days -= dim;
    }

    let day = days + 1;
    let month_name = num_to_month(month);

    let mut result = format!("{:02}/{}/{:04}:{:02}:{:02}:{:02}", day, month_name, year, h, mi, s);

    if !format.tz.is_empty() {
        result = format!("{} {}", result, format.tz);
    }

    if format.has_brackets {
        result = format!("[{}", result);
    }
    if format.has_close {
        result = format!("{}]", result);
    }

    result
}

/// Reconstruct CLF fragment (no closing bracket)
fn reconstruct_clf_fragment(seconds: i64) -> String {
    let mut days = seconds / 86400;
    let rem = seconds % 86400;
    let h = rem / 3600;
    let rem = rem % 3600;
    let mi = rem / 60;
    let s = rem % 60;

    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let mut month = 1u32;
    for m in 0..12 {
        let mut dim = days_in_month[m] as i64;
        if m == 1 && is_leap {
            dim = 29;
        }
        if days < dim {
            month = (m + 1) as u32;
            break;
        }
        days -= dim;
    }

    let day = days + 1;
    let month_name = num_to_month(month);

    format!("[{:02}/{}/{:04}:{:02}:{:02}:{:02}", day, month_name, year, h, mi, s)
}

#[derive(Clone, Debug, Default)]
struct ClfFormat {
    tz: String,
    has_brackets: bool,
    has_close: bool,
}

/// Escape a raw value for text-delta encoding
/// Escapes backslash first, then newline, to handle strings containing literal backslash-n
fn escape_raw(v: &str) -> String {
    v.replace('\\', "\\\\").replace('\n', "\\n")
}

/// Unescape a raw value from text-delta encoding
/// Must unescape in reverse order: backslash first (to avoid double-unescaping), then newline
fn unescape_raw(v: &str) -> String {
    v.replace("\\\\", "\x00").replace("\\n", "\n").replace('\x00', "\\")
}

/// Convert string to bytes using Latin-1 encoding (char U+00XX -> byte 0xXX)
fn string_to_latin1_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}

/// Convert bytes to string using Latin-1 encoding (byte 0xXX -> char U+00XX)
fn latin1_bytes_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Encode a column using the best encoding strategy
pub fn encode_smart_column<W: Write>(writer: &mut W, values: &[&str], n_rows: usize) -> io::Result<()> {
    if values.is_empty() {
        writer.write_all(&[COL_RAW])?;
        varint::write_varint(writer, 0)?;
        return Ok(());
    }

    // Check for sparse column (>50% absent values)
    // Only use for JSON where ABSENT_MARKER "_ABSENT_" is used
    // Don't use for text columns (they use empty strings which mean something different)
    let absent_count = values.iter().filter(|v| **v == "_ABSENT_").count();
    let sparsity = absent_count as f64 / values.len() as f64;

    if sparsity > 0.5 && values.len() > 10 {
        // Use sparse encoding
        return encode_sparse_column(writer, values);
    }

    let (col_type, match_ratio) = analyze_column(values);
    let use_text_delta = match_ratio < 1.0;

    match col_type {
        ColumnType::TimestampClfFragment => {
            if use_text_delta {
                writer.write_all(&[COL_TEXT_DELTA, COL_TS_CLF_FRAG])?;
                encode_timestamp_fragment_text_delta(writer, values)?;
            } else {
                writer.write_all(&[COL_TS_CLF_FRAG])?;
                encode_timestamp_fragment_column(writer, values)?;
            }
        }
        ColumnType::TimestampClf => {
            if use_text_delta {
                writer.write_all(&[COL_TEXT_DELTA, COL_TS_CLF])?;
                encode_timestamp_clf_text_delta(writer, values)?;
            } else {
                writer.write_all(&[COL_TS_CLF])?;
                encode_timestamp_clf_column(writer, values)?;
            }
        }
        ColumnType::PrefixId => {
            if use_text_delta {
                writer.write_all(&[COL_TEXT_DELTA, COL_PREFIX_ID])?;
                encode_prefix_id_text_delta(writer, values)?;
            } else {
                writer.write_all(&[COL_PREFIX_ID])?;
                encode_prefix_id_column(writer, values)?;
            }
        }
        ColumnType::TimestampIso => {
            if use_text_delta {
                writer.write_all(&[COL_TEXT_DELTA, COL_TS_ISO])?;
                encode_iso_timestamp_text_delta(writer, values)?;
            } else {
                writer.write_all(&[COL_TS_ISO])?;
                encode_iso_timestamp_column(writer, values)?;
            }
        }
        ColumnType::IPv4 => {
            if use_text_delta {
                writer.write_all(&[COL_TEXT_DELTA, COL_IPV4])?;
                encode_ipv4_text_delta(writer, values)?;
            } else {
                writer.write_all(&[COL_IPV4])?;
                encode_ipv4_column(writer, values)?;
            }
        }
        ColumnType::Numeric => {
            if use_text_delta {
                writer.write_all(&[COL_TEXT_DELTA, COL_NUMERIC])?;
                encode_numeric_text_delta(writer, values)?;
            } else {
                writer.write_all(&[COL_NUMERIC])?;
                encode_numeric_column(writer, values)?;
            }
        }
        ColumnType::Path => {
            // Path encoding doesn't support text-delta mode currently
            writer.write_all(&[COL_PATH])?;
            encode_path_column(writer, values)?;
        }
        ColumnType::Dictionary => {
            writer.write_all(&[COL_DICT])?;
            encode_dict_column(writer, values)?;
        }
        ColumnType::Raw => {
            // Check if any value contains a newline (needs length-prefixed format)
            let has_newlines = values.iter().any(|v| v.contains('\n'));

            if has_newlines {
                // Use length-prefixed format for values with embedded newlines
                writer.write_all(&[COL_RAW_LENPREFIX])?;
                varint::write_varint(writer, values.len() as u64)?;
                for val in values {
                    let bytes: Vec<u8> = val.chars().map(|c| c as u8).collect();
                    varint::write_varint(writer, bytes.len() as u64)?;
                    writer.write_all(&bytes)?;
                }
            } else {
                // Use newline-separated format for values without newlines (more efficient)
                writer.write_all(&[COL_RAW])?;
                let col_data = values.join("\n");
                let bytes: Vec<u8> = col_data.chars().map(|c| c as u8).collect();
                varint::write_varint(writer, bytes.len() as u64)?;
                writer.write_all(&bytes)?;
            }
        }
    }

    Ok(())
}

/// Encode a sparse column: bitmap of present values + dense values
fn encode_sparse_column<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    writer.write_all(&[COL_SPARSE])?;

    // Build list of (index, value) for non-empty/non-absent values
    let present: Vec<(usize, &str)> = values.iter()
        .enumerate()
        .filter(|(_, v)| !v.is_empty() && **v != "_ABSENT_")
        .map(|(i, v)| (i, *v))
        .collect();

    // Write total row count and present count
    varint::write_varint(writer, values.len() as u64)?;
    varint::write_varint(writer, present.len() as u64)?;

    // Write indices of present values (delta-encoded)
    let mut prev_idx = 0usize;
    for (idx, _) in &present {
        varint::write_varint(writer, (*idx - prev_idx) as u64)?;
        prev_idx = *idx;
    }

    // Extract just the present values and encode them recursively
    let present_values: Vec<&str> = present.iter().map(|(_, v)| *v).collect();

    if present_values.is_empty() {
        // All values are absent - write empty marker
        varint::write_varint(writer, 0)?;
    } else {
        // Encode the dense present values using smart encoding
        let mut dense_buf = Vec::new();
        encode_smart_column(&mut dense_buf, &present_values, present_values.len())?;
        varint::write_varint(writer, dense_buf.len() as u64)?;
        writer.write_all(&dense_buf)?;
    }

    Ok(())
}

fn encode_timestamp_fragment_column<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let ts_values: Vec<i64> = values.iter().map(|v| {
        if v.starts_with('[') {
            parse_clf_timestamp(&format!("{}]", v)).map(|(s, _)| s).unwrap_or(0)
        } else {
            0
        }
    }).collect();

    let min_val = *ts_values.iter().min().unwrap_or(&0);
    varint::write_varint(writer, min_val as u64)?;

    for val in ts_values {
        varint::write_varint(writer, (val - min_val) as u64)?;
    }

    Ok(())
}

fn encode_timestamp_clf_column<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let parsed: Vec<_> = values.iter().map(|v| {
        parse_clf_timestamp(v).unwrap_or((0, ClfFormat::default()))
    }).collect();

    let min_val = parsed.iter().map(|(s, _)| *s).min().unwrap_or(0);
    varint::write_varint(writer, min_val as u64)?;

    for (val, _) in &parsed {
        varint::write_varint(writer, (*val - min_val) as u64)?;
    }

    // Write common format as JSON
    let default_fmt = ClfFormat::default();
    let format = parsed.first().map(|(_, f)| f).unwrap_or(&default_fmt);
    let format_json = format!(
        r#"{{"tz":"{}","has_brackets":{},"has_close":{}}}"#,
        format.tz, format.has_brackets, format.has_close
    );
    let format_bytes = format_json.as_bytes();
    varint::write_varint(writer, format_bytes.len() as u64)?;
    writer.write_all(format_bytes)?;

    Ok(())
}

fn encode_prefix_id_column<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let mut prefix = String::new();
    let mut separator = b'-';  // Default separator
    let mut numbers: Vec<i64> = Vec::new();

    for v in values {
        if let Some(caps) = PREFIX_ID_RE.captures(v) {
            if prefix.is_empty() {
                prefix = caps.get(1).unwrap().as_str().to_string();
                // Detect separator: check what comes after the prefix
                let prefix_end = caps.get(1).unwrap().end();
                if prefix_end < v.len() {
                    let sep_char = v.as_bytes()[prefix_end];
                    if sep_char == b'_' || sep_char == b'-' {
                        separator = sep_char;
                    }
                }
            }
            numbers.push(caps.get(2).unwrap().as_str().parse().unwrap_or(0));
        } else {
            numbers.push(0);
        }
    }

    let prefix_bytes = prefix.as_bytes();
    varint::write_varint(writer, prefix_bytes.len() as u64)?;
    writer.write_all(prefix_bytes)?;

    // Write separator character
    writer.write_all(&[separator])?;

    let mut prev = 0i64;
    for n in numbers {
        varint::write_signed(writer, n - prev)?;
        prev = n;
    }

    Ok(())
}

fn encode_numeric_column<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    // Check if values have STRING_TYPE_MARKER prefix (from JSON string fields)
    let has_marker = values.iter().any(|v| v.starts_with('\x01'));
    writer.write_all(&[if has_marker { 1 } else { 0 }])?;

    let mut prev = 0i64;
    for v in values {
        let s = if v.starts_with('\x01') { &v[1..] } else { *v };
        let val: i64 = s.parse().unwrap_or(0);
        varint::write_signed(writer, val - prev)?;
        prev = val;
    }
    Ok(())
}

/// Parse IPv4 to u32
fn parse_ipv4(s: &str) -> Option<u32> {
    let caps = IPV4_RE.captures(s)?;
    let a: u8 = caps.get(1)?.as_str().parse().ok()?;
    let b: u8 = caps.get(2)?.as_str().parse().ok()?;
    let c: u8 = caps.get(3)?.as_str().parse().ok()?;
    let d: u8 = caps.get(4)?.as_str().parse().ok()?;
    Some(((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32))
}

/// Reconstruct IPv4 from u32
fn reconstruct_ipv4(val: u32) -> String {
    format!("{}.{}.{}.{}",
        (val >> 24) & 0xFF,
        (val >> 16) & 0xFF,
        (val >> 8) & 0xFF,
        val & 0xFF
    )
}

fn encode_ipv4_column<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let parsed: Vec<u32> = values.iter()
        .map(|v| parse_ipv4(v).unwrap_or(0))
        .collect();

    let min_val = *parsed.iter().min().unwrap_or(&0);
    varint::write_varint(writer, min_val as u64)?;

    for val in &parsed {
        varint::write_varint(writer, (*val - min_val) as u64)?;
    }
    Ok(())
}

fn encode_ipv4_text_delta<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let mut deltas = Vec::new();
    let mut prev = 0u32;

    for v in values {
        if let Some(ip) = parse_ipv4(v) {
            // Use signed delta since IPs can go down
            let delta = (ip as i64) - (prev as i64);
            deltas.push(delta.to_string());
            prev = ip;
        } else {
            deltas.push(format!("R{}", escape_raw(v)));
        }
    }

    let delta_text = deltas.join("\n");
    let delta_bytes = string_to_latin1_bytes(&delta_text);
    varint::write_varint(writer, delta_bytes.len() as u64)?;
    writer.write_all(&delta_bytes)?;

    Ok(())
}

/// Encode a column of URL paths by splitting into segments
/// Each path segment becomes a separate dictionary-encoded column
fn encode_path_column<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let n_rows = values.len();
    let mut split_paths: Vec<Vec<&str>> = Vec::new();
    let mut has_trailing_slash: Vec<bool> = Vec::new();
    let mut max_segments = 0;

    for v in values {
        if v.starts_with('/') {
            has_trailing_slash.push(v.ends_with('/'));
            let segments: Vec<&str> = v.split('/').collect();
            // If trailing slash, remove the empty last segment (we track it separately)
            let segments = if segments.last() == Some(&"") && segments.len() > 1 {
                &segments[..segments.len() - 1]
            } else {
                &segments[..]
            };
            max_segments = max_segments.max(segments.len());
            split_paths.push(segments.to_vec());
        } else {
            has_trailing_slash.push(false);
            split_paths.push(vec![v]);
        }
    }

    // Write max segments count
    varint::write_varint(writer, max_segments as u64)?;

    // Encode each segment position as a dictionary column
    for seg_idx in 0..max_segments {
        let col: Vec<&str> = split_paths.iter()
            .map(|p| p.get(seg_idx).copied().unwrap_or(""))
            .collect();
        encode_dict_column(writer, &col)?;
    }

    // Encode trailing slash flags as bitstream
    let packed = pack_bits(
        &has_trailing_slash.iter().map(|&b| if b { 1u32 } else { 0u32 }).collect::<Vec<_>>(),
        1
    );
    varint::write_varint(writer, packed.len() as u64)?;
    writer.write_all(&packed)?;

    Ok(())
}

/// Parse ISO timestamp to nanoseconds since epoch
fn parse_iso_timestamp(s: &str) -> Option<(i64, IsoFormat)> {
    let caps = ISO_TIMESTAMP_RE.captures(s)?;

    let year: u32 = caps.get(1)?.as_str().parse().ok()?;
    let month: u32 = caps.get(2)?.as_str().parse().ok()?;
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hour: u32 = caps.get(4)?.as_str().parse().ok()?;
    let minute: u32 = caps.get(5)?.as_str().parse().ok()?;
    let second: u32 = caps.get(6)?.as_str().parse().ok()?;

    let subsec_str = caps.get(7).map(|m| m.as_str()).unwrap_or("");
    let subsec_nanos: u32 = if !subsec_str.is_empty() {
        // Pad to 9 digits
        let padded = format!("{:0<9}", subsec_str);
        padded[..9].parse().unwrap_or(0)
    } else {
        0
    };

    // Calculate seconds since epoch
    let mut days: i64 = 0;
    for y in 1970..year {
        let is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        days += if is_leap { 366 } else { 365 };
    }

    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    for m in 0..(month - 1) as usize {
        days += days_in_month[m] as i64;
        if m == 1 && is_leap {
            days += 1;
        }
    }
    days += (day - 1) as i64;

    let seconds = days * 86400 + (hour as i64) * 3600 + (minute as i64) * 60 + second as i64;
    let nanos = seconds * 1_000_000_000 + subsec_nanos as i64;

    let format = IsoFormat {
        has_t: s.contains('T'),
        subsec_len: subsec_str.len() as u8,
        tz_offset: caps.get(8).map(|m| m.as_str().to_string()),
        tz_minutes: caps.get(9).map(|m| m.as_str().to_string()),
    };

    Some((nanos, format))
}

/// Reconstruct ISO timestamp from nanoseconds
fn reconstruct_iso_timestamp(nanos: i64, format: &IsoFormat) -> String {
    let seconds = nanos / 1_000_000_000;
    let subsec = (nanos % 1_000_000_000) as u32;

    let mut days = seconds / 86400;
    let rem = seconds % 86400;
    let h = rem / 3600;
    let rem = rem % 3600;
    let mi = rem / 60;
    let s = rem % 60;

    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let mut month = 1u32;
    for m in 0..12 {
        let mut dim = days_in_month[m] as i64;
        if m == 1 && is_leap {
            dim = 29;
        }
        if days < dim {
            month = (m + 1) as u32;
            break;
        }
        days -= dim;
    }

    let day = days + 1;
    let sep = if format.has_t { 'T' } else { ' ' };

    let mut result = format!("{:04}-{:02}-{:02}{}{:02}:{:02}:{:02}", year, month, day, sep, h, mi, s);

    if format.subsec_len > 0 {
        let subsec_str = format!("{:09}", subsec);
        result = format!("{}.{}", result, &subsec_str[..format.subsec_len as usize]);
    }

    if let Some(ref tz_h) = format.tz_offset {
        if let Some(ref tz_m) = format.tz_minutes {
            result = format!("{}{}:{}", result, tz_h, tz_m);
        } else {
            result = format!("{}{}:00", result, tz_h);
        }
    } else {
        result = format!("{}Z", result);
    }

    result
}

#[derive(Clone, Debug, Default)]
struct IsoFormat {
    has_t: bool,
    subsec_len: u8,
    tz_offset: Option<String>,
    tz_minutes: Option<String>,
}

fn encode_iso_timestamp_column<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let parsed: Vec<_> = values.iter().map(|v| {
        parse_iso_timestamp(v).unwrap_or((0, IsoFormat::default()))
    }).collect();

    let min_val = parsed.iter().map(|(s, _)| *s).min().unwrap_or(0);
    varint::write_varint(writer, min_val as u64)?;

    for (val, _) in &parsed {
        varint::write_varint(writer, (*val - min_val) as u64)?;
    }

    // Write common format
    let default_fmt = IsoFormat::default();
    let format = parsed.first().map(|(_, f)| f).unwrap_or(&default_fmt);
    writer.write_all(&[if format.has_t { 1 } else { 0 }])?;
    writer.write_all(&[format.subsec_len])?;

    let tz_str = if let Some(ref h) = format.tz_offset {
        if let Some(ref m) = format.tz_minutes {
            format!("{}:{}", h, m)
        } else {
            format!("{}:00", h)
        }
    } else {
        "Z".to_string()
    };
    let tz_bytes = tz_str.as_bytes();
    varint::write_varint(writer, tz_bytes.len() as u64)?;
    writer.write_all(tz_bytes)?;

    Ok(())
}

fn encode_iso_timestamp_text_delta<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    // Similar to CLF text-delta encoding
    let mut format_set: std::collections::HashSet<(bool, u8, String)> = std::collections::HashSet::new();
    let mut parsed: Vec<Option<(i64, (bool, u8, String))>> = Vec::new();

    for v in values {
        if let Some((ts, fmt)) = parse_iso_timestamp(v) {
            let tz = if let Some(ref h) = fmt.tz_offset {
                if let Some(ref m) = fmt.tz_minutes {
                    format!("{}:{}", h, m)
                } else {
                    format!("{}:00", h)
                }
            } else {
                "Z".to_string()
            };
            let fmt_key = (fmt.has_t, fmt.subsec_len, tz);
            format_set.insert(fmt_key.clone());
            parsed.push(Some((ts, fmt_key)));
        } else {
            parsed.push(None);
        }
    }

    // Write format dictionary
    let format_list: Vec<_> = format_set.into_iter().collect();
    let fmt_to_id: HashMap<_, _> = format_list.iter().enumerate().map(|(i, f)| (f.clone(), i)).collect();

    varint::write_varint(writer, format_list.len() as u64)?;
    for (has_t, subsec_len, tz) in &format_list {
        writer.write_all(&[if *has_t { 1 } else { 0 }])?;
        writer.write_all(&[*subsec_len])?;
        let tz_bytes = tz.as_bytes();
        varint::write_varint(writer, tz_bytes.len() as u64)?;
        writer.write_all(tz_bytes)?;
    }

    // Write deltas and format indices
    let mut deltas = Vec::new();
    let mut fmt_indices = Vec::new();
    let mut prev = 0i64;

    for (i, p) in parsed.iter().enumerate() {
        if let Some((ts, fmt_key)) = p {
            deltas.push((ts - prev).to_string());
            prev = *ts;
            fmt_indices.push(fmt_to_id[fmt_key].to_string());
        } else {
            deltas.push(format!("R{}", escape_raw(values[i])));
            fmt_indices.push("0".to_string());
        }
    }

    let delta_text = deltas.join("\n");
    let delta_bytes = string_to_latin1_bytes(&delta_text);
    varint::write_varint(writer, delta_bytes.len() as u64)?;
    writer.write_all(&delta_bytes)?;

    let fmt_text = fmt_indices.join("\n");
    let fmt_bytes = fmt_text.as_bytes();
    varint::write_varint(writer, fmt_bytes.len() as u64)?;
    writer.write_all(fmt_bytes)?;

    Ok(())
}

fn encode_dict_column<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let mut unique: Vec<&str> = values.iter().copied().collect::<std::collections::HashSet<_>>().into_iter().collect();
    unique.sort();

    let vocab: HashMap<&str, u32> = unique.iter().enumerate().map(|(i, &v)| (v, i as u32)).collect();

    // Write dictionary
    varint::write_varint(writer, unique.len() as u64)?;
    for word in &unique {
        // Convert chars to bytes (Latin-1 encoding: char U+00XX -> byte 0xXX)
        let bytes: Vec<u8> = word.chars().map(|c| c as u8).collect();
        varint::write_varint(writer, bytes.len() as u64)?;
        writer.write_all(&bytes)?;
    }

    // Bit-pack indices
    let bits = if unique.len() <= 1 { 1 } else { (unique.len() as f64).log2().ceil() as usize };
    let indices: Vec<u32> = values.iter().map(|v| *vocab.get(v).unwrap_or(&0)).collect();
    let packed = pack_bits(&indices, bits);

    writer.write_all(&[bits as u8])?;
    varint::write_varint(writer, packed.len() as u64)?;
    writer.write_all(&packed)?;

    Ok(())
}

// Text-delta encodings with R prefix fallback

fn encode_timestamp_fragment_text_delta<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let mut deltas = Vec::new();
    let mut prev = 0i64;

    for v in values {
        if v.starts_with('[') {
            if let Some((ts, _)) = parse_clf_timestamp(&format!("{}]", v)) {
                deltas.push((ts - prev).to_string());
                prev = ts;
            } else {
                deltas.push(format!("R{}", escape_raw(v)));
            }
        } else {
            deltas.push(format!("R{}", escape_raw(v)));
        }
    }

    let delta_text = deltas.join("\n");
    let delta_bytes = string_to_latin1_bytes(&delta_text);
    varint::write_varint(writer, delta_bytes.len() as u64)?;
    writer.write_all(&delta_bytes)?;

    Ok(())
}

fn encode_timestamp_clf_text_delta<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    // Collect format variations
    let mut format_set: std::collections::HashSet<(String, bool, bool)> = std::collections::HashSet::new();
    let mut parsed: Vec<Option<(i64, (String, bool, bool))>> = Vec::new();

    for v in values {
        if let Some((ts, fmt)) = parse_clf_timestamp(v) {
            let fmt_key = (fmt.tz.clone(), fmt.has_brackets, fmt.has_close);
            format_set.insert(fmt_key.clone());
            parsed.push(Some((ts, fmt_key)));
        } else {
            parsed.push(None);
        }
    }

    // Write format dictionary
    let format_list: Vec<_> = format_set.into_iter().collect();
    let fmt_to_id: HashMap<_, _> = format_list.iter().enumerate().map(|(i, f)| (f.clone(), i)).collect();

    varint::write_varint(writer, format_list.len() as u64)?;
    for (tz, has_brackets, has_close) in &format_list {
        let tz_bytes = tz.as_bytes();
        varint::write_varint(writer, tz_bytes.len() as u64)?;
        writer.write_all(tz_bytes)?;
        writer.write_all(&[if *has_brackets { 1 } else { 0 }])?;
        writer.write_all(&[if *has_close { 1 } else { 0 }])?;
    }

    // Write deltas and format indices
    let mut deltas = Vec::new();
    let mut fmt_indices = Vec::new();
    let mut prev = 0i64;

    for (i, p) in parsed.iter().enumerate() {
        if let Some((ts, fmt_key)) = p {
            deltas.push((ts - prev).to_string());
            prev = *ts;
            fmt_indices.push(fmt_to_id[fmt_key].to_string());
        } else {
            deltas.push(format!("R{}", escape_raw(values[i])));
            fmt_indices.push("0".to_string());
        }
    }

    let delta_text = deltas.join("\n");
    let delta_bytes = string_to_latin1_bytes(&delta_text);
    varint::write_varint(writer, delta_bytes.len() as u64)?;
    writer.write_all(&delta_bytes)?;

    let fmt_text = fmt_indices.join("\n");
    let fmt_bytes = fmt_text.as_bytes();
    varint::write_varint(writer, fmt_bytes.len() as u64)?;
    writer.write_all(fmt_bytes)?;

    Ok(())
}

fn encode_prefix_id_text_delta<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let mut prefix = String::new();
    let mut separator = b'-';
    for v in values {
        if let Some(caps) = PREFIX_ID_RE.captures(v) {
            prefix = caps.get(1).unwrap().as_str().to_string();
            // Detect separator
            let prefix_end = caps.get(1).unwrap().end();
            if prefix_end < v.len() {
                let sep_char = v.as_bytes()[prefix_end];
                if sep_char == b'_' || sep_char == b'-' {
                    separator = sep_char;
                }
            }
            break;
        }
    }

    let prefix_bytes = prefix.as_bytes();
    varint::write_varint(writer, prefix_bytes.len() as u64)?;
    writer.write_all(prefix_bytes)?;

    // Write separator character
    writer.write_all(&[separator])?;

    let mut deltas = Vec::new();
    let mut prev = 0i64;

    for v in values {
        if let Some(caps) = PREFIX_ID_RE.captures(v) {
            if caps.get(1).unwrap().as_str() == prefix {
                let num: i64 = caps.get(2).unwrap().as_str().parse().unwrap_or(0);
                deltas.push((num - prev).to_string());
                prev = num;
            } else {
                deltas.push(format!("R{}", escape_raw(v)));
            }
        } else {
            deltas.push(format!("R{}", escape_raw(v)));
        }
    }

    let delta_text = deltas.join("\n");
    let delta_bytes = string_to_latin1_bytes(&delta_text);
    varint::write_varint(writer, delta_bytes.len() as u64)?;
    writer.write_all(&delta_bytes)?;

    Ok(())
}

fn encode_numeric_text_delta<W: Write>(writer: &mut W, values: &[&str]) -> io::Result<()> {
    let mut deltas = Vec::new();
    let mut prev = 0i64;

    for v in values {
        if NUMERIC_RE.is_match(v) && !(v.starts_with('0') && v.len() > 1 && !v.starts_with("0-")) {
            if let Ok(num) = v.parse::<i64>() {
                deltas.push((num - prev).to_string());
                prev = num;
            } else {
                deltas.push(format!("R{}", escape_raw(v)));
            }
        } else {
            deltas.push(format!("R{}", escape_raw(v)));
        }
    }

    let delta_text = deltas.join("\n");
    let delta_bytes = string_to_latin1_bytes(&delta_text);
    varint::write_varint(writer, delta_bytes.len() as u64)?;
    writer.write_all(&delta_bytes)?;

    Ok(())
}

/// Pack values into bit-packed bytes
pub fn pack_bits(values: &[u32], bits: usize) -> Vec<u8> {
    if bits == 0 {
        return vec![];
    }

    let total_bits = values.len() * bits;
    let n_bytes = (total_bits + 7) / 8;
    let mut result = vec![0u8; n_bytes];

    let mut bit_pos = 0;
    for &val in values {
        let mut val = val;
        let mut byte_idx = bit_pos / 8;
        let mut bit_offset = bit_pos % 8;

        let mut remaining_bits = bits;
        while remaining_bits > 0 {
            let space_in_byte = 8 - bit_offset;
            let bits_to_write = remaining_bits.min(space_in_byte);
            let mask = (1u32 << bits_to_write) - 1;
            result[byte_idx] |= ((val & mask) << bit_offset) as u8;
            val >>= bits_to_write;
            remaining_bits -= bits_to_write;
            byte_idx += 1;
            bit_offset = 0;
        }

        bit_pos += bits;
    }

    result
}

/// Unpack bit-packed values
pub fn unpack_bits(data: &[u8], count: usize, bits: usize) -> Vec<u32> {
    if bits == 0 {
        return vec![0; count];
    }

    let mut result = Vec::with_capacity(count);
    let mut bit_pos = 0;

    for _ in 0..count {
        let mut val = 0u32;
        let mut byte_idx = bit_pos / 8;
        let mut bit_offset = bit_pos % 8;

        let mut remaining_bits = bits;
        let mut shift = 0;
        while remaining_bits > 0 && byte_idx < data.len() {
            let space_in_byte = 8 - bit_offset;
            let bits_to_read = remaining_bits.min(space_in_byte);
            let mask = (1u32 << bits_to_read) - 1;
            val |= ((data[byte_idx] as u32 >> bit_offset) & mask) << shift;
            remaining_bits -= bits_to_read;
            shift += bits_to_read;
            byte_idx += 1;
            bit_offset = 0;
        }

        result.push(val);
        bit_pos += bits;
    }

    result
}

/// Decode a smart column
pub fn decode_smart_column(data: &[u8], pos: &mut usize, n_rows: usize) -> io::Result<Vec<String>> {
    if *pos >= data.len() {
        return Ok(vec!["".to_string(); n_rows]);
    }

    let col_type = data[*pos];
    *pos += 1;

    if col_type == COL_RAW {
        decode_raw_column_newline(data, pos)
    } else if col_type == COL_RAW_LENPREFIX {
        decode_raw_column_lenprefix(data, pos)
    } else if col_type == COL_DICT {
        decode_dict_column(data, pos, n_rows)
    } else if col_type == COL_TS_CLF_FRAG {
        decode_timestamp_fragment_column(data, pos, n_rows)
    } else if col_type == COL_TS_CLF {
        decode_timestamp_clf_column(data, pos, n_rows)
    } else if col_type == COL_TS_ISO {
        decode_iso_timestamp_column(data, pos, n_rows)
    } else if col_type == COL_IPV4 {
        decode_ipv4_column(data, pos, n_rows)
    } else if col_type == COL_PREFIX_ID {
        decode_prefix_id_column(data, pos, n_rows)
    } else if col_type == COL_NUMERIC {
        decode_numeric_column(data, pos, n_rows)
    } else if col_type == COL_PATH {
        decode_path_column(data, pos, n_rows)
    } else if col_type == COL_TEXT_DELTA {
        let sub_type = data[*pos];
        *pos += 1;
        decode_text_delta_column(data, pos, n_rows, sub_type)
    } else if col_type == COL_SPARSE {
        decode_sparse_column(data, pos)
    } else {
        Ok(vec!["".to_string(); n_rows])
    }
}

/// Decode COL_SPARSE: sparse column with bitmap + dense values
fn decode_sparse_column(data: &[u8], pos: &mut usize) -> io::Result<Vec<String>> {
    // Read total row count and present count
    let (n_rows, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let n_rows = n_rows as usize;

    let (n_present, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let n_present = n_present as usize;

    // Read delta-encoded indices
    let mut indices = Vec::with_capacity(n_present);
    let mut prev_idx = 0usize;
    for _ in 0..n_present {
        let (delta, bytes_read) = varint::decode(&data[*pos..]);
        *pos += bytes_read;
        prev_idx += delta as usize;
        indices.push(prev_idx);
    }

    // Read dense values length and decode
    let (dense_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let present_values = if dense_len == 0 {
        Vec::new()
    } else {
        let dense_data = &data[*pos..*pos + dense_len as usize];
        *pos += dense_len as usize;
        let mut dense_pos = 0;
        decode_smart_column(dense_data, &mut dense_pos, n_present)?
    };

    // Reconstruct full column with ABSENT_MARKER for missing values
    let mut result = vec!["_ABSENT_".to_string(); n_rows];
    for (i, idx) in indices.iter().enumerate() {
        if i < present_values.len() {
            result[*idx] = present_values[i].clone();
        }
    }

    Ok(result)
}

/// Decode COL_RAW: newline-separated values (no embedded newlines)
fn decode_raw_column_newline(data: &[u8], pos: &mut usize) -> io::Result<Vec<String>> {
    let (len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    // Convert bytes to string using Latin-1 encoding (preserves all bytes)
    let text: String = data[*pos..*pos + len as usize].iter().map(|&b| b as char).collect();
    *pos += len as usize;

    Ok(text.split('\n').map(|s| s.to_string()).collect())
}

/// Decode COL_RAW_LENPREFIX: length-prefixed values (handles embedded newlines)
fn decode_raw_column_lenprefix(data: &[u8], pos: &mut usize) -> io::Result<Vec<String>> {
    // Read number of values
    let (n_values, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let mut values = Vec::with_capacity(n_values as usize);
    for _ in 0..n_values {
        let (len, bytes_read) = varint::decode(&data[*pos..]);
        *pos += bytes_read;

        // Convert bytes to string using Latin-1 encoding (preserves all bytes)
        let text: String = data[*pos..*pos + len as usize].iter().map(|&b| b as char).collect();
        *pos += len as usize;
        values.push(text);
    }

    Ok(values)
}

fn decode_dict_column(data: &[u8], pos: &mut usize, n_rows: usize) -> io::Result<Vec<String>> {
    let (vocab_size, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let mut vocab = Vec::with_capacity(vocab_size as usize);
    for _ in 0..vocab_size {
        let (word_len, bytes_read) = varint::decode(&data[*pos..]);
        *pos += bytes_read;
        // Convert bytes to string using Latin-1 encoding (preserves all bytes)
        let word: String = data[*pos..*pos + word_len as usize].iter().map(|&b| b as char).collect();
        *pos += word_len as usize;
        vocab.push(word);
    }

    let bits = data[*pos] as usize;
    *pos += 1;

    let (packed_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let packed = &data[*pos..*pos + packed_len as usize];
    *pos += packed_len as usize;

    let indices = unpack_bits(packed, n_rows, bits);
    Ok(indices.iter().map(|&i| vocab.get(i as usize).cloned().unwrap_or_default()).collect())
}

fn decode_timestamp_fragment_column(data: &[u8], pos: &mut usize, n_rows: usize) -> io::Result<Vec<String>> {
    let (min_val, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let mut values = Vec::with_capacity(n_rows);
    for _ in 0..n_rows {
        let (offset, bytes_read) = varint::decode(&data[*pos..]);
        *pos += bytes_read;
        values.push(reconstruct_clf_fragment((min_val + offset) as i64));
    }

    Ok(values)
}

fn decode_timestamp_clf_column(data: &[u8], pos: &mut usize, n_rows: usize) -> io::Result<Vec<String>> {
    let (min_val, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let mut ts_values = Vec::with_capacity(n_rows);
    for _ in 0..n_rows {
        let (offset, bytes_read) = varint::decode(&data[*pos..]);
        *pos += bytes_read;
        ts_values.push((min_val + offset) as i64);
    }

    // Read format info
    let (format_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let format_json = latin1_bytes_to_string(&data[*pos..*pos + format_len as usize]);
    *pos += format_len as usize;

    // Parse format (simple JSON parsing)
    let format = parse_clf_format(&format_json);

    Ok(ts_values.iter().map(|&ts| reconstruct_clf_timestamp(ts, &format)).collect())
}

fn parse_clf_format(json: &str) -> ClfFormat {
    // Simple parsing - extract values
    let tz = json.split("\"tz\":\"").nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("")
        .to_string();
    let has_brackets = json.contains("\"has_brackets\":true");
    let has_close = json.contains("\"has_close\":true");

    ClfFormat { tz, has_brackets, has_close }
}

fn decode_prefix_id_column(data: &[u8], pos: &mut usize, n_rows: usize) -> io::Result<Vec<String>> {
    let (prefix_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let prefix = latin1_bytes_to_string(&data[*pos..*pos + prefix_len as usize]);
    *pos += prefix_len as usize;

    // Read separator character
    let separator = data[*pos] as char;
    *pos += 1;

    let mut values = Vec::with_capacity(n_rows);
    let mut prev = 0i64;

    for _ in 0..n_rows {
        let (delta, bytes_read) = varint::decode_signed(&data[*pos..]);
        *pos += bytes_read;
        prev += delta;
        if prefix.is_empty() {
            values.push(prev.to_string());
        } else {
            values.push(format!("{}{}{}", prefix, separator, prev));
        }
    }

    Ok(values)
}

fn decode_numeric_column(data: &[u8], pos: &mut usize, n_rows: usize) -> io::Result<Vec<String>> {
    // Read marker flag for STRING_TYPE_MARKER
    let has_marker = data[*pos] == 1;
    *pos += 1;

    let mut values = Vec::with_capacity(n_rows);
    let mut prev = 0i64;

    for _ in 0..n_rows {
        let (delta, bytes_read) = varint::decode_signed(&data[*pos..]);
        *pos += bytes_read;
        prev += delta;
        if has_marker {
            values.push(format!("\x01{}", prev));
        } else {
            values.push(prev.to_string());
        }
    }

    Ok(values)
}

fn decode_ipv4_column(data: &[u8], pos: &mut usize, n_rows: usize) -> io::Result<Vec<String>> {
    let (min_val, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let mut values = Vec::with_capacity(n_rows);
    for _ in 0..n_rows {
        let (offset, bytes_read) = varint::decode(&data[*pos..]);
        *pos += bytes_read;
        values.push(reconstruct_ipv4((min_val + offset) as u32));
    }

    Ok(values)
}

fn decode_path_column(data: &[u8], pos: &mut usize, n_rows: usize) -> io::Result<Vec<String>> {
    // Read max segments count
    let (max_segments, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let max_segments = max_segments as usize;

    // Read each segment column
    let mut segment_cols: Vec<Vec<String>> = Vec::new();
    for _ in 0..max_segments {
        let col = decode_dict_column(data, pos, n_rows)?;
        segment_cols.push(col);
    }

    // Read trailing slash flags
    let (flags_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let flags_bytes = &data[*pos..*pos + flags_len as usize];
    *pos += flags_len as usize;
    let has_trailing_slash = unpack_bits(flags_bytes, n_rows, 1);

    // Reconstruct paths
    let mut result = Vec::with_capacity(n_rows);
    for i in 0..n_rows {
        let segments: Vec<&str> = segment_cols.iter()
            .map(|col| col[i].as_str())
            .take_while(|s| !s.is_empty() || segment_cols.iter().position(|c| c[i].as_str() == *s) == Some(0))
            .collect();

        // Remove trailing empty segments
        let mut segments = segments;
        while segments.len() > 1 && segments.last() == Some(&"") {
            segments.pop();
        }

        let mut path = segments.join("/");
        if has_trailing_slash[i] == 1 {
            // For "/" alone, path is empty but we still need to produce "/"
            if path.is_empty() {
                path = "/".to_string();
            } else {
                path.push('/');
            }
        }
        result.push(path);
    }

    Ok(result)
}

fn decode_iso_timestamp_column(data: &[u8], pos: &mut usize, n_rows: usize) -> io::Result<Vec<String>> {
    let (min_val, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let mut ts_values = Vec::with_capacity(n_rows);
    for _ in 0..n_rows {
        let (offset, bytes_read) = varint::decode(&data[*pos..]);
        *pos += bytes_read;
        ts_values.push((min_val + offset) as i64);
    }

    // Read format info
    let has_t = data[*pos] == 1;
    *pos += 1;
    let subsec_len = data[*pos];
    *pos += 1;

    let (tz_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let tz_str = latin1_bytes_to_string(&data[*pos..*pos + tz_len as usize]);
    *pos += tz_len as usize;

    let (tz_offset, tz_minutes) = if tz_str == "Z" {
        (None, None)
    } else if tz_str.contains(':') {
        let parts: Vec<&str> = tz_str.split(':').collect();
        (Some(parts[0].to_string()), parts.get(1).map(|s| s.to_string()))
    } else {
        (Some(tz_str.to_string()), None)
    };

    let format = IsoFormat { has_t, subsec_len, tz_offset, tz_minutes };

    Ok(ts_values.iter().map(|&ts| reconstruct_iso_timestamp(ts, &format)).collect())
}

fn decode_text_delta_column(data: &[u8], pos: &mut usize, n_rows: usize, sub_type: u8) -> io::Result<Vec<String>> {
    if sub_type == COL_TS_CLF_FRAG {
        decode_timestamp_fragment_text_delta(data, pos)
    } else if sub_type == COL_TS_CLF {
        decode_timestamp_clf_text_delta(data, pos)
    } else if sub_type == COL_TS_ISO {
        decode_iso_timestamp_text_delta(data, pos)
    } else if sub_type == COL_IPV4 {
        decode_ipv4_text_delta(data, pos)
    } else if sub_type == COL_PREFIX_ID {
        decode_prefix_id_text_delta(data, pos)
    } else if sub_type == COL_NUMERIC {
        decode_numeric_text_delta(data, pos)
    } else {
        Ok(vec!["".to_string(); n_rows])
    }
}

fn decode_timestamp_fragment_text_delta(data: &[u8], pos: &mut usize) -> io::Result<Vec<String>> {
    let (delta_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let delta_text = latin1_bytes_to_string(&data[*pos..*pos + delta_len as usize]);
    *pos += delta_len as usize;

    let mut values = Vec::new();
    let mut current = 0i64;

    for d in delta_text.split('\n') {
        if let Some(raw) = d.strip_prefix('R') {
            values.push(unescape_raw(raw));
        } else {
            let delta: i64 = d.parse().unwrap_or(0);
            current += delta;
            values.push(reconstruct_clf_fragment(current));
        }
    }

    Ok(values)
}

fn decode_timestamp_clf_text_delta(data: &[u8], pos: &mut usize) -> io::Result<Vec<String>> {
    // Read format dictionary
    let (n_formats, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let mut format_list = Vec::new();
    for _ in 0..n_formats {
        let (tz_len, bytes_read) = varint::decode(&data[*pos..]);
        *pos += bytes_read;
        let tz = latin1_bytes_to_string(&data[*pos..*pos + tz_len as usize]);
        *pos += tz_len as usize;

        let has_brackets = data[*pos] == 1;
        *pos += 1;
        let has_close = data[*pos] == 1;
        *pos += 1;

        format_list.push(ClfFormat { tz, has_brackets, has_close });
    }

    // Read deltas
    let (delta_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let delta_text = latin1_bytes_to_string(&data[*pos..*pos + delta_len as usize]);
    *pos += delta_len as usize;
    let deltas: Vec<&str> = delta_text.split('\n').collect();

    // Read format indices
    let (fmt_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let fmt_text = latin1_bytes_to_string(&data[*pos..*pos + fmt_len as usize]);
    *pos += fmt_len as usize;
    let fmt_indices: Vec<usize> = fmt_text.split('\n').map(|s| s.parse().unwrap_or(0)).collect();

    let mut values = Vec::new();
    let mut current = 0i64;

    for (i, d) in deltas.iter().enumerate() {
        if let Some(raw) = d.strip_prefix('R') {
            values.push(unescape_raw(raw));
        } else {
            let delta: i64 = d.parse().unwrap_or(0);
            current += delta;
            let fmt_idx = fmt_indices.get(i).copied().unwrap_or(0);
            let fmt = format_list.get(fmt_idx).cloned().unwrap_or_default();
            values.push(reconstruct_clf_timestamp(current, &fmt));
        }
    }

    Ok(values)
}

fn decode_prefix_id_text_delta(data: &[u8], pos: &mut usize) -> io::Result<Vec<String>> {
    let (prefix_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let prefix = latin1_bytes_to_string(&data[*pos..*pos + prefix_len as usize]);
    *pos += prefix_len as usize;

    // Read separator character
    let separator = data[*pos] as char;
    *pos += 1;

    let (delta_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let delta_text = latin1_bytes_to_string(&data[*pos..*pos + delta_len as usize]);
    *pos += delta_len as usize;

    let mut values = Vec::new();
    let mut current = 0i64;

    for d in delta_text.split('\n') {
        if let Some(raw) = d.strip_prefix('R') {
            values.push(unescape_raw(raw));
        } else {
            let delta: i64 = d.parse().unwrap_or(0);
            current += delta;
            if prefix.is_empty() {
                values.push(current.to_string());
            } else {
                values.push(format!("{}{}{}", prefix, separator, current));
            }
        }
    }

    Ok(values)
}

fn decode_numeric_text_delta(data: &[u8], pos: &mut usize) -> io::Result<Vec<String>> {
    let (delta_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let delta_text = latin1_bytes_to_string(&data[*pos..*pos + delta_len as usize]);
    *pos += delta_len as usize;

    let mut values = Vec::new();
    let mut current = 0i64;

    for d in delta_text.split('\n') {
        if let Some(raw) = d.strip_prefix('R') {
            values.push(unescape_raw(raw));
        } else {
            let delta: i64 = d.parse().unwrap_or(0);
            current += delta;
            values.push(current.to_string());
        }
    }

    Ok(values)
}

fn decode_ipv4_text_delta(data: &[u8], pos: &mut usize) -> io::Result<Vec<String>> {
    let (delta_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let delta_text = latin1_bytes_to_string(&data[*pos..*pos + delta_len as usize]);
    *pos += delta_len as usize;

    let mut values = Vec::new();
    let mut current = 0i64;

    for d in delta_text.split('\n') {
        if let Some(raw) = d.strip_prefix('R') {
            values.push(unescape_raw(raw));
        } else {
            let delta: i64 = d.parse().unwrap_or(0);
            current += delta;
            values.push(reconstruct_ipv4(current as u32));
        }
    }

    Ok(values)
}

fn decode_iso_timestamp_text_delta(data: &[u8], pos: &mut usize) -> io::Result<Vec<String>> {
    // Read format dictionary
    let (n_formats, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;

    let mut format_list = Vec::new();
    for _ in 0..n_formats {
        let has_t = data[*pos] == 1;
        *pos += 1;
        let subsec_len = data[*pos];
        *pos += 1;
        let (tz_len, bytes_read) = varint::decode(&data[*pos..]);
        *pos += bytes_read;
        let tz_str = latin1_bytes_to_string(&data[*pos..*pos + tz_len as usize]);
        *pos += tz_len as usize;

        let (tz_offset, tz_minutes) = if tz_str == "Z" {
            (None, None)
        } else if tz_str.contains(':') {
            let parts: Vec<&str> = tz_str.split(':').collect();
            (Some(parts[0].to_string()), parts.get(1).map(|s| s.to_string()))
        } else {
            (Some(tz_str.to_string()), None)
        };

        format_list.push(IsoFormat { has_t, subsec_len, tz_offset, tz_minutes });
    }

    // Read deltas
    let (delta_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let delta_text = latin1_bytes_to_string(&data[*pos..*pos + delta_len as usize]);
    *pos += delta_len as usize;
    let deltas: Vec<&str> = delta_text.split('\n').collect();

    // Read format indices
    let (fmt_len, bytes_read) = varint::decode(&data[*pos..]);
    *pos += bytes_read;
    let fmt_text = latin1_bytes_to_string(&data[*pos..*pos + fmt_len as usize]);
    *pos += fmt_len as usize;
    let fmt_indices: Vec<usize> = fmt_text.split('\n').map(|s| s.parse().unwrap_or(0)).collect();

    let mut values = Vec::new();
    let mut current = 0i64;

    for (i, d) in deltas.iter().enumerate() {
        if let Some(raw) = d.strip_prefix('R') {
            values.push(unescape_raw(raw));
        } else {
            let delta: i64 = d.parse().unwrap_or(0);
            current += delta;
            let fmt_idx = fmt_indices.get(i).copied().unwrap_or(0);
            let fmt = format_list.get(fmt_idx).cloned().unwrap_or_default();
            values.push(reconstruct_iso_timestamp(current, &fmt));
        }
    }

    Ok(values)
}

/// Public column encoder interface for text_encoder.rs
pub struct ColumnEncoder;

impl ColumnEncoder {
    /// Encode column values using smart encoding strategies
    pub fn encode(values: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = encode_smart_column(&mut buf, values, values.len());
        buf
    }

    /// Decode column values from encoded data
    pub fn decode(data: &[u8], n_rows: usize) -> io::Result<Vec<String>> {
        let mut pos = 0;
        decode_smart_column(data, &mut pos, n_rows)
    }
}

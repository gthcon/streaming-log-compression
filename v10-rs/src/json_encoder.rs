//! JSON columnar encoding with schema learning and key order preservation
//!
//! Implements JSON log encoding with:
//! - Schema extraction and stable field ordering
//! - Per-row key order preservation for lossless roundtrip
//! - JSON separator style detection (compact vs spaced)
//! - Smart column encoding (timestamps, IPv4, prefix-ID, dictionary, delta)
//! - Raw fallback for unparseable lines

use crate::config::StreamingConfig;
use crate::column;
use crate::varint;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write, Read, Cursor};

/// JSON separator style
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum SeparatorStyle {
    /// Compact: {"a":1,"b":2}
    #[default]
    Compact,
    /// Spaced: {"a": 1, "b": 2}
    Spaced,
}

impl SeparatorStyle {
    pub fn to_byte(self) -> u8 {
        match self {
            SeparatorStyle::Compact => 0,
            SeparatorStyle::Spaced => 1,
        }
    }

    pub fn from_byte(b: u8) -> Self {
        if b == 1 {
            SeparatorStyle::Spaced
        } else {
            SeparatorStyle::Compact
        }
    }

    pub fn separators(self) -> (&'static str, &'static str) {
        match self {
            SeparatorStyle::Compact => (",", ":"),
            SeparatorStyle::Spaced => (", ", ": "),
        }
    }
}

/// Detect separator style from a line
fn detect_separator_style(line: &str) -> SeparatorStyle {
    // Look for ": " (colon-space) pattern - indicates spaced style
    if line.contains(": ") {
        SeparatorStyle::Spaced
    } else {
        SeparatorStyle::Compact
    }
}

/// Detect separator style from multiple lines (majority wins)
fn detect_separator_style_multi(lines: &[&str]) -> SeparatorStyle {
    let mut spaced_count = 0;
    let mut compact_count = 0;

    for line in lines.iter().take(10) {
        match detect_separator_style(line) {
            SeparatorStyle::Spaced => spaced_count += 1,
            SeparatorStyle::Compact => compact_count += 1,
        }
    }

    if spaced_count > compact_count {
        SeparatorStyle::Spaced
    } else {
        SeparatorStyle::Compact
    }
}

const ABSENT_MARKER: &str = "_ABSENT_";

/// JSON schema - ordered list of keys
#[derive(Clone, Debug, Default)]
pub struct JsonSchema {
    /// Ordered keys in the schema
    pub keys: Vec<String>,
    /// Key -> index mapping
    key_to_idx: HashMap<String, usize>,
}

impl JsonSchema {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key to the schema, returns its index
    pub fn add_key(&mut self, key: &str) -> usize {
        if let Some(&idx) = self.key_to_idx.get(key) {
            return idx;
        }
        let idx = self.keys.len();
        self.keys.push(key.to_string());
        self.key_to_idx.insert(key.to_string(), idx);
        idx
    }

    /// Get index for a key
    pub fn get_index(&self, key: &str) -> Option<usize> {
        self.key_to_idx.get(key).copied()
    }

    /// Encode schema to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        varint::write_varint(&mut buf, self.keys.len() as u64).unwrap();
        for key in &self.keys {
            // Use Latin-1 encoding (char U+00XX -> byte 0xXX)
            let key_bytes: Vec<u8> = key.chars().map(|c| c as u8).collect();
            varint::write_varint(&mut buf, key_bytes.len() as u64).unwrap();
            buf.extend_from_slice(&key_bytes);
        }
        buf
    }

    /// Decode schema from bytes
    pub fn decode(data: &[u8]) -> io::Result<(Self, usize)> {
        let mut cursor = Cursor::new(data);
        let num_keys = varint::read_varint(&mut cursor)? as usize;
        let mut schema = JsonSchema::new();

        for _ in 0..num_keys {
            let key_len = varint::read_varint(&mut cursor)? as usize;
            let pos = cursor.position() as usize;
            // Use Latin-1 decoding to preserve all bytes
            let key: String = data[pos..pos + key_len].iter().map(|&b| b as char).collect();
            cursor.set_position((pos + key_len) as u64);
            schema.add_key(&key);
        }

        Ok((schema, cursor.position() as usize))
    }
}

/// Marker to indicate the value is a JSON string type (not number/bool/null/array/object)
const STRING_TYPE_MARKER: char = '\x01';
/// Marker to indicate the value is a JSON array or nested object (serialized as JSON)
const JSON_TYPE_MARKER: char = '\x02';

/// Maximum depth for JSON flattening (deeper nesting stored as JSON blob)
const MAX_FLATTEN_DEPTH: usize = 2;

/// Flatten nested JSON into dot-notation keys, preserving order and type info
fn flatten_json(value: &serde_json::Value, prefix: &str) -> Vec<(String, String)> {
    flatten_json_depth(value, prefix, 0)
}

/// Flatten with depth tracking
fn flatten_json_depth(value: &serde_json::Value, prefix: &str, depth: usize) -> Vec<(String, String)> {
    let mut result = Vec::new();

    match value {
        serde_json::Value::Object(obj) => {
            for (key, val) in obj.iter() {
                let new_prefix = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };

                match val {
                    serde_json::Value::Object(nested_obj) => {
                        if nested_obj.is_empty() {
                            // Handle empty objects - store as JSON
                            result.push((new_prefix, format!("{}{}", JSON_TYPE_MARKER, "{}")));
                        } else if depth >= MAX_FLATTEN_DEPTH {
                            // Max depth reached - store nested object as JSON blob
                            let json_str = serde_json::to_string(val).unwrap_or_default();
                            result.push((new_prefix, format!("{}{}", JSON_TYPE_MARKER, json_str)));
                        } else {
                            result.extend(flatten_json_depth(val, &new_prefix, depth + 1));
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        // Store arrays with JSON marker (not string marker)
                        let json_str = serde_json::to_string(arr).unwrap_or_default();
                        result.push((new_prefix, format!("{}{}", JSON_TYPE_MARKER, json_str)));
                    }
                    serde_json::Value::String(s) => {
                        // Prefix string values with STRING marker
                        result.push((new_prefix, format!("{}{}", STRING_TYPE_MARKER, s)));
                    }
                    serde_json::Value::Number(n) => {
                        // No prefix for numbers - we want parse_json_value to recognize them
                        result.push((new_prefix, n.to_string()));
                    }
                    serde_json::Value::Bool(b) => {
                        result.push((new_prefix, b.to_string()));
                    }
                    serde_json::Value::Null => {
                        result.push((new_prefix, "null".to_string()));
                    }
                }
            }
        }
        _ => {
            if !prefix.is_empty() {
                result.push((prefix.to_string(), value.to_string()));
            }
        }
    }

    result
}

/// Unflatten dot-notation keys back to nested JSON
fn unflatten_json(pairs: &[(String, String)]) -> serde_json::Value {
    let mut root = serde_json::Map::new();

    for (key, value) in pairs {
        set_nested_value(&mut root, key, value);
    }

    serde_json::Value::Object(root)
}

/// Set a nested value using dot notation
fn set_nested_value(obj: &mut serde_json::Map<String, serde_json::Value>, key: &str, value: &str) {
    let parts: Vec<&str> = key.splitn(2, '.').collect();

    if parts.len() == 1 {
        // Leaf value - try to parse as JSON type
        let json_val = parse_json_value(value);
        obj.insert(key.to_string(), json_val);
    } else {
        // Nested - get or create sub-object
        let first = parts[0];
        let rest = parts[1];

        let sub_obj = obj.entry(first.to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

        if let serde_json::Value::Object(sub_map) = sub_obj {
            set_nested_value(sub_map, rest, value);
        }
    }
}

/// Parse a string value back to its JSON type
fn parse_json_value(value: &str) -> serde_json::Value {
    // Check for JSON type marker (array or nested object)
    if value.starts_with(JSON_TYPE_MARKER) {
        let actual_value = &value[1..];
        // Parse as JSON array or object
        serde_json::from_str(actual_value).unwrap_or_else(|_| serde_json::Value::String(actual_value.to_string()))
    // Check for string type marker - always return as string
    } else if value.starts_with(STRING_TYPE_MARKER) {
        let actual_value = &value[1..];
        serde_json::Value::String(actual_value.to_string())
    } else if value == "null" {
        serde_json::Value::Null
    } else if value == "true" {
        serde_json::Value::Bool(true)
    } else if value == "false" {
        serde_json::Value::Bool(false)
    } else if let Ok(n) = value.parse::<i64>() {
        serde_json::Value::Number(n.into())
    } else if let Ok(f) = value.parse::<f64>() {
        serde_json::json!(f)
    } else if (value.starts_with('[') && value.ends_with(']')) ||
              (value.starts_with('{') && value.ends_with('}')) {
        // Try to parse as JSON array or object (legacy unmarked)
        serde_json::from_str(value).unwrap_or_else(|_| serde_json::Value::String(value.to_string()))
    } else {
        serde_json::Value::String(value.to_string())
    }
}

/// Per-column encoder state - stores values for later smart column encoding
struct ColumnEncoder {
    values: Vec<String>,
}

impl ColumnEncoder {
    fn new() -> Self {
        Self {
            values: Vec::new(),
        }
    }

    fn add_value(&mut self, value: &str) {
        self.values.push(value.to_string());
    }
}

/// JSON encoder for a chunk of lines with lossless key order preservation
pub struct JsonChunkEncoder {
    config: StreamingConfig,
    schema: JsonSchema,
    key_set: HashSet<String>,
    columns: HashMap<String, ColumnEncoder>,
    /// Per-row key order as list of key indices
    row_key_orders: Vec<Vec<usize>>,
    /// Original lines for raw fallback
    raw_lines: Vec<String>,
    /// Separator style
    separator_style: SeparatorStyle,
    line_count: usize,
}

impl JsonChunkEncoder {
    pub fn new(config: StreamingConfig) -> Self {
        Self {
            config,
            schema: JsonSchema::new(),
            key_set: HashSet::new(),
            columns: HashMap::new(),
            row_key_orders: Vec::new(),
            raw_lines: Vec::new(),
            separator_style: SeparatorStyle::Compact,
            line_count: 0,
        }
    }

    /// Add a JSON line. Returns true if successfully parsed.
    pub fn add_line(&mut self, line: &str) -> bool {
        // Detect separator style from first line
        if self.line_count == 0 {
            self.separator_style = detect_separator_style(line);
        }

        // Try to parse as JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line.trim());

        match parsed {
            Ok(serde_json::Value::Object(_)) => {
                let flat = flatten_json(&parsed.unwrap(), "");

                // Track this row's key order and add new keys to schema
                let mut row_key_indices = Vec::new();
                for (key, _) in &flat {
                    if !self.key_set.contains(key) {
                        self.schema.add_key(key);
                        self.key_set.insert(key.clone());
                    }
                    let idx = self.schema.get_index(key).unwrap();
                    row_key_indices.push(idx);
                }
                self.row_key_orders.push(row_key_indices.clone());

                // Add values to columns (ABSENT for missing keys)
                for key in &self.schema.keys {
                    let encoder = self.columns.entry(key.clone()).or_insert_with(|| {
                        let mut enc = ColumnEncoder::new();
                        // Fill previous rows with ABSENT
                        for _ in 0..self.line_count {
                            enc.add_value(ABSENT_MARKER);
                        }
                        enc
                    });

                    let value = flat.iter()
                        .find(|(k, _)| k == key)
                        .map(|(_, v)| v.as_str())
                        .unwrap_or(ABSENT_MARKER);
                    encoder.add_value(value);
                }

                self.raw_lines.push(String::new());
                self.line_count += 1;
                true
            }
            _ => {
                // Not a JSON object, store as raw
                self.row_key_orders.push(Vec::new());

                // Add ABSENT to all columns
                for key in &self.schema.keys {
                    if let Some(encoder) = self.columns.get_mut(key) {
                        encoder.add_value(ABSENT_MARKER);
                    }
                }

                self.raw_lines.push(line.to_string());
                self.line_count += 1;
                false
            }
        }
    }

    /// Encode all data to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Write separator style (1 byte)
        buf.push(self.separator_style.to_byte());

        // Write schema
        let schema_bytes = self.schema.encode();
        buf.extend_from_slice(&schema_bytes);

        // Write line count
        varint::write_varint(&mut buf, self.line_count as u64).unwrap();

        // Write each column in schema order using smart column encoding
        for key in &self.schema.keys {
            if let Some(encoder) = self.columns.get(key) {
                // Collect values as &str slice for smart column encoding
                let values: Vec<&str> = encoder.values.iter().map(|s| s.as_str()).collect();

                // Encode to a temporary buffer to get the length
                let mut col_buf = Vec::new();
                column::encode_smart_column(&mut col_buf, &values, self.line_count).unwrap();

                varint::write_varint(&mut buf, col_buf.len() as u64).unwrap();
                buf.extend_from_slice(&col_buf);
            } else {
                // Empty column
                varint::write_varint(&mut buf, 0u64).unwrap();
            }
        }

        // Write per-row key order indices
        for indices in &self.row_key_orders {
            varint::write_varint(&mut buf, indices.len() as u64).unwrap();
            for &idx in indices {
                varint::write_varint(&mut buf, idx as u64).unwrap();
            }
        }

        // Write raw lines (for non-JSON or failed parses)
        let has_raw = self.raw_lines.iter().any(|s| !s.is_empty());
        buf.push(if has_raw { 1 } else { 0 });

        if has_raw {
            for line in &self.raw_lines {
                // Use Latin-1 encoding (char U+00XX -> byte 0xXX)
                let line_bytes: Vec<u8> = line.chars().map(|c| c as u8).collect();
                varint::write_varint(&mut buf, line_bytes.len() as u64).unwrap();
                buf.extend_from_slice(&line_bytes);
            }
        }

        buf
    }
}

/// JSON decoder for a chunk
pub struct JsonChunkDecoder {
    schema: JsonSchema,
    columns: Vec<Vec<String>>,
    row_key_orders: Vec<Vec<usize>>,
    raw_lines: Vec<String>,
    separator_style: SeparatorStyle,
    line_count: usize,
}

impl JsonChunkDecoder {
    /// Decode a JSON chunk from bytes
    pub fn decode(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);

        // Read separator style
        let mut style_byte = [0u8; 1];
        cursor.read_exact(&mut style_byte)?;
        let separator_style = SeparatorStyle::from_byte(style_byte[0]);

        // Read schema
        let pos = cursor.position() as usize;
        let (schema, schema_len) = JsonSchema::decode(&data[pos..])?;
        cursor.set_position((pos + schema_len) as u64);

        // Read line count
        let line_count = varint::read_varint(&mut cursor)? as usize;

        // Read columns using smart column decoding
        let mut columns = Vec::with_capacity(schema.keys.len());
        for _ in 0..schema.keys.len() {
            let col_len = varint::read_varint(&mut cursor)? as usize;
            if col_len == 0 {
                columns.push(vec![ABSENT_MARKER.to_string(); line_count]);
            } else {
                let col_start = cursor.position() as usize;
                let mut pos = 0usize;
                let col_data = &data[col_start..col_start + col_len];
                let values = column::decode_smart_column(col_data, &mut pos, line_count)?;
                cursor.set_position((col_start + col_len) as u64);
                columns.push(values);
            }
        }

        // Read per-row key order indices
        let mut row_key_orders = Vec::with_capacity(line_count);
        for _ in 0..line_count {
            let n_indices = varint::read_varint(&mut cursor)? as usize;
            let mut indices = Vec::with_capacity(n_indices);
            for _ in 0..n_indices {
                let idx = varint::read_varint(&mut cursor)? as usize;
                indices.push(idx);
            }
            row_key_orders.push(indices);
        }

        // Read raw lines flag
        let mut has_raw = [0u8; 1];
        cursor.read_exact(&mut has_raw)?;

        let mut raw_lines = vec![String::new(); line_count];
        if has_raw[0] == 1 {
            for i in 0..line_count {
                let len = varint::read_varint(&mut cursor)? as usize;
                if len > 0 {
                    let pos = cursor.position() as usize;
                    // Use Latin-1 decoding to preserve all bytes
                    raw_lines[i] = data[pos..pos + len].iter().map(|&b| b as char).collect();
                    cursor.set_position((pos + len) as u64);
                }
            }
        }

        Ok(Self {
            schema,
            columns,
            row_key_orders,
            raw_lines,
            separator_style,
            line_count,
        })
    }

    /// Reconstruct lines from decoded data with original key order
    pub fn reconstruct_lines(&self) -> Vec<String> {
        let mut lines = Vec::with_capacity(self.line_count);
        let (sep_comma, sep_colon) = self.separator_style.separators();

        for row in 0..self.line_count {
            // Check if this is a raw line
            if !self.raw_lines[row].is_empty() {
                lines.push(self.raw_lines[row].clone());
                continue;
            }

            // Build object with keys in original order for this row
            let row_key_indices = &self.row_key_orders[row];
            let mut pairs: Vec<(String, String)> = Vec::new();

            for &key_idx in row_key_indices {
                if key_idx < self.schema.keys.len() {
                    let key = &self.schema.keys[key_idx];
                    if key_idx < self.columns.len() {
                        let val = &self.columns[key_idx][row];
                        if val != ABSENT_MARKER {
                            pairs.push((key.clone(), val.clone()));
                        }
                    }
                }
            }

            // Reconstruct JSON with original key order
            let obj = unflatten_json(&pairs);

            // Manually serialize to preserve key order
            let json_str = serialize_with_order(&obj, sep_comma, sep_colon);
            lines.push(json_str);
        }

        lines
    }
}

/// Serialize JSON value with specific separators, preserving object key order
fn serialize_with_order(value: &serde_json::Value, sep_comma: &str, sep_colon: &str) -> String {
    match value {
        serde_json::Value::Object(obj) => {
            let mut parts = Vec::new();
            for (key, val) in obj.iter() {
                let key_str = serde_json::to_string(key).unwrap_or_else(|_| format!("\"{}\"", key));
                let val_str = serialize_with_order(val, sep_comma, sep_colon);
                parts.push(format!("{}{}{}", key_str, sep_colon, val_str));
            }
            format!("{{{}}}", parts.join(sep_comma))
        }
        serde_json::Value::Array(arr) => {
            let parts: Vec<String> = arr.iter()
                .map(|v| serialize_with_order(v, sep_comma, sep_colon))
                .collect();
            format!("[{}]", parts.join(sep_comma))
        }
        serde_json::Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s)),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_roundtrip() {
        let mut schema = JsonSchema::new();
        schema.add_key("timestamp");
        schema.add_key("level");
        schema.add_key("message");

        let encoded = schema.encode();
        let (decoded, _) = JsonSchema::decode(&encoded).unwrap();

        assert_eq!(decoded.keys, schema.keys);
    }

    #[test]
    fn test_json_encoder_basic() {
        let config = StreamingConfig::default();
        let mut encoder = JsonChunkEncoder::new(config);

        encoder.add_line(r#"{"level":"INFO","msg":"Hello"}"#);
        encoder.add_line(r#"{"level":"INFO","msg":"World"}"#);
        encoder.add_line(r#"{"level":"WARN","msg":"Test"}"#);

        let encoded = encoder.encode();
        assert!(!encoded.is_empty());

        let decoder = JsonChunkDecoder::decode(&encoded).unwrap();
        let lines = decoder.reconstruct_lines();
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn test_json_key_order_preservation() {
        let config = StreamingConfig::default();
        let mut encoder = JsonChunkEncoder::new(config);

        // Different key orders
        encoder.add_line(r#"{"a":1,"b":2,"c":3}"#);
        encoder.add_line(r#"{"c":3,"b":2,"a":1}"#);
        encoder.add_line(r#"{"b":2,"a":1,"c":3}"#);

        let encoded = encoder.encode();
        let decoder = JsonChunkDecoder::decode(&encoded).unwrap();
        let lines = decoder.reconstruct_lines();

        assert_eq!(lines[0], r#"{"a":1,"b":2,"c":3}"#);
        assert_eq!(lines[1], r#"{"c":3,"b":2,"a":1}"#);
        assert_eq!(lines[2], r#"{"b":2,"a":1,"c":3}"#);
    }

    #[test]
    fn test_json_separator_style() {
        let config = StreamingConfig::default();

        // Test spaced style
        let mut encoder = JsonChunkEncoder::new(config.clone());
        encoder.add_line(r#"{"a": 1, "b": 2}"#);
        let encoded = encoder.encode();
        let decoder = JsonChunkDecoder::decode(&encoded).unwrap();
        let lines = decoder.reconstruct_lines();
        assert_eq!(lines[0], r#"{"a": 1, "b": 2}"#);

        // Test compact style
        let mut encoder = JsonChunkEncoder::new(config);
        encoder.add_line(r#"{"a":1,"b":2}"#);
        let encoded = encoder.encode();
        let decoder = JsonChunkDecoder::decode(&encoded).unwrap();
        let lines = decoder.reconstruct_lines();
        assert_eq!(lines[0], r#"{"a":1,"b":2}"#);
    }
}

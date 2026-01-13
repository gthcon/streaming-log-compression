//! Text template encoding with smart column types and incremental templates
//!
//! Implements text log encoding with:
//! - Template mining via Drain algorithm
//! - Incremental template writing (only NEW templates per chunk)
//! - Columnar format with bit-packed template indices
//! - Smart column encoding for timestamps, IPs, etc.
//! - Text-delta encoding for similar strings

use crate::config::StreamingConfig;
use crate::drain::DrainState;
use crate::column::ColumnEncoder as SmartColumnEncoder;
use crate::varint;
use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor};

/// Pack indices using bit-packing
fn pack_bits(indices: &[u16], bits: u8) -> Vec<u8> {
    if indices.is_empty() {
        return Vec::new();
    }

    let total_bits = indices.len() * bits as usize;
    let num_bytes = (total_bits + 7) / 8;
    let mut packed = vec![0u8; num_bytes];

    let mut bit_pos = 0;
    for &idx in indices {
        let val = idx as u32;
        for b in 0..bits {
            if (val >> b) & 1 == 1 {
                let byte_idx = bit_pos / 8;
                let bit_offset = bit_pos % 8;
                packed[byte_idx] |= 1 << bit_offset;
            }
            bit_pos += 1;
        }
    }

    packed
}

/// Unpack bit-packed indices
fn unpack_bits(data: &[u8], bits: u8, count: usize) -> Vec<u16> {
    let mut indices = Vec::with_capacity(count);
    let mut bit_pos = 0;

    for _ in 0..count {
        let mut val: u16 = 0;
        for b in 0..bits {
            let byte_idx = bit_pos / 8;
            let bit_offset = bit_pos % 8;
            if byte_idx < data.len() && (data[byte_idx] >> bit_offset) & 1 == 1 {
                val |= 1 << b;
            }
            bit_pos += 1;
        }
        indices.push(val);
    }

    indices
}

/// Encoded text chunk with incremental template support
pub struct TextChunkEncoder {
    config: StreamingConfig,
    pub drain: DrainState,
    /// Template ID -> list of variable lists
    template_vars: HashMap<i32, Vec<Vec<String>>>,
    /// Raw lines that didn't match any template
    raw_lines: Vec<String>,
    /// Line order: (template_id, variables) where template_id = -1 means raw
    line_data: Vec<(i32, Vec<String>)>,
    /// Set of template IDs already written in previous chunks
    pub written_template_ids: HashSet<i32>,
}

impl TextChunkEncoder {
    pub fn new(config: StreamingConfig) -> Self {
        Self {
            config: config.clone(),
            drain: DrainState::new(config),
            template_vars: HashMap::new(),
            raw_lines: Vec::new(),
            line_data: Vec::new(),
            written_template_ids: HashSet::new(),
        }
    }

    /// Create from existing drain state (for cross-chunk learning)
    pub fn with_drain(drain: DrainState, config: StreamingConfig) -> Self {
        Self {
            config,
            drain,
            template_vars: HashMap::new(),
            raw_lines: Vec::new(),
            line_data: Vec::new(),
            written_template_ids: HashSet::new(),
        }
    }

    /// Create from existing drain state and written template IDs
    pub fn with_drain_and_written(
        drain: DrainState,
        written_template_ids: HashSet<i32>,
        config: StreamingConfig,
    ) -> Self {
        Self {
            config,
            drain,
            template_vars: HashMap::new(),
            raw_lines: Vec::new(),
            line_data: Vec::new(),
            written_template_ids,
        }
    }

    /// Add a line to the encoder
    pub fn add_line(&mut self, line: &str) {
        let (tid, _template, vars) = self.drain.add_line(line);

        if tid >= 0 && !vars.is_empty() && !(vars.len() == 1 && vars[0] == self.drain.preprocess(line)) {
            // Matched a template
            self.template_vars
                .entry(tid)
                .or_default()
                .push(vars.clone());
            self.line_data.push((tid, vars));
        } else {
            // Raw line
            let processed = self.drain.preprocess(line);
            self.line_data.push((-1, vec![processed]));
        }
    }

    /// Take ownership of the drain state for reuse
    pub fn take_drain(self) -> DrainState {
        self.drain
    }

    /// Get the drain state reference
    pub fn drain(&self) -> &DrainState {
        &self.drain
    }

    /// Get the set of written template IDs (for passing to next chunk)
    pub fn take_written_template_ids(self) -> HashSet<i32> {
        self.written_template_ids
    }

    /// Encode the chunk to bytes (columnar format with incremental templates)
    pub fn encode(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Collect all templates used in this chunk
        let templates = self.drain.get_templates();
        let chunk_templates: HashMap<i32, &str> = templates
            .iter()
            .filter(|(id, _)| self.template_vars.contains_key(&(*id as i32)))
            .map(|(id, tmpl)| (*id as i32, tmpl.as_str()))
            .collect();

        // Write only NEW templates (not already written in previous chunks)
        let mut new_templates: Vec<_> = chunk_templates
            .iter()
            .filter(|(tid, _)| !self.written_template_ids.contains(tid))
            .map(|(tid, tmpl)| (*tid, *tmpl))
            .collect();
        new_templates.sort_by_key(|(tid, _)| *tid);

        varint::write_varint(&mut buf, new_templates.len() as u64).unwrap();
        for (tid, tmpl) in &new_templates {
            varint::write_varint(&mut buf, *tid as u64).unwrap();
            // Convert template to Latin-1 bytes (char U+00XX -> byte 0xXX)
            let tmpl_bytes: Vec<u8> = tmpl.chars().map(|c| c as u8).collect();
            varint::write_varint(&mut buf, tmpl_bytes.len() as u64).unwrap();
            buf.extend_from_slice(&tmpl_bytes);
            self.written_template_ids.insert(*tid);
        }

        // Write template ID mapping for this chunk (ALL templates used)
        let mut template_list: Vec<_> = chunk_templates.keys().copied().collect();
        template_list.sort();

        varint::write_varint(&mut buf, template_list.len() as u64).unwrap();
        for tid in &template_list {
            varint::write_varint(&mut buf, *tid as u64).unwrap();
        }

        // Create local template index (maps global tid to chunk-local index)
        let tid_to_local: HashMap<i32, u16> = template_list
            .iter()
            .enumerate()
            .map(|(i, tid)| (*tid, i as u16))
            .collect();

        // Write line count
        let n_lines = self.line_data.len();
        varint::write_varint(&mut buf, n_lines as u64).unwrap();

        // Column 1: Template indices (bit-packed) - uses local indices
        let mut indices: Vec<u16> = Vec::with_capacity(n_lines);
        for (tid, _) in &self.line_data {
            if *tid < 0 {
                indices.push(0xFFFF); // Raw marker
            } else {
                indices.push(*tid_to_local.get(tid).unwrap_or(&0xFFFF));
            }
        }

        // Bit-pack template indices
        let max_idx = *indices.iter().filter(|&&x| x != 0xFFFF).max().unwrap_or(&0);
        let has_raw = indices.iter().any(|&x| x == 0xFFFF);
        let bits = if has_raw {
            16 // Need 16 bits for 0xFFFF marker
        } else {
            std::cmp::max(1, (max_idx as u32 + 1).next_power_of_two().trailing_zeros() as u8)
        };

        buf.push(bits);
        let packed = pack_bits(&indices, bits);
        varint::write_varint(&mut buf, packed.len() as u64).unwrap();
        buf.extend_from_slice(&packed);

        // Find max variables across all lines
        let max_vars = self.line_data.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
        varint::write_varint(&mut buf, max_vars as u64).unwrap();

        // Column 2+: Variable columns with smart encoding
        for var_idx in 0..max_vars {
            let col_values: Vec<&str> = self.line_data
                .iter()
                .map(|(tid, vars)| {
                    if *tid < 0 {
                        // Raw line - store as first "variable"
                        if var_idx == 0 && !vars.is_empty() {
                            vars[0].as_str()
                        } else {
                            ""
                        }
                    } else if var_idx < vars.len() {
                        vars[var_idx].as_str()
                    } else {
                        ""
                    }
                })
                .collect();

            // Use smart column encoder
            let col_data = SmartColumnEncoder::encode(&col_values);
            varint::write_varint(&mut buf, col_data.len() as u64).unwrap();
            buf.extend_from_slice(&col_data);
        }

        buf
    }
}

/// Text chunk decoder (with support for incremental templates)
pub struct TextChunkDecoder {
    /// Template ID -> template string (accumulated across chunks)
    templates: HashMap<u32, String>,
    /// Template ID -> current row index for reconstruction
    template_row_idx: HashMap<u32, usize>,
    /// Line data: (template_id, variables) - -1 for raw
    line_data: Vec<(i32, Vec<String>)>,
    /// Drain for postprocessing
    drain: DrainState,
}

impl TextChunkDecoder {
    /// Create a new decoder with accumulated templates
    pub fn new(templates: HashMap<u32, String>, config: StreamingConfig) -> Self {
        Self {
            templates,
            template_row_idx: HashMap::new(),
            line_data: Vec::new(),
            drain: DrainState::new(config),
        }
    }

    /// Decode a text chunk from bytes
    pub fn decode(data: &[u8], config: StreamingConfig) -> io::Result<Self> {
        Self::decode_with_templates(data, HashMap::new(), config)
    }

    /// Decode a text chunk with accumulated templates from previous chunks
    pub fn decode_with_templates(
        data: &[u8],
        mut accumulated_templates: HashMap<u32, String>,
        config: StreamingConfig,
    ) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);
        let drain = DrainState::new(config);

        // Read NEW templates for this chunk (incremental)
        let n_new_templates = varint::read_varint(&mut cursor)? as usize;
        for _ in 0..n_new_templates {
            let tid = varint::read_varint(&mut cursor)? as u32;
            let len = varint::read_varint(&mut cursor)? as usize;
            let pos = cursor.position() as usize;
            // Use Latin-1 decoding to preserve all bytes
            let tmpl: String = data[pos..pos + len].iter().map(|&b| b as char).collect();
            cursor.set_position((pos + len) as u64);
            accumulated_templates.insert(tid, tmpl);
        }

        // Read template ID mapping for this chunk
        let n_chunk_templates = varint::read_varint(&mut cursor)? as usize;
        let mut local_to_global: Vec<u32> = Vec::with_capacity(n_chunk_templates);
        for _ in 0..n_chunk_templates {
            let tid = varint::read_varint(&mut cursor)? as u32;
            local_to_global.push(tid);
        }

        // Read line count
        let n_lines = varint::read_varint(&mut cursor)? as usize;

        // Read bit-packed template indices
        let bits = {
            let mut bits_buf = [0u8; 1];
            std::io::Read::read_exact(&mut cursor, &mut bits_buf)?;
            bits_buf[0]
        };
        let packed_len = varint::read_varint(&mut cursor)? as usize;
        let pos = cursor.position() as usize;
        let packed_data = &data[pos..pos + packed_len];
        cursor.set_position((pos + packed_len) as u64);

        let local_indices = unpack_bits(packed_data, bits, n_lines);

        // Read max variables
        let max_vars = varint::read_varint(&mut cursor)? as usize;

        // Read variable columns
        let mut columns: Vec<Vec<String>> = Vec::with_capacity(max_vars);
        for _ in 0..max_vars {
            let col_len = varint::read_varint(&mut cursor)? as usize;
            let pos = cursor.position() as usize;
            let col_data = &data[pos..pos + col_len];
            cursor.set_position((pos + col_len) as u64);

            let values = SmartColumnEncoder::decode(col_data, n_lines)?;
            columns.push(values);
        }

        // Reconstruct line_data
        let mut line_data = Vec::with_capacity(n_lines);
        for i in 0..n_lines {
            let local_idx = local_indices[i];

            if local_idx == 0xFFFF {
                // Raw line
                let raw = if !columns.is_empty() {
                    columns[0].get(i).cloned().unwrap_or_default()
                } else {
                    String::new()
                };
                line_data.push((-1, vec![raw]));
            } else {
                // Template line
                let global_tid = local_to_global.get(local_idx as usize)
                    .copied()
                    .unwrap_or(0);

                let vars: Vec<String> = columns
                    .iter()
                    .map(|col| col.get(i).cloned().unwrap_or_default())
                    .collect();

                line_data.push((global_tid as i32, vars));
            }
        }

        Ok(Self {
            templates: accumulated_templates,
            template_row_idx: HashMap::new(),
            line_data,
            drain,
        })
    }

    /// Get the accumulated templates for passing to next chunk decoder
    pub fn templates(&self) -> &HashMap<u32, String> {
        &self.templates
    }

    /// Reconstruct all lines
    pub fn reconstruct_lines(&mut self) -> Vec<String> {
        let mut lines = Vec::with_capacity(self.line_data.len());

        for (tid, vars) in &self.line_data {
            if *tid < 0 {
                // Raw line
                let processed = vars.first().cloned().unwrap_or_default();
                lines.push(self.drain.postprocess(&processed));
            } else {
                let template_id = *tid as u32;
                let template = self.templates.get(&template_id).cloned().unwrap_or_default();

                // Reconstruct line
                let line = self.drain.reconstruct_line(&template, vars);
                lines.push(line);
            }
        }

        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_pack_unpack() {
        let indices = vec![0u16, 1, 2, 3, 0, 1, 2, 3];
        let packed = pack_bits(&indices, 2);
        let unpacked = unpack_bits(&packed, 2, 8);
        assert_eq!(indices, unpacked);
    }

    #[test]
    fn test_bit_pack_with_raw_marker() {
        let indices = vec![0u16, 0xFFFF, 1, 0xFFFF];
        let packed = pack_bits(&indices, 16);
        let unpacked = unpack_bits(&packed, 16, 4);
        assert_eq!(indices, unpacked);
    }

    #[test]
    fn test_text_encoder_basic() {
        let config = StreamingConfig::default();
        let mut encoder = TextChunkEncoder::new(config.clone());

        encoder.add_line("Error at line 123");
        encoder.add_line("Error at line 456");
        encoder.add_line("Warning: disk full");

        let encoded = encoder.encode();
        assert!(!encoded.is_empty());

        let mut decoder = TextChunkDecoder::decode(&encoded, config).unwrap();
        let lines = decoder.reconstruct_lines();
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn test_text_roundtrip() {
        let config = StreamingConfig::default();
        let mut encoder = TextChunkEncoder::new(config.clone());

        let test_lines = vec![
            "Jun  9 06:06:01 combo sshd(pam_unix)[19939]: session opened",
            "Jun  9 06:06:02 combo sshd(pam_unix)[19939]: session closed",
            "Jun  9 06:06:03 combo sshd(pam_unix)[19940]: session opened",
        ];

        for line in &test_lines {
            encoder.add_line(line);
        }

        let encoded = encoder.encode();
        let mut decoder = TextChunkDecoder::decode(&encoded, config).unwrap();
        let lines = decoder.reconstruct_lines();

        assert_eq!(lines.len(), test_lines.len());
        for (orig, decoded) in test_lines.iter().zip(lines.iter()) {
            assert_eq!(*orig, decoded);
        }
    }

    #[test]
    fn test_incremental_templates() {
        let config = StreamingConfig::default();

        // First chunk
        let drain = DrainState::new(config.clone());
        let mut encoder1 = TextChunkEncoder::with_drain(drain, config.clone());
        encoder1.add_line("Error at line 123");
        encoder1.add_line("Error at line 456");
        let encoded1 = encoder1.encode();

        // Decode first chunk
        let mut decoder1 = TextChunkDecoder::decode(&encoded1, config.clone()).unwrap();
        let lines1 = decoder1.reconstruct_lines();
        assert_eq!(lines1.len(), 2);

        // Second chunk should reuse templates - use public fields
        let drain2 = encoder1.drain.clone();
        let written = encoder1.written_template_ids.clone();
        let mut encoder2 = TextChunkEncoder::with_drain_and_written(drain2, written, config.clone());
        encoder2.add_line("Error at line 789"); // Should reuse template
        let encoded2 = encoder2.encode();

        // Check that second chunk is smaller (no new templates)
        // This is the key optimization!
        let mut decoder2 = TextChunkDecoder::decode_with_templates(
            &encoded2,
            decoder1.templates().clone(),
            config,
        ).unwrap();
        let lines2 = decoder2.reconstruct_lines();
        assert_eq!(lines2.len(), 1);
        assert_eq!(lines2[0], "Error at line 789");
    }
}

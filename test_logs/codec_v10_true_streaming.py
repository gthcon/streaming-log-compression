#!/usr/bin/env python3
"""
V10 True Streaming Codec with Cross-Chunk Learning

Features:
- True zstd streaming via Python zstandard library
- Per-line format detection (JSON vs TEXT interleaved)
- Cross-chunk learning:
  - Drain templates persist across chunks
  - JSON schema/dictionary learning across chunks
- Heuristic-based encoding selection (no trial encoding)
- Configurable chunk sizes, memory limits, flush API
- Adaptive fallback based on compression ratio history

Architecture:
- Each line is classified as JSON or TEXT
- Lines are grouped by format within each chunk
- Learned state (templates, schemas) persists across chunks
- zstd streaming compressor wraps entire output
"""

import io
import json
import struct
import re
from collections import defaultdict
from typing import Optional, List, Dict, Tuple, Any, Iterator
from dataclasses import dataclass, field

import zstandard as zstd

# Try to import drain3 for template mining
try:
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig
    HAS_DRAIN = True
except ImportError:
    HAS_DRAIN = False

# ============================================================================
# Constants
# ============================================================================

MAGIC = b'V10S'  # V10 Streaming
VERSION = 1

# Line format types
FMT_JSON = 0
FMT_TEXT = 1

# Chunk encoding types
CHUNK_RAW = 0
CHUNK_V10_JSON = 1
CHUNK_V10_TEXT = 2
CHUNK_V10_MIXED = 3

# Variable encoding types for JSON columns
VAR_RAW = 0
VAR_DICT = 1
VAR_DELTA_INT = 2
VAR_DELTA_TS = 3

# Smart column encoding types (for TEXT variable columns)
COL_RAW = 0         # Raw newline-separated strings
COL_DICT = 1        # Dictionary encoded (bit-packed indices)
COL_TS_CLF = 2      # CLF timestamp delta encoding
COL_TS_CLF_FRAG = 3 # CLF timestamp fragment (no closing bracket)
COL_TS_ISO = 4      # ISO timestamp delta encoding
COL_PREFIX_ID = 5   # Prefix-ID delta encoding (e.g., "blk-123")
COL_NUMERIC = 6     # Numeric strings as delta integers

# Multi-space marker for text compression
MULTI_SPACE_PREFIX = '•'

# Regex patterns for column type detection
ISO_TIMESTAMP_RE = re.compile(
    r'^"?(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"?,?$'
)
CLF_TIMESTAMP_RE = re.compile(
    r'^\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]?$'
)
PREFIX_ID_RE = re.compile(r'^"?([a-zA-Z][\w-]*)-(\d+)"?,?$')
NUMERIC_STRING_RE = re.compile(r'^-?\d+$')

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
MONTHS_REV = {v:k for k,v in MONTHS.items()}

# ============================================================================
# Configuration
# ============================================================================

@dataclass
class StreamingConfig:
    """Configuration for the streaming codec."""
    # Chunk sizes
    chunk_size: int = 10000  # Lines per chunk
    initial_chunk_size: int = 1000  # Smaller first chunk for faster startup

    # zstd settings
    zstd_level: int = 3
    zstd_long_distance: int = 27  # 128MB window (2^27)

    # Memory limits for learning state
    max_templates: int = 10000  # Max Drain templates to keep
    max_dict_entries: int = 50000  # Max dictionary entries per JSON key
    max_schema_keys: int = 1000  # Max unique JSON keys to track

    # Fallback thresholds
    fallback_ratio_threshold: float = 1.1  # Switch to raw if V10 > 1.1x raw size
    fallback_consecutive_chunks: int = 3  # Need N consecutive bad chunks
    recovery_interval: int = 10  # Try V10 again every N chunks after fallback


# ============================================================================
# Varint encoding (from codec_v10.py)
# ============================================================================

def encode_varint(n: int) -> bytes:
    """Encode integer as variable-length bytes."""
    if n < 0:
        raise ValueError("Varint cannot be negative")
    result = []
    while n >= 0x80:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n)
    return bytes(result)


def decode_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Decode varint, return (value, new_position)."""
    result = 0
    shift = 0
    while True:
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def encode_signed_varint(n: int) -> bytes:
    """Encode signed integer using zigzag encoding."""
    if n >= 0:
        return encode_varint(n * 2)
    else:
        return encode_varint((-n) * 2 - 1)


def decode_signed_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Decode signed varint."""
    val, pos = decode_varint(data, pos)
    if val & 1:
        return -(val + 1) // 2, pos
    else:
        return val // 2, pos


# ============================================================================
# Smart Column Encoding Utilities
# ============================================================================

def parse_clf_timestamp(s: str) -> Tuple[Optional[int], Optional[dict]]:
    """Parse CLF timestamp to seconds since epoch + format info."""
    m = CLF_TIMESTAMP_RE.match(s)
    if not m:
        return None, None

    day = int(m.group(1))
    month = MONTHS.get(m.group(2), 1)
    year = int(m.group(3))
    hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))
    tz = m.group(7) or ''

    # Days since epoch
    days = 0
    for y in range(1970, year):
        days += 366 if (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0) else 365

    DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    for m_idx in range(month - 1):
        days += DAYS_IN_MONTH[m_idx]
        if m_idx == 1 and is_leap:
            days += 1
    days += day - 1

    seconds_val = days * 86400 + hour * 3600 + minute * 60 + second

    format_info = {
        'tz': tz,
        'has_brackets': s.startswith('['),
        'has_close': s.endswith(']'),
    }

    return seconds_val, format_info


def reconstruct_clf_timestamp(seconds_val: int, format_info: dict) -> str:
    """Reconstruct CLF timestamp from seconds value."""
    days = seconds_val // 86400
    rem = seconds_val % 86400
    h = rem // 3600
    rem = rem % 3600
    mi = rem // 60
    s = rem % 60

    DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    year = 1970
    while True:
        is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
        days_in_year = 366 if is_leap else 365
        if days < days_in_year:
            break
        days -= days_in_year
        year += 1

    is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    month = 1
    for m_idx in range(12):
        days_in_month = DAYS_IN_MONTH[m_idx]
        if m_idx == 1 and is_leap:
            days_in_month = 29
        if days < days_in_month:
            month = m_idx + 1
            break
        days -= days_in_month
    else:
        month = 12

    day = days + 1
    month_name = MONTHS_REV.get(month, 'Jan')

    result = f"{day:02d}/{month_name}/{year}:{h:02d}:{mi:02d}:{s:02d}"

    tz = format_info.get('tz', '')
    if tz:
        result += ' ' + tz

    if format_info.get('has_brackets', True):
        result = '[' + result
    if format_info.get('has_close', True):
        result += ']'

    return result


def reconstruct_clf_fragment(seconds_val: int) -> str:
    """Reconstruct CLF timestamp fragment (no closing bracket)."""
    days = seconds_val // 86400
    rem = seconds_val % 86400
    h = rem // 3600
    rem = rem % 3600
    mi = rem // 60
    s = rem % 60

    DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    year = 1970
    while True:
        is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
        days_in_year = 366 if is_leap else 365
        if days < days_in_year:
            break
        days -= days_in_year
        year += 1

    is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    month = 1
    for m_idx in range(12):
        days_in_month = DAYS_IN_MONTH[m_idx]
        if m_idx == 1 and is_leap:
            days_in_month = 29
        if days < days_in_month:
            month = m_idx + 1
            break
        days -= days_in_month
    else:
        month = 12

    day = days + 1
    month_name = MONTHS_REV.get(month, 'Jan')

    return f"[{day:02d}/{month_name}/{year}:{h:02d}:{mi:02d}:{s:02d}"


def analyze_column(values: List[str]) -> str:
    """Analyze column values and return the best encoding type.

    IMPORTANT: Specialized encodings (timestamp, numeric, prefix-ID) require
    ALL values to match the pattern, because non-matching values would be
    corrupted (e.g., parsed as 0). Dictionary encoding is used as fallback.
    """
    # Filter empty values
    present = [v for v in values if v]
    if not present:
        return 'empty'

    # Check for CLF timestamp fragments (e.g., '[01/Jul/1995:00:00:01' without closing bracket)
    # MUST be 100% match to avoid data corruption
    clf_frag_count = 0
    clf_full_count = 0
    for v in present:
        if isinstance(v, str) and v.startswith('['):
            # Try to parse as CLF
            result, fmt = parse_clf_timestamp(v + ']')  # Add closing bracket for parsing
            if result is not None:
                if v.endswith(']'):
                    clf_full_count += 1
                else:
                    clf_frag_count += 1

    # Require 100% match for timestamp encoding (lossy for non-matches)
    if clf_frag_count == len(present):
        return 'timestamp_clf_fragment'
    if clf_full_count == len(present):
        return 'timestamp_clf'

    # Check for prefix-ID pattern (e.g., "blk-123456") - must be 100% match
    if all(isinstance(v, str) and PREFIX_ID_RE.match(v) for v in present):
        return 'prefix_id'

    # Check for numeric strings - must be 100% match AND no leading zeros
    # (leading zeros would be lost when converting to int and back)
    def is_safe_numeric(v):
        if not isinstance(v, str) or not NUMERIC_STRING_RE.match(v):
            return False
        # Reject values with leading zeros (except "0" itself)
        if v.startswith('0') and len(v) > 1 and v[1] != '-':
            return False
        return True

    if all(is_safe_numeric(v) for v in present):
        return 'numeric_string'

    # Check cardinality for dictionary encoding (lossless, safe for mixed data)
    unique = set(values)
    if len(unique) <= 256:  # Low cardinality - dictionary encode
        return 'low_cardinality'

    return 'general'


def encode_smart_column(output: io.BytesIO, values: List[str], n_rows: int) -> None:
    """Encode a column using the best encoding strategy."""
    if not values:
        output.write(bytes([COL_RAW]))
        output.write(encode_varint(0))
        return

    col_type = analyze_column(values)

    # Timestamp CLF fragment encoding
    if col_type == 'timestamp_clf_fragment':
        output.write(bytes([COL_TS_CLF_FRAG]))
        encode_timestamp_fragment_column(output, values)
        return

    # Timestamp CLF full encoding
    if col_type == 'timestamp_clf':
        output.write(bytes([COL_TS_CLF]))
        encode_timestamp_clf_column(output, values)
        return

    # Prefix-ID delta encoding
    if col_type == 'prefix_id':
        output.write(bytes([COL_PREFIX_ID]))
        encode_prefix_id_column(output, values)
        return

    # Numeric string encoding
    if col_type == 'numeric_string':
        output.write(bytes([COL_NUMERIC]))
        encode_numeric_column(output, values)
        return

    # Dictionary encoding for low cardinality
    if col_type == 'low_cardinality':
        output.write(bytes([COL_DICT]))
        encode_dict_column(output, values)
        return

    # Default: raw newline-separated
    output.write(bytes([COL_RAW]))
    col_data = '\n'.join(values).encode('utf-8')
    output.write(encode_varint(len(col_data)))
    output.write(col_data)


def encode_timestamp_fragment_column(output: io.BytesIO, values: List[str]) -> None:
    """Encode CLF timestamp fragments using delta encoding."""
    ts_values = []
    for v in values:
        if isinstance(v, str) and v.startswith('['):
            result, _ = parse_clf_timestamp(v + ']')
            ts_values.append(result if result is not None else 0)
        else:
            ts_values.append(0)

    # Frame-of-reference encoding
    min_val = min(ts_values) if ts_values else 0
    output.write(encode_varint(min_val))

    # Delta encode from minimum
    for val in ts_values:
        output.write(encode_varint(val - min_val))


def encode_timestamp_clf_column(output: io.BytesIO, values: List[str]) -> None:
    """Encode full CLF timestamps using delta encoding."""
    ts_values = []
    formats = []
    for v in values:
        result, fmt = parse_clf_timestamp(v) if isinstance(v, str) else (None, None)
        ts_values.append(result if result is not None else 0)
        formats.append(fmt if fmt else {})

    # Frame-of-reference encoding
    min_val = min(ts_values) if ts_values else 0
    output.write(encode_varint(min_val))

    # Delta encode from minimum
    for val in ts_values:
        output.write(encode_varint(val - min_val))

    # Store common format (most formats are the same)
    from collections import Counter
    format_strs = [json.dumps(f, sort_keys=True) for f in formats]
    common_format = Counter(format_strs).most_common(1)[0][0] if format_strs else '{}'
    format_bytes = common_format.encode('utf-8')
    output.write(encode_varint(len(format_bytes)))
    output.write(format_bytes)


def encode_prefix_id_column(output: io.BytesIO, values: List[str]) -> None:
    """Encode prefix-ID values (e.g., 'blk-123') using delta encoding."""
    prefix = None
    numbers = []

    for v in values:
        m = PREFIX_ID_RE.match(v) if v else None
        if m:
            if prefix is None:
                prefix = m.group(1)
            numbers.append(int(m.group(2)))
        else:
            numbers.append(0)

    prefix_bytes = (prefix or '').encode('utf-8')
    output.write(encode_varint(len(prefix_bytes)))
    output.write(prefix_bytes)

    # Delta encode numbers
    prev = 0
    for n in numbers:
        output.write(encode_signed_varint(n - prev))
        prev = n


def encode_numeric_column(output: io.BytesIO, values: List[str]) -> None:
    """Encode numeric string values using delta encoding."""
    int_vals = []
    for v in values:
        try:
            int_vals.append(int(v))
        except (ValueError, TypeError):
            int_vals.append(0)

    # Delta encode
    prev = 0
    for val in int_vals:
        output.write(encode_signed_varint(val - prev))
        prev = val


def encode_dict_column(output: io.BytesIO, values: List[str]) -> None:
    """Encode column using dictionary compression with bit-packing."""
    unique = sorted(set(values))
    vocab = {v: i for i, v in enumerate(unique)}

    # Write dictionary
    output.write(encode_varint(len(unique)))
    for word in unique:
        word_bytes = word.encode('utf-8')
        output.write(encode_varint(len(word_bytes)))
        output.write(word_bytes)

    # Bit-pack indices
    bits = max(1, (len(unique) - 1).bit_length()) if unique else 1
    indices = [vocab.get(v, 0) for v in values]
    packed = pack_bits_simple(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)


def pack_bits_simple(values: List[int], bits_per_value: int) -> bytes:
    """Simple bit-packing implementation."""
    if not values or bits_per_value == 0:
        return b''

    result = bytearray()
    buffer = 0
    bits_in_buffer = 0

    for v in values:
        buffer |= (v << bits_in_buffer)
        bits_in_buffer += bits_per_value

        while bits_in_buffer >= 8:
            result.append(buffer & 0xFF)
            buffer >>= 8
            bits_in_buffer -= 8

    if bits_in_buffer > 0:
        result.append(buffer & 0xFF)

    return bytes(result)


def unpack_bits_simple(data: bytes, count: int, bits_per_value: int) -> List[int]:
    """Simple bit-unpacking implementation."""
    if not data or bits_per_value == 0 or count == 0:
        return [0] * count

    result = []
    buffer = 0
    bits_in_buffer = 0
    pos = 0
    mask = (1 << bits_per_value) - 1

    for _ in range(count):
        while bits_in_buffer < bits_per_value and pos < len(data):
            buffer |= data[pos] << bits_in_buffer
            pos += 1
            bits_in_buffer += 8

        result.append(buffer & mask)
        buffer >>= bits_per_value
        bits_in_buffer -= bits_per_value

    return result


def decode_smart_column(data: bytes, pos: int, n_rows: int) -> Tuple[List[str], int]:
    """Decode a smart-encoded column."""
    enc_type = data[pos]
    pos += 1

    if enc_type == COL_RAW:
        col_len, pos = decode_varint(data, pos)
        col_data = data[pos:pos+col_len].decode('utf-8')
        pos += col_len
        return col_data.split('\n'), pos

    if enc_type == COL_TS_CLF_FRAG:
        return decode_timestamp_fragment_column(data, pos, n_rows)

    if enc_type == COL_TS_CLF:
        return decode_timestamp_clf_column(data, pos, n_rows)

    if enc_type == COL_PREFIX_ID:
        return decode_prefix_id_column(data, pos, n_rows)

    if enc_type == COL_NUMERIC:
        return decode_numeric_column(data, pos, n_rows)

    if enc_type == COL_DICT:
        return decode_dict_column_smart(data, pos, n_rows)

    # Fallback - shouldn't happen
    return [''] * n_rows, pos


def decode_timestamp_fragment_column(data: bytes, pos: int, n_rows: int) -> Tuple[List[str], int]:
    """Decode CLF timestamp fragment column."""
    min_val, pos = decode_varint(data, pos)

    values = []
    for _ in range(n_rows):
        offset, pos = decode_varint(data, pos)
        seconds_val = min_val + offset
        values.append(reconstruct_clf_fragment(seconds_val))

    return values, pos


def decode_timestamp_clf_column(data: bytes, pos: int, n_rows: int) -> Tuple[List[str], int]:
    """Decode full CLF timestamp column."""
    min_val, pos = decode_varint(data, pos)

    ts_values = []
    for _ in range(n_rows):
        offset, pos = decode_varint(data, pos)
        ts_values.append(min_val + offset)

    # Read format info
    format_len, pos = decode_varint(data, pos)
    format_info = json.loads(data[pos:pos+format_len].decode('utf-8'))
    pos += format_len

    values = [reconstruct_clf_timestamp(v, format_info) for v in ts_values]
    return values, pos


def decode_prefix_id_column(data: bytes, pos: int, n_rows: int) -> Tuple[List[str], int]:
    """Decode prefix-ID column."""
    prefix_len, pos = decode_varint(data, pos)
    prefix = data[pos:pos+prefix_len].decode('utf-8')
    pos += prefix_len

    result = []
    prev = 0
    for _ in range(n_rows):
        delta, pos = decode_signed_varint(data, pos)
        prev += delta
        result.append(f"{prefix}-{prev}" if prefix else str(prev))

    return result, pos


def decode_numeric_column(data: bytes, pos: int, n_rows: int) -> Tuple[List[str], int]:
    """Decode numeric string column."""
    result = []
    prev = 0
    for _ in range(n_rows):
        delta, pos = decode_signed_varint(data, pos)
        prev += delta
        result.append(str(prev))

    return result, pos


def decode_dict_column_smart(data: bytes, pos: int, n_rows: int) -> Tuple[List[str], int]:
    """Decode dictionary-encoded column."""
    vocab_size, pos = decode_varint(data, pos)
    vocab = []
    for _ in range(vocab_size):
        word_len, pos = decode_varint(data, pos)
        word = data[pos:pos+word_len].decode('utf-8')
        pos += word_len
        vocab.append(word)

    bits = data[pos]
    pos += 1
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len

    indices = unpack_bits_simple(packed, n_rows, bits)
    return [vocab[i] if i < len(vocab) else '' for i in indices], pos


# ============================================================================
# Line Format Detection
# ============================================================================

def is_json_line(line: str) -> bool:
    """Check if line is valid JSON (object or array)."""
    if not line:
        return False
    stripped = line.strip()
    if not stripped:
        return False
    first_char = stripped[0]

    # Quick rejection for non-JSON starters
    if first_char not in ('{', '['):
        return False

    # For objects, check matching braces
    if first_char == '{':
        if not stripped.endswith('}'):
            return False
    elif first_char == '[':
        if not stripped.endswith(']'):
            return False
        # Additional heuristic: real JSON arrays usually have commas or are empty
        # Log lines like "[timestamp] [level]..." don't have JSON structure
        # Check for JSON array patterns: [], ["..."], [123], [true], etc.
        inner = stripped[1:-1].strip()
        if inner:
            # If first char after [ is not a valid JSON value start, not JSON
            if inner[0] not in ('"', "'", '[', '{', 't', 'f', 'n', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'):
                return False

    # Try actual JSON parsing (not too expensive for short lines)
    # Only do this for lines that pass heuristics
    try:
        json.loads(stripped)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def classify_line(line: str) -> int:
    """Classify a line as JSON or TEXT."""
    return FMT_JSON if is_json_line(line) else FMT_TEXT


# ============================================================================
# Drain Template Mining (Cross-chunk learning)
# ============================================================================

class DrainState:
    """Persistent Drain state for cross-chunk learning."""

    def __init__(self, config: StreamingConfig):
        self.config = config
        self.miner: Optional[TemplateMiner] = None
        self.template_cache: Dict[int, str] = {}  # cluster_id -> template
        self.template_to_id: Dict[str, int] = {}  # template -> output_id
        self.next_template_id = 0

        if HAS_DRAIN:
            self._init_miner()

    def _init_miner(self):
        """Initialize Drain miner with config."""
        miner_config = TemplateMinerConfig()
        miner_config.load("""
[MASKING]
[DRAIN]
sim_th = 0.4
depth = 4
max_children = 100
""")
        self.miner = TemplateMiner(config=miner_config)

    def add_line(self, line: str) -> Tuple[int, str, List[str]]:
        """
        Add a line to Drain, return (template_id, template, variables).
        Template ID is stable across chunks.
        """
        if not self.miner or not line.strip():
            return -1, "", [line]

        # Preprocess multi-space
        processed = self._preprocess(line)

        # Mine template
        result = self.miner.add_log_message(processed)
        if not result:
            return -1, "", [line]

        cluster_id = result['cluster_id']

        # Get template from the cluster (not from result dict - it may be empty on first line)
        # Find the cluster and get its current template
        cluster = None
        for c in self.miner.drain.clusters:
            if c.cluster_id == cluster_id:
                cluster = c
                break

        if not cluster:
            return -1, "", [line]

        # Get the template (which updates as Drain learns)
        template = cluster.get_template()

        # Update cache and assign stable ID
        self.template_cache[cluster_id] = template

        if template not in self.template_to_id:
            if self.next_template_id < self.config.max_templates:
                self.template_to_id[template] = self.next_template_id
                self.next_template_id += 1

        template_id = self.template_to_id.get(template, -1)

        # Extract variables
        variables = self._extract_variables(processed, template)

        return template_id, template, variables

    def _preprocess(self, line: str) -> str:
        """Compress multi-space sequences, handle leading tabs and trailing spaces."""
        # Handle leading tabs (Drain strips them)
        leading_tabs = 0
        while line and line[0] == '\t':
            leading_tabs += 1
            line = line[1:]

        # Handle trailing spaces (Drain strips them)
        trailing = 0
        while line and line[-1] == ' ':
            trailing += 1
            line = line[:-1]

        def replace_spaces(match):
            count = len(match.group(0))
            if count <= 9:
                return MULTI_SPACE_PREFIX + str(count)
            result = []
            while count > 0:
                chunk = min(count, 9)
                result.append(MULTI_SPACE_PREFIX + str(chunk))
                count -= chunk
            return ''.join(result)

        line = re.sub(r'  +', replace_spaces, line)

        # Add leading tab marker (using T prefix)
        if leading_tabs > 0:
            line = MULTI_SPACE_PREFIX + 'T' + str(leading_tabs) + MULTI_SPACE_PREFIX + line

        # Add trailing space marker
        if trailing > 0:
            while trailing > 0:
                chunk = min(trailing, 9)
                line += MULTI_SPACE_PREFIX + str(chunk)
                trailing -= chunk

        return line

    def _postprocess(self, line: str) -> str:
        """Restore multi-space sequences, leading tabs, and trailing spaces."""
        # Restore leading tabs (format: •T<count>•)
        tab_pattern = MULTI_SPACE_PREFIX + r'T(\d)' + MULTI_SPACE_PREFIX
        m = re.match(tab_pattern, line)
        if m:
            tabs = '\t' * int(m.group(1))
            line = tabs + line[m.end():]

        # Restore multi-spaces (format: •<count>)
        def restore_spaces(match):
            return ' ' * int(match.group(1))
        while MULTI_SPACE_PREFIX in line:
            line = re.sub(MULTI_SPACE_PREFIX + r'(\d)', restore_spaces, line)
        return line

    def _extract_variables(self, line: str, template: str) -> List[str]:
        """Extract variable values from line using template."""
        if not template:
            return [line]

        parts = template.split('<*>')
        if len(parts) == 1:
            return [] if template == line else [line]

        variables = []
        remaining = line

        for i, part in enumerate(parts):
            if not part:
                continue
            idx = remaining.find(part)
            if idx == -1:
                return [line]  # Mismatch, return raw
            if idx > 0:
                variables.append(remaining[:idx])
            remaining = remaining[idx + len(part):]

        if remaining:
            variables.append(remaining)

        return variables

    def reconstruct_line(self, template: str, variables: List[str]) -> str:
        """Reconstruct line from template and variables."""
        if not template:
            return variables[0] if variables else ""

        parts = template.split('<*>')
        if len(parts) == 1:
            return template if not variables else variables[0]

        result = []
        var_idx = 0
        for i, part in enumerate(parts):
            if i > 0 and var_idx < len(variables):
                result.append(variables[var_idx])
                var_idx += 1
            result.append(part)

        if var_idx < len(variables):
            result.append(variables[var_idx])

        reconstructed = ''.join(result)
        return self._postprocess(reconstructed)

    def get_templates_for_encoding(self) -> List[Tuple[int, str]]:
        """Get list of (id, template) for encoding in chunk header."""
        return [(tid, tmpl) for tmpl, tid in self.template_to_id.items()]

    def memory_usage(self) -> int:
        """Estimate memory usage in bytes."""
        size = 0
        for tmpl in self.template_to_id:
            size += len(tmpl) * 2  # Approximate
        return size


# ============================================================================
# JSON Schema Learning (Cross-chunk learning)
# ============================================================================

class JSONSchemaState:
    """Persistent JSON schema state for cross-chunk learning."""

    def __init__(self, config: StreamingConfig):
        self.config = config

        # Key tracking
        self.all_keys: Dict[str, int] = {}  # key_path -> key_id
        self.next_key_id = 0

        # Per-key dictionaries for string values
        self.key_dicts: Dict[str, Dict[str, int]] = defaultdict(dict)  # key -> {value -> id}
        self.key_dict_next_id: Dict[str, int] = defaultdict(int)

        # Value type statistics per key (for heuristic encoding selection)
        self.key_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # key -> {'int': count, 'str': count, 'null': count, ...}

        # Compression ratio history
        self.ratio_history: List[float] = []

    def register_key(self, key_path: str) -> int:
        """Register a key path, return stable ID."""
        if key_path not in self.all_keys:
            if self.next_key_id < self.config.max_schema_keys:
                self.all_keys[key_path] = self.next_key_id
                self.next_key_id += 1
            else:
                return -1  # Too many keys
        return self.all_keys[key_path]

    def register_string_value(self, key_path: str, value: str) -> int:
        """Register a string value for dictionary encoding, return ID."""
        key_dict = self.key_dicts[key_path]

        if value not in key_dict:
            if self.key_dict_next_id[key_path] < self.config.max_dict_entries:
                key_dict[value] = self.key_dict_next_id[key_path]
                self.key_dict_next_id[key_path] += 1
            else:
                return -1  # Dictionary full

        return key_dict[value]

    def update_stats(self, key_path: str, value_type: str):
        """Update statistics for a key."""
        self.key_stats[key_path][value_type] += 1

    def get_encoding_hint(self, key_path: str) -> str:
        """Get heuristic encoding hint for a key based on history."""
        stats = self.key_stats.get(key_path, {})
        if not stats:
            return 'raw'

        total = sum(stats.values())
        if total < 10:
            return 'raw'  # Not enough data

        # If mostly integers, suggest delta encoding
        if stats.get('int', 0) / total > 0.8:
            return 'delta_int'

        # If mostly strings with low cardinality, suggest dictionary
        if stats.get('str', 0) / total > 0.5:
            dict_size = len(self.key_dicts.get(key_path, {}))
            if dict_size < 1000 and dict_size > 0:
                return 'dict'

        return 'raw'

    def add_ratio_sample(self, ratio: float):
        """Add compression ratio sample for fallback decision."""
        self.ratio_history.append(ratio)
        # Keep last 20 samples
        if len(self.ratio_history) > 20:
            self.ratio_history = self.ratio_history[-20:]

    def should_use_raw(self) -> bool:
        """Check if we should fall back to raw based on history."""
        if len(self.ratio_history) < 3:
            return False

        # Check last 3 ratios
        recent = self.ratio_history[-3:]
        return all(r > 1.1 for r in recent)  # V10 worse than raw

    def memory_usage(self) -> int:
        """Estimate memory usage in bytes."""
        size = len(self.all_keys) * 50  # Approximate key path size
        for key, d in self.key_dicts.items():
            for v in d:
                size += len(v) * 2
        return size


# ============================================================================
# Streaming Encoder
# ============================================================================

class StreamingEncoder:
    """
    True streaming V10 encoder with cross-chunk learning.

    Usage:
        encoder = StreamingEncoder(output_file, config)
        for line in lines:
            encoder.add_line(line)
        encoder.finish()
    """

    def __init__(self, output: io.BufferedWriter, config: Optional[StreamingConfig] = None):
        self.config = config or StreamingConfig()
        self.output = output

        # zstd streaming compressor
        params = zstd.ZstdCompressionParameters.from_level(
            self.config.zstd_level,
            window_log=self.config.zstd_long_distance
        )
        self.compressor = zstd.ZstdCompressor(compression_params=params)
        self.zstd_stream = self.compressor.stream_writer(output, closefd=False)

        # Learning state (persists across chunks)
        self.drain_state = DrainState(self.config)
        self.json_state = JSONSchemaState(self.config)

        # Current chunk buffer
        self.chunk_lines: List[str] = []
        self.chunk_formats: List[int] = []  # FMT_JSON or FMT_TEXT per line
        self.chunk_number = 0

        # Stats
        self.total_lines = 0
        self.total_raw_bytes = 0
        self.total_encoded_bytes = 0

        # Fallback state
        self.use_raw_json = False
        self.use_raw_text = False
        self.chunks_since_fallback = 0

        # Write header
        self._write_header()

    def _write_header(self):
        """Write stream header."""
        header = io.BytesIO()
        header.write(MAGIC)
        header.write(bytes([VERSION]))

        # Config info for decoder
        header.write(encode_varint(self.config.chunk_size))
        header.write(encode_varint(self.config.initial_chunk_size))
        header.write(encode_varint(self.config.zstd_level))
        header.write(encode_varint(self.config.zstd_long_distance))

        self.zstd_stream.write(header.getvalue())

    def add_line(self, line: str):
        """Add a line to the stream."""
        self.total_lines += 1
        self.total_raw_bytes += len(line.encode('utf-8')) + 1  # +1 for newline

        # Classify line
        fmt = classify_line(line)
        self.chunk_lines.append(line)
        self.chunk_formats.append(fmt)

        # Learn from line (even if we'll encode as raw later)
        if fmt == FMT_JSON:
            self._learn_json(line)
        else:
            self._learn_text(line)

        # Check if chunk is full
        target_size = (self.config.initial_chunk_size if self.chunk_number == 0
                       else self.config.chunk_size)
        if len(self.chunk_lines) >= target_size:
            self._flush_chunk()

    def _learn_json(self, line: str):
        """Learn from JSON line (update schema state)."""
        try:
            obj = json.loads(line)
            self._learn_json_object(obj, "")
        except json.JSONDecodeError:
            pass

    def _learn_json_object(self, obj: Any, prefix: str):
        """Recursively learn from JSON object."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_path = f"{prefix}.{key}" if prefix else key
                self.json_state.register_key(key_path)
                self._learn_json_value(key_path, value)
                if isinstance(value, dict):
                    self._learn_json_object(value, key_path)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            self._learn_json_object(item, key_path)

    def _learn_json_value(self, key_path: str, value: Any):
        """Learn value type and potentially dictionary-encode strings."""
        if value is None:
            self.json_state.update_stats(key_path, 'null')
        elif isinstance(value, bool):
            self.json_state.update_stats(key_path, 'bool')
        elif isinstance(value, int):
            self.json_state.update_stats(key_path, 'int')
        elif isinstance(value, float):
            self.json_state.update_stats(key_path, 'float')
        elif isinstance(value, str):
            self.json_state.update_stats(key_path, 'str')
            # Register for dictionary if short enough
            if len(value) < 200:
                self.json_state.register_string_value(key_path, value)
        elif isinstance(value, list):
            self.json_state.update_stats(key_path, 'list')
        elif isinstance(value, dict):
            self.json_state.update_stats(key_path, 'dict')

    def _learn_text(self, line: str):
        """Learn from text line (update Drain state)."""
        if HAS_DRAIN:
            self.drain_state.add_line(line)

    def flush(self):
        """Flush current buffer (for reader catch-up)."""
        if self.chunk_lines:
            self._flush_chunk()
        self.zstd_stream.flush()

    def _flush_chunk(self):
        """Encode and write current chunk."""
        if not self.chunk_lines:
            return

        chunk_data = self._encode_chunk()
        self.total_encoded_bytes += len(chunk_data)

        # Write chunk length + data
        self.zstd_stream.write(encode_varint(len(chunk_data)))
        self.zstd_stream.write(chunk_data)

        # Update fallback state
        self._update_fallback_state()

        # Clear buffer
        self.chunk_lines = []
        self.chunk_formats = []
        self.chunk_number += 1

    def _encode_chunk(self) -> bytes:
        """Encode current chunk, return bytes."""
        output = io.BytesIO()

        n_lines = len(self.chunk_lines)
        output.write(encode_varint(n_lines))

        # Separate JSON and TEXT lines with their indices
        json_indices = []
        json_lines = []
        text_indices = []
        text_lines = []

        for i, (line, fmt) in enumerate(zip(self.chunk_lines, self.chunk_formats)):
            if fmt == FMT_JSON:
                json_indices.append(i)
                json_lines.append(line)
            else:
                text_indices.append(i)
                text_lines.append(line)

        # Write format bitmap (which lines are JSON)
        # Encode as runs for efficiency
        self._write_format_bitmap(output, self.chunk_formats)

        # Encode JSON lines
        if json_lines:
            json_encoded = self._encode_json_lines(json_lines)
            output.write(encode_varint(len(json_encoded)))
            output.write(json_encoded)
        else:
            output.write(encode_varint(0))

        # Encode TEXT lines
        if text_lines:
            text_encoded = self._encode_text_lines(text_lines)
            output.write(encode_varint(len(text_encoded)))
            output.write(text_encoded)
        else:
            output.write(encode_varint(0))

        return output.getvalue()

    def _write_format_bitmap(self, output: io.BytesIO, formats: List[int]):
        """Write format bitmap as run-length encoded."""
        if not formats:
            output.write(encode_varint(0))
            return

        # Run-length encode: (format, count) pairs
        runs = []
        current_fmt = formats[0]
        count = 1

        for fmt in formats[1:]:
            if fmt == current_fmt:
                count += 1
            else:
                runs.append((current_fmt, count))
                current_fmt = fmt
                count = 1
        runs.append((current_fmt, count))

        output.write(encode_varint(len(runs)))
        for fmt, cnt in runs:
            output.write(bytes([fmt]))
            output.write(encode_varint(cnt))

    def _encode_json_lines(self, lines: List[str]) -> bytes:
        """Encode JSON lines using learned schema."""
        output = io.BytesIO()

        # Check if we should use raw
        if self.use_raw_json or not lines:
            output.write(bytes([CHUNK_RAW]))
            for line in lines:
                line_bytes = line.encode('utf-8')
                output.write(encode_varint(len(line_bytes)))
                output.write(line_bytes)
            return output.getvalue()

        # Try columnar encoding
        try:
            columnar = self._encode_json_columnar(lines)
            raw_size = sum(len(line.encode('utf-8')) + 1 for line in lines)

            if len(columnar) < raw_size:
                output.write(bytes([CHUNK_V10_JSON]))
                output.write(columnar)
                self.json_state.add_ratio_sample(len(columnar) / raw_size)
            else:
                output.write(bytes([CHUNK_RAW]))
                for line in lines:
                    line_bytes = line.encode('utf-8')
                    output.write(encode_varint(len(line_bytes)))
                    output.write(line_bytes)
                self.json_state.add_ratio_sample(1.0)
        except Exception:
            # Fallback to raw on any error
            output.write(bytes([CHUNK_RAW]))
            for line in lines:
                line_bytes = line.encode('utf-8')
                output.write(encode_varint(len(line_bytes)))
                output.write(line_bytes)

        return output.getvalue()

    def _encode_json_columnar(self, lines: List[str]) -> bytes:
        """Encode JSON lines in columnar format."""
        output = io.BytesIO()

        # Parse all lines
        objects = []
        row_keys = []  # Per-row key order
        all_keys = set()

        for line in lines:
            try:
                obj = json.loads(line)
                objects.append(obj)
                if isinstance(obj, dict):
                    keys = list(obj.keys())
                    row_keys.append(keys)
                    all_keys.update(keys)
                else:
                    row_keys.append([])
            except json.JSONDecodeError:
                objects.append(None)
                row_keys.append([])

        # Sort keys for consistent ordering
        sorted_keys = sorted(all_keys)
        key_to_idx = {k: i for i, k in enumerate(sorted_keys)}

        # Write number of keys
        output.write(encode_varint(len(sorted_keys)))

        # Write key names
        for key in sorted_keys:
            key_bytes = key.encode('utf-8')
            output.write(encode_varint(len(key_bytes)))
            output.write(key_bytes)

        # Write per-row key order indices (for lossless reconstruction)
        for keys in row_keys:
            output.write(encode_varint(len(keys)))
            for k in keys:
                output.write(encode_varint(key_to_idx.get(k, 0)))

        # Write columns
        for key in sorted_keys:
            values = []
            for obj in objects:
                if isinstance(obj, dict) and key in obj:
                    values.append(obj[key])
                else:
                    values.append('_ABSENT_')

            self._encode_column(output, key, values)

        return output.getvalue()

    def _encode_column(self, output: io.BytesIO, key: str, values: List[Any]):
        """Encode a single column with heuristic-based encoding."""
        # Get encoding hint from learned state
        hint = self.json_state.get_encoding_hint(key)

        # Serialize values to strings first
        str_values = []
        for v in values:
            if v == '_ABSENT_':
                str_values.append('_ABSENT_')
            elif v is None:
                str_values.append('null')
            elif isinstance(v, bool):
                str_values.append('true' if v else 'false')
            elif isinstance(v, (int, float)):
                str_values.append(json.dumps(v))
            elif isinstance(v, str):
                str_values.append(json.dumps(v, ensure_ascii=False))
            else:
                str_values.append(json.dumps(v, separators=(',', ':'), ensure_ascii=False))

        # Try dictionary encoding if hinted
        if hint == 'dict':
            unique = set(str_values)
            if len(unique) < len(str_values) * 0.5:  # <50% unique
                self._encode_column_dict(output, str_values)
                return

        # Try delta int encoding if hinted
        if hint == 'delta_int':
            try:
                int_values = []
                for v in values:
                    if v == '_ABSENT_':
                        int_values.append(None)
                    elif isinstance(v, int):
                        int_values.append(v)
                    else:
                        raise ValueError("Not all ints")

                if all(x is not None for x in int_values):
                    self._encode_column_delta_int(output, int_values)
                    return
            except (ValueError, TypeError):
                pass

        # Default to raw encoding
        self._encode_column_raw(output, str_values)

    def _encode_column_raw(self, output: io.BytesIO, values: List[str]):
        """Raw column encoding."""
        output.write(bytes([VAR_RAW]))
        for v in values:
            v_bytes = v.encode('utf-8')
            output.write(encode_varint(len(v_bytes)))
            output.write(v_bytes)

    def _encode_column_dict(self, output: io.BytesIO, values: List[str]):
        """Dictionary column encoding."""
        output.write(bytes([VAR_DICT]))

        # Build dictionary
        unique = sorted(set(values))
        val_to_idx = {v: i for i, v in enumerate(unique)}

        # Write dictionary
        output.write(encode_varint(len(unique)))
        for v in unique:
            v_bytes = v.encode('utf-8')
            output.write(encode_varint(len(v_bytes)))
            output.write(v_bytes)

        # Write indices
        bits = max(1, len(unique).bit_length())
        packed = self._pack_bits([val_to_idx[v] for v in values], bits)
        output.write(encode_varint(bits))
        output.write(encode_varint(len(packed)))
        output.write(packed)

    def _encode_column_delta_int(self, output: io.BytesIO, values: List[int]):
        """Delta integer column encoding."""
        output.write(bytes([VAR_DELTA_INT]))

        if not values:
            output.write(encode_varint(0))
            return

        # Write first value
        output.write(encode_signed_varint(values[0]))

        # Write deltas
        prev = values[0]
        for v in values[1:]:
            output.write(encode_signed_varint(v - prev))
            prev = v

    def _pack_bits(self, values: List[int], bits: int) -> bytes:
        """Pack values into bit-packed bytes."""
        if bits == 0:
            return b''

        total_bits = len(values) * bits
        n_bytes = (total_bits + 7) // 8
        result = bytearray(n_bytes)

        bit_pos = 0
        for val in values:
            byte_idx = bit_pos // 8
            bit_offset = bit_pos % 8

            # Write bits across bytes
            remaining_bits = bits
            while remaining_bits > 0:
                space_in_byte = 8 - bit_offset
                bits_to_write = min(remaining_bits, space_in_byte)
                mask = (1 << bits_to_write) - 1
                result[byte_idx] |= (val & mask) << bit_offset
                val >>= bits_to_write
                remaining_bits -= bits_to_write
                byte_idx += 1
                bit_offset = 0

            bit_pos += bits

        return bytes(result)

    def _encode_raw_text(self, lines: List[str]) -> bytes:
        """Encode text lines as raw."""
        output = io.BytesIO()
        output.write(bytes([CHUNK_RAW]))
        for line in lines:
            line_bytes = line.encode('utf-8')
            output.write(encode_varint(len(line_bytes)))
            output.write(line_bytes)
        return output.getvalue()

    def _encode_text_v10(self, lines: List[str]) -> bytes:
        """Encode text lines using Drain templates (V10 format).

        Uses persistent miner for cross-chunk learning. Templates improve
        as more data is processed, leading to better compression over time.
        """
        output = io.BytesIO()
        output.write(bytes([CHUNK_V10_TEXT]))

        # Use persistent miner for cross-chunk learning
        miner = self.drain_state.miner

        # First pass: mine all templates with persistent miner
        line_clusters: List[Tuple[int, str]] = []  # (cluster_id, preprocessed_line)
        for line in lines:
            if not line.strip():
                line_clusters.append((-1, line))
                continue

            processed = self.drain_state._preprocess(line)
            result = miner.add_log_message(processed)
            if result:
                line_clusters.append((result['cluster_id'], processed))
            else:
                line_clusters.append((-1, line))

        # Get FINAL templates after processing all lines in this chunk
        # (templates may have evolved during processing)
        final_templates: Dict[int, str] = {}
        for c in miner.drain.clusters:
            final_templates[c.cluster_id] = c.get_template()

        # Second pass: extract variables using final templates
        chunk_templates: Dict[int, str] = {}
        template_data: List[Tuple[int, List[str]]] = []

        for cluster_id, processed in line_clusters:
            if cluster_id < 0:
                template_data.append((-1, [processed]))
                continue

            template = final_templates.get(cluster_id, '')
            if not template:
                template_data.append((-1, [processed]))
                continue

            # Extract variables using final template
            variables = self.drain_state._extract_variables(processed, template)

            # Get stable template ID (use global state for cross-chunk consistency)
            if template not in self.drain_state.template_to_id:
                if self.drain_state.next_template_id < self.config.max_templates:
                    self.drain_state.template_to_id[template] = self.drain_state.next_template_id
                    self.drain_state.next_template_id += 1

            tid = self.drain_state.template_to_id.get(template, -1)
            if tid >= 0:
                chunk_templates[tid] = template
                template_data.append((tid, variables))
            else:
                template_data.append((-1, [processed]))

        # Write templates used in this chunk
        template_list = sorted(chunk_templates.items())
        output.write(encode_varint(len(template_list)))
        for tid, template in template_list:
            output.write(encode_varint(tid))
            tmpl_bytes = template.encode('utf-8')
            output.write(encode_varint(len(tmpl_bytes)))
            output.write(tmpl_bytes)

        # Create local template index
        tid_to_local = {tid: i for i, (tid, _) in enumerate(template_list)}

        # COLUMNAR encoding for better compression
        n_lines = len(template_data)
        output.write(encode_varint(n_lines))

        # Column 1: Template indices (bit-packed)
        indices = []
        for tid, variables in template_data:
            if tid < 0:
                indices.append(0xFFFF)  # Raw marker
            else:
                indices.append(tid_to_local.get(tid, 0xFFFF))

        # Bit-pack template indices
        max_idx = max(indices) if indices else 0
        bits = max(1, max_idx.bit_length()) if max_idx < 0xFFFF else 16
        output.write(bytes([bits]))
        packed = self._pack_bits(indices, bits)
        output.write(encode_varint(len(packed)))
        output.write(packed)

        # Find max variables across all lines
        max_vars = max((len(v) for _, v in template_data), default=0)
        output.write(encode_varint(max_vars))

        # Column 2+: Variable columns with smart encoding
        for var_idx in range(max_vars):
            col_values = []
            for tid, variables in template_data:
                if tid < 0:
                    # Raw line - store as first "variable"
                    col_values.append(variables[0] if variables and var_idx == 0 else '')
                elif var_idx < len(variables):
                    col_values.append(variables[var_idx])
                else:
                    col_values.append('')

            # Use smart column encoding (timestamp delta, dictionary, etc.)
            encode_smart_column(output, col_values, n_lines)

        return output.getvalue()

    def _encode_text_lines(self, lines: List[str]) -> bytes:
        """Encode text lines - always use V10 since it's more compressible by zstd."""
        if not lines:
            return self._encode_raw_text(lines)

        # If no Drain available, use raw
        if not HAS_DRAIN:
            return self._encode_raw_text(lines)

        # Always use V10 encoding - it produces larger pre-zstd output but
        # much more compressible data, resulting in smaller final size.
        # (V10 pre-zstd may be 2x larger, but post-zstd can be 2x smaller)
        return self._encode_text_v10(lines)

    def _update_fallback_state(self):
        """Update fallback state based on compression performance."""
        if self.json_state.should_use_raw():
            self.use_raw_json = True
            self.chunks_since_fallback = 0
        elif self.use_raw_json:
            self.chunks_since_fallback += 1
            if self.chunks_since_fallback >= self.config.recovery_interval:
                # Try V10 again
                self.use_raw_json = False
                self.json_state.ratio_history.clear()

    def finish(self):
        """Finish encoding and close stream."""
        # Flush remaining lines
        if self.chunk_lines:
            self._flush_chunk()

        # Write end marker
        self.zstd_stream.write(encode_varint(0))  # Zero-length chunk = end

        # Close zstd stream
        self.zstd_stream.close()

    def get_stats(self) -> Dict[str, Any]:
        """Get encoding statistics."""
        return {
            'total_lines': self.total_lines,
            'total_raw_bytes': self.total_raw_bytes,
            'total_encoded_bytes': self.total_encoded_bytes,
            'chunks': self.chunk_number,
            'templates_learned': self.drain_state.next_template_id if HAS_DRAIN else 0,
            'json_keys_learned': self.json_state.next_key_id,
            'drain_memory': self.drain_state.memory_usage() if HAS_DRAIN else 0,
            'json_memory': self.json_state.memory_usage(),
        }


# ============================================================================
# Streaming Decoder
# ============================================================================

class StreamingDecoder:
    """
    True streaming V10 decoder.

    Usage:
        decoder = StreamingDecoder(input_file)
        for line in decoder:
            process(line)
    """

    def __init__(self, input_stream: io.BufferedReader):
        self.input = input_stream

        # zstd streaming decompressor
        self.decompressor = zstd.ZstdDecompressor()
        self.zstd_stream = self.decompressor.stream_reader(input_stream)

        # Read all decompressed data (for simplicity - could be truly streaming)
        self.data = self.zstd_stream.read()
        self.pos = 0

        # Template state (learned from chunks)
        self.templates: Dict[int, str] = {}

        # Parse header
        self._read_header()

    def _read_header(self):
        """Read and validate stream header."""
        magic = self.data[self.pos:self.pos+4]
        self.pos += 4

        if magic != MAGIC:
            raise ValueError(f"Invalid magic: {magic}")

        version = self.data[self.pos]
        self.pos += 1

        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")

        # Read config
        self.chunk_size, self.pos = decode_varint(self.data, self.pos)
        self.initial_chunk_size, self.pos = decode_varint(self.data, self.pos)
        self.zstd_level, self.pos = decode_varint(self.data, self.pos)
        self.zstd_long_distance, self.pos = decode_varint(self.data, self.pos)

    def __iter__(self) -> Iterator[str]:
        """Iterate over decoded lines."""
        while True:
            chunk_len, self.pos = decode_varint(self.data, self.pos)
            if chunk_len == 0:
                break  # End marker

            chunk_data = self.data[self.pos:self.pos+chunk_len]
            self.pos += chunk_len

            for line in self._decode_chunk(chunk_data):
                yield line

    def _decode_chunk(self, data: bytes) -> List[str]:
        """Decode a chunk, return lines."""
        pos = 0

        n_lines, pos = decode_varint(data, pos)

        # Read format bitmap
        formats, pos = self._read_format_bitmap(data, pos, n_lines)

        # Separate indices
        json_indices = [i for i, f in enumerate(formats) if f == FMT_JSON]
        text_indices = [i for i, f in enumerate(formats) if f == FMT_TEXT]

        # Read JSON lines
        json_len, pos = decode_varint(data, pos)
        json_lines = []
        if json_len > 0:
            json_data = data[pos:pos+json_len]
            pos += json_len
            json_lines = self._decode_json_lines(json_data, len(json_indices))

        # Read TEXT lines
        text_len, pos = decode_varint(data, pos)
        text_lines = []
        if text_len > 0:
            text_data = data[pos:pos+text_len]
            pos += text_len
            text_lines = self._decode_text_lines(text_data, len(text_indices))

        # Reconstruct in original order
        lines = [''] * n_lines
        for i, idx in enumerate(json_indices):
            if i < len(json_lines):
                lines[idx] = json_lines[i]
        for i, idx in enumerate(text_indices):
            if i < len(text_lines):
                lines[idx] = text_lines[i]

        return lines

    def _read_format_bitmap(self, data: bytes, pos: int, n_lines: int) -> Tuple[List[int], int]:
        """Read run-length encoded format bitmap."""
        n_runs, pos = decode_varint(data, pos)

        formats = []
        for _ in range(n_runs):
            fmt = data[pos]
            pos += 1
            count, pos = decode_varint(data, pos)
            formats.extend([fmt] * count)

        return formats[:n_lines], pos

    def _decode_json_lines(self, data: bytes, n_lines: int) -> List[str]:
        """Decode JSON lines."""
        pos = 0
        enc_type = data[pos]
        pos += 1

        if enc_type == CHUNK_RAW:
            lines = []
            for _ in range(n_lines):
                line_len, pos = decode_varint(data, pos)
                line = data[pos:pos+line_len].decode('utf-8')
                pos += line_len
                lines.append(line)
            return lines

        elif enc_type == CHUNK_V10_JSON:
            return self._decode_json_columnar(data[pos:], n_lines)

        return []

    def _decode_json_columnar(self, data: bytes, n_lines: int) -> List[str]:
        """Decode columnar JSON."""
        pos = 0

        # Read keys
        n_keys, pos = decode_varint(data, pos)
        keys = []
        for _ in range(n_keys):
            key_len, pos = decode_varint(data, pos)
            key = data[pos:pos+key_len].decode('utf-8')
            pos += key_len
            keys.append(key)

        # Read per-row key order
        row_key_orders = []
        for _ in range(n_lines):
            n_row_keys, pos = decode_varint(data, pos)
            row_keys = []
            for _ in range(n_row_keys):
                idx, pos = decode_varint(data, pos)
                row_keys.append(idx)
            row_key_orders.append(row_keys)

        # Read columns
        columns: Dict[str, List[str]] = {}
        for key in keys:
            values, pos = self._decode_column(data, pos, n_lines)
            columns[key] = values

        # Reconstruct objects with original key order
        lines = []
        for i in range(n_lines):
            obj = {}
            row_keys = [keys[idx] for idx in row_key_orders[i] if idx < len(keys)]

            for key in row_keys:
                val_str = columns.get(key, ['_ABSENT_'] * n_lines)[i]
                if val_str != '_ABSENT_':
                    try:
                        obj[key] = json.loads(val_str)
                    except json.JSONDecodeError:
                        obj[key] = val_str

            lines.append(json.dumps(obj, separators=(',', ':'), ensure_ascii=False))

        return lines

    def _decode_column(self, data: bytes, pos: int, n_rows: int) -> Tuple[List[str], int]:
        """Decode a column."""
        enc_type = data[pos]
        pos += 1

        if enc_type == VAR_RAW:
            values = []
            for _ in range(n_rows):
                val_len, pos = decode_varint(data, pos)
                val = data[pos:pos+val_len].decode('utf-8')
                pos += val_len
                values.append(val)
            return values, pos

        elif enc_type == VAR_DICT:
            # Read dictionary
            n_unique, pos = decode_varint(data, pos)
            unique = []
            for _ in range(n_unique):
                val_len, pos = decode_varint(data, pos)
                val = data[pos:pos+val_len].decode('utf-8')
                pos += val_len
                unique.append(val)

            # Read indices
            bits, pos = decode_varint(data, pos)
            packed_len, pos = decode_varint(data, pos)
            packed = data[pos:pos+packed_len]
            pos += packed_len

            indices = self._unpack_bits(packed, n_rows, bits)
            values = [unique[i] if i < len(unique) else '' for i in indices]
            return values, pos

        elif enc_type == VAR_DELTA_INT:
            if n_rows == 0:
                return [], pos

            first, pos = decode_signed_varint(data, pos)
            values = [str(first)]
            prev = first
            for _ in range(n_rows - 1):
                delta, pos = decode_signed_varint(data, pos)
                prev += delta
                values.append(str(prev))
            return values, pos

        return [''] * n_rows, pos

    def _unpack_bits(self, packed: bytes, n_values: int, bits: int) -> List[int]:
        """Unpack bit-packed values."""
        if bits == 0:
            return [0] * n_values

        values = []
        bit_pos = 0

        for _ in range(n_values):
            val = 0
            remaining_bits = bits
            byte_idx = bit_pos // 8
            bit_offset = bit_pos % 8
            shift = 0

            while remaining_bits > 0 and byte_idx < len(packed):
                space_in_byte = 8 - bit_offset
                bits_to_read = min(remaining_bits, space_in_byte)
                mask = (1 << bits_to_read) - 1
                val |= ((packed[byte_idx] >> bit_offset) & mask) << shift
                shift += bits_to_read
                remaining_bits -= bits_to_read
                byte_idx += 1
                bit_offset = 0

            values.append(val)
            bit_pos += bits

        return values

    def _decode_text_lines(self, data: bytes, n_lines: int) -> List[str]:
        """Decode text lines."""
        pos = 0
        enc_type = data[pos]
        pos += 1

        if enc_type == CHUNK_RAW:
            lines = []
            for _ in range(n_lines):
                line_len, pos = decode_varint(data, pos)
                line = data[pos:pos+line_len].decode('utf-8')
                pos += line_len
                lines.append(line)
            return lines

        elif enc_type == CHUNK_V10_TEXT:
            return self._decode_text_templated(data[pos:], n_lines)

        return []

    def _decode_text_templated(self, data: bytes, n_lines_expected: int) -> List[str]:
        """Decode template-encoded text lines (columnar format)."""
        pos = 0

        # Read templates for this chunk
        n_templates, pos = decode_varint(data, pos)
        local_templates = {}

        for i in range(n_templates):
            tid, pos = decode_varint(data, pos)
            tmpl_len, pos = decode_varint(data, pos)
            template = data[pos:pos+tmpl_len].decode('utf-8')
            pos += tmpl_len
            local_templates[i] = template  # Map local index to template
            self.templates[tid] = template  # Update global state

        # Read number of lines
        n_lines, pos = decode_varint(data, pos)

        # Read template indices (bit-packed)
        bits = data[pos]
        pos += 1
        packed_len, pos = decode_varint(data, pos)
        packed = data[pos:pos+packed_len]
        pos += packed_len
        indices = self._unpack_bits(packed, n_lines, bits)

        # Read max variables
        max_vars, pos = decode_varint(data, pos)

        # Read variable columns using smart decoding
        columns = []
        for var_idx in range(max_vars):
            col_values, pos = decode_smart_column(data, pos, n_lines)
            columns.append(col_values)

        # Reconstruct lines
        lines = []
        for i in range(n_lines):
            local_idx = indices[i]

            if local_idx == 0xFFFF or local_idx >= len(local_templates):
                # Raw line - stored in first column
                if columns and i < len(columns[0]):
                    lines.append(columns[0][i])
                else:
                    lines.append('')
            else:
                # Template + variables from columns
                template = local_templates.get(local_idx, '')

                # Count how many <*> placeholders in template
                n_placeholders = template.count('<*>')

                # Get that many variables from columns
                variables = []
                for col_idx in range(n_placeholders):
                    if col_idx < len(columns) and i < len(columns[col_idx]):
                        variables.append(columns[col_idx][i])
                    else:
                        variables.append('')

                # Reconstruct
                line = self._reconstruct_line(template, variables)
                lines.append(line)

        return lines

    def _reconstruct_line(self, template: str, variables: List[str]) -> str:
        """Reconstruct line from template and variables."""
        if not template:
            reconstructed = variables[0] if variables else ""
        elif len(template.split('<*>')) == 1:
            reconstructed = template if not variables else variables[0]
        else:
            parts = template.split('<*>')
            result = []
            var_idx = 0
            for i, part in enumerate(parts):
                if i > 0 and var_idx < len(variables):
                    result.append(variables[var_idx])
                    var_idx += 1
                result.append(part)

            if var_idx < len(variables):
                result.append(variables[var_idx])

            reconstructed = ''.join(result)

        # Restore multi-space (always, for all code paths)
        def restore_spaces(match):
            return ' ' * int(match.group(1))
        while MULTI_SPACE_PREFIX in reconstructed:
            reconstructed = re.sub(MULTI_SPACE_PREFIX + r'(\d)', restore_spaces, reconstructed)

        return reconstructed


# ============================================================================
# High-level API
# ============================================================================

def compress_streaming(lines: List[str], config: Optional[StreamingConfig] = None) -> bytes:
    """Compress lines using streaming encoder."""
    output = io.BytesIO()
    encoder = StreamingEncoder(output, config)

    for line in lines:
        encoder.add_line(line)

    encoder.finish()
    return output.getvalue()


def decompress_streaming(data: bytes) -> List[str]:
    """Decompress streaming-encoded data."""
    input_stream = io.BytesIO(data)
    decoder = StreamingDecoder(input_stream)
    return list(decoder)


def compress_file_streaming(input_path: str, output_path: str,
                           config: Optional[StreamingConfig] = None) -> Dict[str, Any]:
    """Compress a file using streaming encoder."""
    with open(output_path, 'wb') as out_file:
        encoder = StreamingEncoder(out_file, config)

        with open(input_path, 'r', encoding='utf-8', errors='replace') as in_file:
            for line in in_file:
                encoder.add_line(line.rstrip('\n\r'))

        encoder.finish()
        return encoder.get_stats()


def decompress_file_streaming(input_path: str, output_path: str) -> int:
    """Decompress a streaming-encoded file."""
    with open(input_path, 'rb') as in_file:
        decoder = StreamingDecoder(in_file)

        n_lines = 0
        with open(output_path, 'w', encoding='utf-8') as out_file:
            for line in decoder:
                out_file.write(line + '\n')
                n_lines += 1

        return n_lines


# ============================================================================
# CLI and Testing
# ============================================================================

def test_roundtrip(lines: List[str], config: Optional[StreamingConfig] = None) -> bool:
    """Test lossless roundtrip."""
    compressed = compress_streaming(lines, config)
    decompressed = decompress_streaming(compressed)

    if len(lines) != len(decompressed):
        print(f"Line count mismatch: {len(lines)} vs {len(decompressed)}")
        return False

    for i, (orig, dec) in enumerate(zip(lines, decompressed)):
        if orig != dec:
            print(f"Line {i} mismatch:")
            print(f"  Original: {repr(orig[:100])}")
            print(f"  Decoded:  {repr(dec[:100])}")
            return False

    return True


def main():
    import sys
    import os

    if len(sys.argv) < 2:
        print("Usage: codec_v10_true_streaming.py <command> [args]")
        print("Commands:")
        print("  compress <input> <output>  - Compress file")
        print("  decompress <input> <output> - Decompress file")
        print("  test <input>               - Test roundtrip on file")
        print("  benchmark <input>          - Benchmark compression")
        return

    cmd = sys.argv[1]

    if cmd == "compress" and len(sys.argv) >= 4:
        stats = compress_file_streaming(sys.argv[2], sys.argv[3])
        print(f"Compressed: {stats}")

    elif cmd == "decompress" and len(sys.argv) >= 4:
        n_lines = decompress_file_streaming(sys.argv[2], sys.argv[3])
        print(f"Decompressed {n_lines} lines")

    elif cmd == "test" and len(sys.argv) >= 3:
        with open(sys.argv[2], 'r', encoding='utf-8', errors='replace') as f:
            lines = [line.rstrip('\n\r') for line in f]

        print(f"Testing {len(lines)} lines...")
        if test_roundtrip(lines):
            print("✓ Roundtrip test passed!")
        else:
            print("✗ Roundtrip test FAILED!")
            sys.exit(1)

    elif cmd == "benchmark" and len(sys.argv) >= 3:
        with open(sys.argv[2], 'r', encoding='utf-8', errors='replace') as f:
            lines = [line.rstrip('\n\r') for line in f]

        raw_size = sum(len(line.encode('utf-8')) + 1 for line in lines)

        import time
        start = time.time()
        compressed = compress_streaming(lines)
        encode_time = time.time() - start

        start = time.time()
        decompressed = decompress_streaming(compressed)
        decode_time = time.time() - start

        # Verify
        ok = len(lines) == len(decompressed) and all(a == b for a, b in zip(lines, decompressed))

        print(f"Raw size:    {raw_size:,} bytes")
        print(f"Compressed:  {len(compressed):,} bytes ({100*len(compressed)/raw_size:.2f}%)")
        print(f"Encode time: {encode_time:.3f}s ({len(lines)/encode_time:.0f} lines/sec)")
        print(f"Decode time: {decode_time:.3f}s ({len(lines)/decode_time:.0f} lines/sec)")
        print(f"Lossless:    {'✓' if ok else '✗'}")

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()

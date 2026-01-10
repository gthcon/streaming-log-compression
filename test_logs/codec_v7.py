#!/usr/bin/env python3
"""
V7 Ultimate Log Codec - Combining all best techniques

Key innovations over V6:
1. Multi-space preprocessing for whitespace preservation (from Drain)
2. XOR delta encoding for similar consecutive lines (from LogLite)
3. Frame-of-reference timestamp encoding (from V3)
4. Sub-byte bit-packed dictionaries for low cardinality (from V3)
5. Delimiter-based path columnar encoding (from V3)
6. Prefix-ID extraction with delta encoding (from V3/Drain)
7. Recursive smart column encoding (from V6)
"""

import sys
import struct
import json
import re
from collections import Counter, defaultdict
from io import BytesIO

# Import Drain
try:
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig
    HAS_DRAIN = True
except ImportError:
    HAS_DRAIN = False

# ============================================================================
# Constants
# ============================================================================

MAGIC = b'LGV7'
VERSION = 1

# Format types for top-level
FMT_JSON = 1
FMT_TEXT = 2

# Column encoding types
ENC_RAW = 0
ENC_DICT = 1           # Dictionary with JSON-preserved types
ENC_INT_DELTA = 2      # Integer delta encoding
ENC_INT_DICT = 3       # Integer dictionary
ENC_BITPACK = 4        # Bitpacked integers
ENC_SPARSE = 5         # Sparse column
ENC_DRAIN = 6          # Drain template + variables (for text fields)
ENC_NESTED_JSON = 7    # Nested JSON array/object (recurse)
ENC_TIMESTAMP_FOR = 8  # Frame-of-reference timestamp encoding
ENC_PATH_COLUMNAR = 9  # Delimiter-based path columnar
ENC_PREFIX_DELTA = 10  # Prefix + numeric delta encoding
ENC_XOR_DELTA = 11     # XOR delta encoding for similar strings

# Multi-space preprocessing marker - use a visible char that Drain won't normalize
MULTI_SPACE_MARKER = '«'

# Patterns
ISO_TIMESTAMP_RE = re.compile(
    r'^"?(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"?,?$'
)
CLF_TIMESTAMP_RE = re.compile(
    r'^\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]?$'
)
PREFIX_ID_RE = re.compile(r'^"?([a-zA-Z][\w-]*)-(\d+)"?,?$')
HTTP_LOG_RE = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[^"]*"\s+\d+\s+\S+')
JSON_RE = re.compile(r'^\s*[\[{]')
NUMERIC_RE = re.compile(r'^-?\d+$')
URL_PATH_RE = re.compile(r'^/[\w./-]*$')
MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
MONTHS_REV = {v:k for k,v in MONTHS.items()}

# ============================================================================
# Utility Functions
# ============================================================================

def encode_varint(n):
    result = []
    while n >= 0x80:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n)
    return bytes(result)

def decode_varint(data, pos):
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

def encode_signed_varint(n):
    zigzag = (n << 1) ^ (n >> 63)
    return encode_varint(zigzag)

def decode_signed_varint(data, pos):
    zigzag, pos = decode_varint(data, pos)
    return (zigzag >> 1) ^ (-(zigzag & 1)), pos

def pack_bits(values, bits_per_value):
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

def unpack_bits(data, count, bits_per_value):
    if not data or bits_per_value == 0 or count == 0:
        return [0] * count
    result = []
    buffer = 0
    bits_in_buffer = 0
    pos = 0
    mask = (1 << bits_per_value) - 1
    for _ in range(count):
        while bits_in_buffer < bits_per_value:
            buffer |= data[pos] << bits_in_buffer
            pos += 1
            bits_in_buffer += 8
        result.append(buffer & mask)
        buffer >>= bits_per_value
        bits_in_buffer -= bits_per_value
    return result

# ============================================================================
# Multi-Space Preprocessing (Whitespace Preservation)
# ============================================================================

def preprocess_line(line):
    """Replace multi-spaces, trailing spaces, and leading tabs with compact markers."""
    def replace_spaces(match):
        count = len(match.group(0))
        if count <= 9:
            return MULTI_SPACE_MARKER + str(count)
        else:
            result = []
            while count > 0:
                chunk = min(count, 9)
                result.append(MULTI_SPACE_MARKER + str(chunk))
                count -= chunk
            return ''.join(result)

    # Handle leading tabs - encode as special marker
    leading_tabs = 0
    while line and line[0] == '\t':
        leading_tabs += 1
        line = line[1:]

    # Handle trailing spaces
    trailing = 0
    while line and line[-1] == ' ':
        trailing += 1
        line = line[:-1]

    # Replace multiple consecutive spaces
    line = re.sub(r'  +', replace_spaces, line)

    # Add leading tab marker - use delimiter to separate from content
    if leading_tabs > 0:
        line = MULTI_SPACE_MARKER + 'T' + str(leading_tabs) + MULTI_SPACE_MARKER + line

    # Add trailing space marker
    if trailing > 0:
        while trailing > 0:
            chunk = min(trailing, 9)
            line += MULTI_SPACE_MARKER + str(chunk)
            trailing -= chunk

    return line

def postprocess_line(line):
    """Restore multi-spaces, trailing spaces, and leading tabs from compact markers."""
    # Restore leading tabs first - format is «T<count>«
    tab_match = re.match(MULTI_SPACE_MARKER + r'T(\d+)' + MULTI_SPACE_MARKER, line)
    if tab_match:
        tab_count = int(tab_match.group(1))
        line = '\t' * tab_count + line[len(tab_match.group(0)):]

    # Restore spaces
    def restore_spaces(match):
        count = int(match.group(1))
        return ' ' * count
    while MULTI_SPACE_MARKER in line:
        line = re.sub(MULTI_SPACE_MARKER + r'(\d)', restore_spaces, line)
    return line

# ============================================================================
# XOR Delta Encoding (from LogLite)
# ============================================================================

def xor_strings(a, b):
    """XOR two strings of equal length, return bytes."""
    return bytes(ord(x) ^ ord(y) for x, y in zip(a, b))

def un_xor_strings(xor_result, reference):
    """Recover original string from XOR result and reference."""
    return ''.join(chr(b ^ ord(c)) for b, c in zip(xor_result, reference))

def rle_encode_zeros(data):
    """RLE encode with focus on zero runs (common after XOR)."""
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0:
            # Count consecutive zeros
            count = 1
            while i + count < len(data) and data[i + count] == 0 and count < 255:
                count += 1
            result.append(0)  # Marker for zero run
            result.append(count)
            i += count
        else:
            # Non-zero byte
            result.append(data[i])
            if data[i] == 0:  # Escape zero if needed (shouldn't happen here)
                result.append(1)
            i += 1
    return bytes(result)

def rle_decode_zeros(data, target_len):
    """RLE decode zero runs."""
    result = bytearray()
    i = 0
    while i < len(data) and len(result) < target_len:
        if data[i] == 0:
            # Zero run
            count = data[i + 1] if i + 1 < len(data) else 1
            result.extend([0] * count)
            i += 2
        else:
            result.append(data[i])
            i += 1
    return bytes(result[:target_len])

def compute_similarity(a, b):
    """Compute string similarity (fraction of matching chars)."""
    if len(a) != len(b):
        return 0
    matches = sum(1 for x, y in zip(a, b) if x == y)
    return matches / len(a) if a else 0

# ============================================================================
# Timestamp Encoding (Frame-of-Reference)
# ============================================================================

def parse_iso_timestamp(s):
    """Parse ISO timestamp to milliseconds since epoch."""
    m = ISO_TIMESTAMP_RE.match(s)
    if not m:
        return None, None

    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))

    ms_str = m.group(7)
    ms = 0
    ms_digits = 0
    if ms_str:
        ms_digits = len(ms_str) - 1  # Exclude the dot
        ms = int((ms_str + '000')[1:4])  # Pad to 3 digits

    tz = m.group(8) or ''

    # Calculate days since epoch (1970-01-01)
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

    ms_val = days * 86400000 + hour * 3600000 + minute * 60000 + second * 1000 + ms

    format_info = {
        'ms_digits': ms_digits,
        'tz': tz,
        'separator': 'T' if 'T' in s else ' ',
        'has_quotes': s.startswith('"'),
        'has_comma': s.endswith(',')
    }

    return ms_val, format_info

def reconstruct_iso_timestamp(ms_val, format_info):
    """Reconstruct ISO timestamp from milliseconds."""
    days = ms_val // 86400000
    rem = ms_val % 86400000
    h = rem // 3600000
    rem = rem % 3600000
    mi = rem // 60000
    rem = rem % 60000
    s = rem // 1000
    ms = rem % 1000

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

    sep = format_info.get('separator', 'T')
    result = f"{year:04d}-{month:02d}-{day:02d}{sep}{h:02d}:{mi:02d}:{s:02d}"

    ms_digits = format_info.get('ms_digits', 0)
    if ms_digits > 0:
        ms_str = f"{ms:03d}"[:ms_digits]
        result += f".{ms_str}"

    tz = format_info.get('tz', '')
    if tz:
        result += tz

    if format_info.get('has_quotes'):
        result = '"' + result + '"'
    if format_info.get('has_comma'):
        result += ','

    return result

def parse_clf_timestamp(s):
    """Parse CLF timestamp like [01/Jul/1995:00:00:01 -0400]."""
    m = CLF_TIMESTAMP_RE.match(s)
    if not m:
        return None, None

    day = int(m.group(1))
    month = MONTHS.get(m.group(2), 1)
    year = int(m.group(3))
    hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))
    tz = m.group(7) or ''

    # Calculate days since epoch
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
    }

    return seconds_val, format_info

def reconstruct_clf_timestamp(seconds_val, format_info):
    """Reconstruct CLF timestamp."""
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
    month_str = MONTHS_REV.get(month, 'Jan')

    tz = format_info.get('tz', '')
    tz_part = f" {tz}" if tz else ""

    result = f"{day:02d}/{month_str}/{year:04d}:{h:02d}:{mi:02d}:{s:02d}{tz_part}"

    if format_info.get('has_brackets'):
        result = '[' + result + ']'

    return result

# ============================================================================
# Path Columnar Encoding
# ============================================================================

def encode_path_columnar(output, values, n_rows):
    """Encode URL paths by splitting on / delimiter."""
    # Split all paths
    split_paths = []
    max_segments = 0
    for v in values:
        if v and isinstance(v, str) and v.startswith('/'):
            segments = v.split('/')
            split_paths.append(segments)
            max_segments = max(max_segments, len(segments))
        else:
            split_paths.append([str(v) if v else ''])

    output.write(encode_varint(max_segments))

    # Encode each segment position as a column
    for seg_idx in range(max_segments):
        col = [p[seg_idx] if seg_idx < len(p) else '' for p in split_paths]
        encode_dict_column(output, col, n_rows)

def decode_path_columnar(data, pos, n_rows):
    """Decode path columnar encoding."""
    max_segments, pos = decode_varint(data, pos)

    segment_cols = []
    for _ in range(max_segments):
        col, pos = decode_dict_column(data, pos, n_rows)
        segment_cols.append(col)

    # Reconstruct paths - preserve empty strings for leading/trailing slashes
    result = []
    for i in range(n_rows):
        segments = [col[i] for col in segment_cols]
        # Remove trailing empty segments but keep leading ones
        while segments and segments[-1] == '':
            segments.pop()
        result.append('/'.join(segments))

    return result, pos

# ============================================================================
# Prefix-Delta Encoding
# ============================================================================

def encode_prefix_delta(output, values, n_rows):
    """Encode prefix-ID patterns like 'user-123' with delta on numeric part."""
    # Extract prefix and numeric parts
    prefix = None
    numbers = []

    for v in values:
        m = PREFIX_ID_RE.match(str(v)) if v else None
        if m:
            if prefix is None:
                prefix = m.group(1)
            numbers.append(int(m.group(2)))
        else:
            numbers.append(0)

    # Write prefix
    prefix_bytes = (prefix or '').encode('utf-8')
    output.write(encode_varint(len(prefix_bytes)))
    output.write(prefix_bytes)

    # Write numbers as deltas
    prev = 0
    for n in numbers:
        output.write(encode_signed_varint(n - prev))
        prev = n

def decode_prefix_delta(data, pos, n_rows):
    """Decode prefix-delta encoding."""
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

# ============================================================================
# Drain Encoder/Decoder
# ============================================================================

def create_drain_miner():
    if not HAS_DRAIN:
        return None
    config = TemplateMinerConfig()
    config.load("""
[MASKING]
[DRAIN]
sim_th = 0.4
depth = 4
max_children = 100
""")
    return TemplateMiner(config=config)

def extract_variables(line, template):
    """Extract variable values from line given template."""
    template_parts = template.split('<*>')
    if len(template_parts) == 1:
        return []

    # Use regex matching
    regex_parts = []
    for i, part in enumerate(template_parts):
        regex_parts.append(re.escape(part))
        if i < len(template_parts) - 1:
            regex_parts.append('(.*?)')

    pattern = '^' + ''.join(regex_parts) + '$'
    try:
        m = re.match(pattern, line)
        if m:
            return list(m.groups())
    except re.error:
        pass

    # Fallback: simple split matching
    variables = []
    remaining = line
    for i, part in enumerate(template_parts[:-1]):
        if part:
            idx = remaining.find(part)
            if idx > 0:
                variables.append(remaining[:idx])
            remaining = remaining[idx + len(part):] if idx >= 0 else remaining

        next_part = template_parts[i + 1] if i + 1 < len(template_parts) else ''
        if next_part:
            idx = remaining.find(next_part)
            if idx >= 0:
                variables.append(remaining[:idx])
                remaining = remaining[idx:]
            else:
                variables.append(remaining)
                remaining = ''
        elif i == len(template_parts) - 2:
            variables.append(remaining)

    return variables

def reconstruct_line(template, variables):
    """Reconstruct line from template and variables."""
    parts = template.split('<*>')
    result = []

    for i, part in enumerate(parts):
        result.append(part)
        if i < len(variables):
            result.append(str(variables[i]))

    return ''.join(result)

# ============================================================================
# Smart Column Encoder/Decoder
# ============================================================================

def analyze_column(values):
    """Analyze column to determine best encoding."""
    present = [v for v in values if v != '_ABSENT_' and v is not None]
    if not present:
        return 'empty', {}

    # Check for timestamps
    iso_count = 0
    clf_count = 0
    for v in present[:100]:
        if isinstance(v, str):
            if parse_iso_timestamp(v)[0] is not None:
                iso_count += 1
            elif parse_clf_timestamp(v)[0] is not None:
                clf_count += 1

    if iso_count > len(present[:100]) * 0.8:
        return 'timestamp_iso', {}
    if clf_count > len(present[:100]) * 0.8:
        return 'timestamp_clf', {}

    # Check for prefix-ID pattern
    prefix_count = sum(1 for v in present[:100] if isinstance(v, str) and PREFIX_ID_RE.match(v))
    if prefix_count > len(present[:100]) * 0.8:
        return 'prefix_id', {}

    # Check for URL paths
    path_count = sum(1 for v in present[:100] if isinstance(v, str) and URL_PATH_RE.match(v))
    if path_count > len(present[:100]) * 0.8:
        return 'path', {}

    # Check cardinality for dictionary
    unique = set(str(v) for v in present)
    if len(unique) <= 16:
        return 'low_cardinality', {'unique': len(unique)}

    return 'general', {}

def encode_smart_column(output, values, n_rows):
    """Intelligently encode a column with optimal encoding."""
    if not values:
        output.write(bytes([ENC_RAW]))
        return

    # Filter out absent markers
    present = [v for v in values if v != '_ABSENT_']
    if not present:
        output.write(bytes([ENC_SPARSE]))
        output.write(encode_varint(0))
        return

    # Check sparsity
    sparsity = 1 - len(present) / len(values)
    if sparsity >= 0.5:
        output.write(bytes([ENC_SPARSE]))
        indices = [i for i, v in enumerate(values) if v != '_ABSENT_']
        present_vals = [v for v in values if v != '_ABSENT_']

        output.write(encode_varint(len(indices)))
        prev = 0
        for idx in indices:
            output.write(encode_varint(idx - prev))
            prev = idx

        encode_smart_column(output, present_vals, len(present_vals))
        return

    # Analyze column type
    col_type, info = analyze_column(values)
    has_absent = any(v == '_ABSENT_' for v in values)

    # Check for timestamps - use frame-of-reference encoding
    if col_type == 'timestamp_iso' and not has_absent:
        output.write(bytes([ENC_TIMESTAMP_FOR]))
        output.write(bytes([1]))  # ISO type
        encode_timestamp_column(output, values, n_rows, 'iso')
        return

    if col_type == 'timestamp_clf' and not has_absent:
        output.write(bytes([ENC_TIMESTAMP_FOR]))
        output.write(bytes([2]))  # CLF type
        encode_timestamp_column(output, values, n_rows, 'clf')
        return

    # Check for prefix-ID pattern
    if col_type == 'prefix_id' and not has_absent:
        output.write(bytes([ENC_PREFIX_DELTA]))
        encode_prefix_delta(output, values, n_rows)
        return

    # Check for URL paths
    if col_type == 'path' and not has_absent:
        output.write(bytes([ENC_PATH_COLUMNAR]))
        encode_path_columnar(output, values, n_rows)
        return

    # Check for integers
    int_vals = []
    all_ints = True
    for v in present:
        if isinstance(v, int) and not isinstance(v, bool):
            int_vals.append(v)
        else:
            all_ints = False
            break

    if all_ints and int_vals and not has_absent:
        unique = len(set(int_vals))

        # Low cardinality integers - use bit-packed dictionary
        if unique <= 16:
            output.write(bytes([ENC_INT_DICT]))
            encode_int_dict_column(output, values, n_rows)
            return

        # Use delta encoding for sequential-ish integers
        output.write(bytes([ENC_INT_DELTA]))
        encode_int_delta_column(output, values, n_rows)
        return

    # Default to dictionary encoding with type preservation
    output.write(bytes([ENC_DICT]))
    encode_dict_column(output, values, n_rows)

def decode_smart_column(data, pos, n_rows):
    """Decode a column, handling all encodings."""
    enc_type = data[pos]
    pos += 1

    if enc_type == ENC_RAW:
        values = []
        for _ in range(n_rows):
            str_len, pos = decode_varint(data, pos)
            values.append(data[pos:pos+str_len].decode('utf-8'))
            pos += str_len
        return values, pos

    if enc_type == ENC_SPARSE:
        n_present, pos = decode_varint(data, pos)
        if n_present == 0:
            return ['_ABSENT_'] * n_rows, pos

        indices = []
        prev = 0
        for _ in range(n_present):
            delta, pos = decode_varint(data, pos)
            prev += delta
            indices.append(prev)

        inner_vals, pos = decode_smart_column(data, pos, n_present)

        result = ['_ABSENT_'] * n_rows
        for idx, val in zip(indices, inner_vals):
            if idx < n_rows:
                result[idx] = val
        return result, pos

    if enc_type == ENC_DICT:
        return decode_dict_column(data, pos, n_rows)

    if enc_type == ENC_INT_DELTA:
        return decode_int_delta_column(data, pos, n_rows)

    if enc_type == ENC_INT_DICT:
        return decode_int_dict_column(data, pos, n_rows)

    if enc_type == ENC_BITPACK:
        return decode_bitpack_column(data, pos, n_rows)

    if enc_type == ENC_TIMESTAMP_FOR:
        ts_type = data[pos]
        pos += 1
        return decode_timestamp_column(data, pos, n_rows, 'iso' if ts_type == 1 else 'clf')

    if enc_type == ENC_PREFIX_DELTA:
        return decode_prefix_delta(data, pos, n_rows)

    if enc_type == ENC_PATH_COLUMNAR:
        return decode_path_columnar(data, pos, n_rows)

    if enc_type == ENC_DRAIN:
        return decode_drain_column(data, pos, n_rows)

    # Fallback
    values = []
    for _ in range(n_rows):
        str_len, pos = decode_varint(data, pos)
        values.append(data[pos:pos+str_len].decode('utf-8'))
        pos += str_len
    return values, pos

# ============================================================================
# Specific Column Encoders/Decoders
# ============================================================================

def encode_dict_column(output, values, n_rows):
    """Dictionary encoding with JSON type preservation."""
    def to_json_str(v):
        if v == '_ABSENT_':
            return '_ABSENT_'
        return json.dumps(v)

    unique = sorted(set(to_json_str(v) for v in values))
    vocab = {v: i for i, v in enumerate(unique)}

    output.write(encode_varint(len(unique)))
    for word in unique:
        word_bytes = word.encode('utf-8')
        output.write(encode_varint(len(word_bytes)))
        output.write(word_bytes)

    # Use optimal bit width
    bits = max(1, (len(unique) - 1).bit_length()) if unique else 1
    indices = [vocab.get(to_json_str(v), 0) for v in values]
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

def decode_dict_column(data, pos, n_rows):
    """Decode dictionary-encoded column."""
    vocab_size, pos = decode_varint(data, pos)
    vocab = []
    for _ in range(vocab_size):
        word_len, pos = decode_varint(data, pos)
        word_str = data[pos:pos+word_len].decode('utf-8')
        pos += word_len
        if word_str == '_ABSENT_':
            vocab.append('_ABSENT_')
        else:
            try:
                vocab.append(json.loads(word_str))
            except:
                vocab.append(word_str)

    bits = data[pos]
    pos += 1
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len

    indices = unpack_bits(packed, n_rows, bits)
    return [vocab[i] if i < len(vocab) else '' for i in indices], pos

def encode_int_delta_column(output, values, n_rows):
    """Delta encoding for integers."""
    prev = 0
    for v in values:
        val = v if isinstance(v, int) else 0
        output.write(encode_signed_varint(val - prev))
        prev = val

def decode_int_delta_column(data, pos, n_rows):
    """Decode delta-encoded integers."""
    values = []
    prev = 0
    for _ in range(n_rows):
        delta, pos = decode_signed_varint(data, pos)
        prev += delta
        values.append(prev)
    return values, pos

def encode_int_dict_column(output, values, n_rows):
    """Dictionary encoding for integers with sub-byte bit packing."""
    int_vals = [v if isinstance(v, int) else 0 for v in values]
    unique = sorted(set(int_vals))
    vocab = {v: i for i, v in enumerate(unique)}

    output.write(encode_varint(len(unique)))
    for val in unique:
        output.write(encode_signed_varint(val))

    bits = max(1, (len(unique) - 1).bit_length()) if unique else 1
    indices = [vocab[v] for v in int_vals]
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

def decode_int_dict_column(data, pos, n_rows):
    """Decode integer dictionary column."""
    vocab_size, pos = decode_varint(data, pos)
    vocab = []
    for _ in range(vocab_size):
        val, pos = decode_signed_varint(data, pos)
        vocab.append(val)

    bits = data[pos]
    pos += 1
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len

    indices = unpack_bits(packed, n_rows, bits)
    return [vocab[i] if i < len(vocab) else 0 for i in indices], pos

def decode_bitpack_column(data, pos, n_rows):
    """Decode bitpacked column."""
    bits = data[pos]
    pos += 1
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len
    return unpack_bits(packed, n_rows, bits), pos

def encode_timestamp_column(output, values, n_rows, ts_type):
    """Frame-of-reference timestamp encoding."""
    if ts_type == 'iso':
        parsed = [parse_iso_timestamp(str(v)) for v in values]
    else:
        parsed = [parse_clf_timestamp(str(v)) for v in values]

    ts_values = [p[0] if p[0] is not None else 0 for p in parsed]
    formats = [p[1] if p[1] is not None else {} for p in parsed]

    # Store min value as reference
    min_val = min(ts_values) if ts_values else 0
    output.write(encode_varint(min_val))

    # Store offsets from min
    for val in ts_values:
        output.write(encode_varint(val - min_val))

    # Store format info (use most common format)
    format_counter = Counter(json.dumps(f, sort_keys=True) for f in formats)
    common_format = json.loads(format_counter.most_common(1)[0][0]) if format_counter else {}
    format_bytes = json.dumps(common_format).encode('utf-8')
    output.write(encode_varint(len(format_bytes)))
    output.write(format_bytes)

def decode_timestamp_column(data, pos, n_rows, ts_type):
    """Decode frame-of-reference timestamp column."""
    min_val, pos = decode_varint(data, pos)

    values = []
    for _ in range(n_rows):
        offset, pos = decode_varint(data, pos)
        values.append(min_val + offset)

    format_len, pos = decode_varint(data, pos)
    format_info = json.loads(data[pos:pos+format_len].decode('utf-8'))
    pos += format_len

    if ts_type == 'iso':
        return [reconstruct_iso_timestamp(v, format_info) for v in values], pos
    else:
        return [reconstruct_clf_timestamp(v, format_info) for v in values], pos

def encode_drain_column(output, values, n_rows):
    """Encode a column of text using Drain template mining."""
    if not HAS_DRAIN:
        encode_dict_column(output, values, n_rows)
        return

    str_values = [str(v) if v is not None and v != '_ABSENT_' else '' for v in values]

    # First pass: mine templates
    miner = create_drain_miner()
    template_ids = []
    for s in str_values:
        if s:
            result = miner.add_log_message(s)
            template_ids.append(result['cluster_id'])
        else:
            template_ids.append(0)

    clusters = miner.drain.clusters
    templates = {c.cluster_id: c.get_template() for c in clusters}

    # Second pass: extract variables using final templates
    all_variables = []
    for i, s in enumerate(str_values):
        if s and template_ids[i] in templates:
            template = templates[template_ids[i]]
            vars_list = extract_variables(s, template)
            all_variables.append(vars_list)
        else:
            all_variables.append([])

    # Write templates
    template_list = sorted(templates.keys())
    template_to_idx = {tid: i for i, tid in enumerate(template_list)}

    output.write(encode_varint(len(template_list)))
    for tid in template_list:
        tmpl = templates[tid]
        tmpl_bytes = tmpl.encode('utf-8')
        output.write(encode_varint(len(tmpl_bytes)))
        output.write(tmpl_bytes)

    # Write template indices
    indices = [template_to_idx.get(tid, 0) for tid in template_ids]
    bits = max(1, len(template_list).bit_length()) if template_list else 1
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

    # Write variables columnar
    max_vars = max(len(v) for v in all_variables) if all_variables else 0
    output.write(encode_varint(max_vars))

    for var_idx in range(max_vars):
        col = [v[var_idx] if var_idx < len(v) else '' for v in all_variables]
        encode_smart_column(output, col, n_rows)

def decode_drain_column(data, pos, n_rows):
    """Decode a Drain-encoded column."""
    n_templates, pos = decode_varint(data, pos)
    templates = []
    for _ in range(n_templates):
        tmpl_len, pos = decode_varint(data, pos)
        templates.append(data[pos:pos+tmpl_len].decode('utf-8'))
        pos += tmpl_len

    bits = data[pos]
    pos += 1
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len
    template_indices = unpack_bits(packed, n_rows, bits)

    max_vars, pos = decode_varint(data, pos)
    var_columns = []
    for _ in range(max_vars):
        col_vals, pos = decode_smart_column(data, pos, n_rows)
        var_columns.append(col_vals)

    result = []
    for i in range(n_rows):
        tmpl_idx = template_indices[i]
        template = templates[tmpl_idx] if tmpl_idx < len(templates) else ''

        vars_for_line = [col[i] for col in var_columns]
        line = reconstruct_line(template, vars_for_line)
        result.append(line)

    return result, pos

# ============================================================================
# JSON Flattening
# ============================================================================

def flatten_json(obj, prefix='', sep='.'):
    """Flatten nested JSON to dot-notation keys."""
    items = {}

    if isinstance(obj, dict):
        if not obj:
            if prefix:
                items[prefix] = '_EMPTY_DICT_'
        else:
            for k, v in obj.items():
                new_key = f"{prefix}{sep}{k}" if prefix else k
                if isinstance(v, dict):
                    items.update(flatten_json(v, new_key, sep))
                elif isinstance(v, list):
                    items[new_key] = json.dumps(v)
                else:
                    items[new_key] = v
    else:
        items[prefix] = obj

    return items

def set_nested_value(obj, key, value):
    """Set a value in nested dict using dot notation key."""
    if value == '_EMPTY_DICT_':
        parts = key.split('.')
        current = obj
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = {}
        return

    parts = key.split('.')
    current = obj
    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        current = current[part]

    if isinstance(value, str):
        if value.startswith('[') or value.startswith('{'):
            try:
                value = json.loads(value)
            except:
                pass

    current[parts[-1]] = value

# ============================================================================
# JSON Columnar Encoding
# ============================================================================

def encode_json_columnar(lines):
    """Encode JSON logs with smart encoding for each column."""
    rows = []
    all_keys = set()

    for line in lines:
        try:
            obj = json.loads(line)
            flat = flatten_json(obj)
            rows.append(flat)
            all_keys.update(flat.keys())
        except:
            rows.append({})

    keys = sorted(all_keys)
    n_rows = len(rows)

    columns = {k: [] for k in keys}
    for row in rows:
        for k in keys:
            columns[k].append(row.get(k, '_ABSENT_'))

    output = BytesIO()

    output.write(encode_varint(len(keys)))
    for key in keys:
        key_bytes = key.encode('utf-8')
        output.write(encode_varint(len(key_bytes)))
        output.write(key_bytes)

    output.write(encode_varint(n_rows))

    for key in keys:
        col_data = columns[key]
        encode_smart_column(output, col_data, n_rows)

    return output.getvalue(), keys

def decode_json_columnar(data, pos):
    """Decode JSON columnar format."""
    n_keys, pos = decode_varint(data, pos)
    keys = []
    for _ in range(n_keys):
        key_len, pos = decode_varint(data, pos)
        keys.append(data[pos:pos+key_len].decode('utf-8'))
        pos += key_len

    n_rows, pos = decode_varint(data, pos)

    columns = {}
    for key in keys:
        col_values, pos = decode_smart_column(data, pos, n_rows)
        columns[key] = col_values

    lines = []
    for i in range(n_rows):
        obj = {}
        for key in keys:
            val = columns[key][i]
            if val != '_ABSENT_':
                set_nested_value(obj, key, val)
        lines.append(json.dumps(obj, separators=(',', ':')))

    return lines

# ============================================================================
# Text Log Encoding with XOR Delta
# ============================================================================

def encode_text_logs(lines):
    """Encode text logs with multi-space preservation and XOR delta."""
    output = BytesIO()
    n_lines = len(lines)
    output.write(encode_varint(n_lines))

    # Preprocess lines to preserve whitespace
    preprocessed = [preprocess_line(line) for line in lines]

    if not HAS_DRAIN:
        # Fallback: raw with multi-space preprocessing
        output.write(bytes([0]))
        for line in preprocessed:
            line_bytes = line.encode('utf-8')
            output.write(encode_varint(len(line_bytes)))
            output.write(line_bytes)
        return output.getvalue()

    # Mine templates
    miner = create_drain_miner()
    template_ids = []

    for line in preprocessed:
        result = miner.add_log_message(line)
        template_ids.append(result['cluster_id'])

    clusters = miner.drain.clusters
    templates = {c.cluster_id: c.get_template() for c in clusters}

    # Extract variables using final templates
    variables = []
    for i, line in enumerate(preprocessed):
        cluster_id = template_ids[i]
        final_template = templates.get(cluster_id, line)
        vars_in_line = extract_variables(line, final_template)
        variables.append(vars_in_line)

    output.write(bytes([1]))

    # Write templates
    template_list = sorted(templates.keys())
    template_to_idx = {tid: i for i, tid in enumerate(template_list)}

    output.write(encode_varint(len(templates)))
    for tid in template_list:
        tmpl = templates[tid]
        tmpl_bytes = tmpl.encode('utf-8')
        output.write(encode_varint(len(tmpl_bytes)))
        output.write(tmpl_bytes)

    # Write template indices
    indices = [template_to_idx.get(tid, 0) for tid in template_ids]
    bits = max(1, (len(templates) - 1).bit_length()) if len(templates) > 1 else 1
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

    # Encode variables with smart encoding
    max_vars = max(len(v) for v in variables) if variables else 0
    output.write(encode_varint(max_vars))

    for var_idx in range(max_vars):
        col = [v[var_idx] if var_idx < len(v) else '' for v in variables]
        encode_smart_column(output, col, n_lines)

    return output.getvalue()

def decode_text_logs(data, pos):
    """Decode text logs with multi-space restoration."""
    n_lines, pos = decode_varint(data, pos)
    has_templates = data[pos]
    pos += 1

    if not has_templates:
        lines = []
        for _ in range(n_lines):
            line_len, pos = decode_varint(data, pos)
            lines.append(data[pos:pos+line_len].decode('utf-8'))
            pos += line_len
        return [postprocess_line(line) for line in lines]

    # Read templates
    n_templates, pos = decode_varint(data, pos)
    templates = []
    for _ in range(n_templates):
        tmpl_len, pos = decode_varint(data, pos)
        templates.append(data[pos:pos+tmpl_len].decode('utf-8'))
        pos += tmpl_len

    # Read template indices
    bits = data[pos]
    pos += 1
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len
    template_indices = unpack_bits(packed, n_lines, bits)

    # Read variables
    max_vars, pos = decode_varint(data, pos)
    var_columns = []
    for _ in range(max_vars):
        col_vals, pos = decode_smart_column(data, pos, n_lines)
        var_columns.append(col_vals)

    # Reconstruct lines
    lines = []
    for i in range(n_lines):
        tmpl_idx = template_indices[i]
        template = templates[tmpl_idx] if tmpl_idx < len(templates) else ''

        vars_for_line = [col[i] for col in var_columns]
        line = reconstruct_line(template, vars_for_line)
        lines.append(postprocess_line(line))

    return lines

# ============================================================================
# Top-Level Encoder/Decoder
# ============================================================================

def detect_format(lines):
    """Detect log format."""
    if not lines:
        return FMT_TEXT

    json_count = 0
    for line in lines[:100]:
        line = line.strip()
        if line:
            try:
                json.loads(line)
                json_count += 1
            except:
                pass

    if json_count > len(lines[:100]) * 0.5:
        return FMT_JSON
    return FMT_TEXT

def encode_v7(lines):
    """Main V7 encoder."""
    if not lines:
        return MAGIC + bytes([VERSION, FMT_TEXT]) + encode_varint(0)

    fmt = detect_format(lines)

    output = BytesIO()
    output.write(MAGIC)
    output.write(bytes([VERSION, fmt]))

    if fmt == FMT_JSON:
        data, _ = encode_json_columnar(lines)
        output.write(data)
    else:
        data = encode_text_logs(lines)
        output.write(data)

    return output.getvalue()

def decode_v7(data):
    """Main V7 decoder."""
    if len(data) < 6:
        return []

    if data[:4] != MAGIC:
        return []

    version = data[4]
    fmt = data[5]
    pos = 6

    if fmt == FMT_JSON:
        return decode_json_columnar(data, pos)
    else:
        return decode_text_logs(data, pos)

# ============================================================================
# Verification
# ============================================================================

def verify_file(input_path):
    """Encode, decode, and verify a file."""
    import time

    print(f"V7 Processing {input_path}...")

    with open(input_path, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    print(f"  Lines: {len(lines)}")

    fmt = detect_format(lines)
    fmt_name = 'JSON' if fmt == FMT_JSON else 'Text'
    print(f"  Detected format: {fmt_name}")

    start = time.time()
    encoded = encode_v7(lines)
    encode_time = time.time() - start

    orig_size = len('\n'.join(lines))
    print(f"  Encoded size: {len(encoded):,} bytes ({len(encoded)/orig_size*100:.1f}%)")
    print(f"  Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")

    start = time.time()
    decoded = decode_v7(encoded)
    decode_time = time.time() - start

    print(f"  Decode time: {decode_time:.2f}s ({len(lines)/decode_time:.0f} lines/sec)")

    # Verify
    mismatches = 0
    for i, (orig, dec) in enumerate(zip(lines, decoded)):
        if orig != dec:
            try:
                orig_obj = json.loads(orig)
                dec_obj = json.loads(dec)
                if orig_obj == dec_obj:
                    continue
            except:
                pass
            mismatches += 1
            if mismatches <= 5:
                print(f"  ✗ Line {i} mismatch:")
                print(f"    Orig: {orig[:100]}")
                print(f"    Dec:  {dec[:100]}")

    if mismatches == 0:
        print(f"  ✓ All {len(lines)} lines verified!")
        return True, encoded
    else:
        print(f"  ✗ {mismatches} mismatches")
        return False, encoded

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: codec_v7.py <logfile>")
        sys.exit(1)

    success, data = verify_file(sys.argv[1])
    sys.exit(0 if success else 1)

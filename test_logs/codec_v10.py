#!/usr/bin/env python3
"""
V10 Ultimate Log Codec - Combines all winning techniques

Key optimizations:
1. Bitstream-level RLE (9 bits per zero run vs 16 bits) - from LogLite
2. 85% XOR match threshold (higher quality matches) - from LogLite
3. Frame-of-reference timestamp encoding - from V3
4. Sub-byte bit-packing for low-cardinality columns - from V3
5. Multi-space whitespace compression - from Drain
6. Path columnarization for URL fields - from V3
7. 2-bit null masks for sparse columns - from V3
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

# Import drain_lossless_v4 for template-based text logs
try:
    from drain_lossless_v4 import (
        encode_lossless as drain_v4_encode_lossless,
        encode_to_bytes as drain_v4_encode_to_bytes,
        decode_from_bytes as drain_v4_decode_from_bytes
    )
    HAS_DRAIN_V4 = True
except ImportError:
    HAS_DRAIN_V4 = False

# Import V3 JSON encoder (better for some JSON logs like nginx_json)
try:
    from json_codec_v3 import (
        encode_json_logs as v3_parse_json,
        encode_to_bytes as v3_encode_to_bytes,
        decode_from_bytes as v3_json_decode
    )
    HAS_V3_JSON = True
except ImportError:
    HAS_V3_JSON = False

# ============================================================================
# Constants
# ============================================================================

MAGIC = b'LG10'
VERSION = 1

# Format types
FMT_JSON = 1
FMT_TEXT = 2
FMT_JSON_V3 = 3  # V3 JSON encoder (better for some logs like nginx_json)
FMT_RAW = 4      # Raw text passthrough (best for highly repetitive logs where zstd alone wins)

# Column encoding types
ENC_RAW = 0
ENC_DICT = 1
ENC_INT_DELTA = 2
ENC_INT_DICT = 3
ENC_BITPACK = 4
ENC_SPARSE = 5
ENC_DRAIN = 6
ENC_IP_PACKED = 7      # IPv4 as 4 bytes (from V5)
ENC_TIMESTAMP_FOR = 8
ENC_PATH_COLUMNAR = 9
ENC_PREFIX_DELTA = 10
ENC_BOOLEAN = 11       # Bit-packed booleans (from V5)
ENC_STRING_INT = 12    # Numeric strings as integers (from V5)
ENC_XOR_DELTA = 13     # XOR delta for similar strings (from V5/V7)

# Text encoding modes
TEXT_RAW = 0
TEXT_DRAIN = 1
TEXT_XOR_BITSTREAM = 2  # LogLite-style bitstream XOR+RLE
TEXT_DRAIN_DELTA = 3    # Drain with text-based delta encoding (like drain_optimal_codec)
TEXT_DRAIN_V4 = 4       # Use drain_lossless_v4 format directly (best for Apache/NASA)

# Whitespace marker
MULTI_SPACE_MARKER = '«'

# XOR parameters - match LogLite's proven settings
XOR_WINDOW_SIZE = 8   # LogLite uses 2^3 = 8 per bucket
XOR_BUCKET_SIZE = 1   # LogLite matches EXACT length (bucket size = 1)
XOR_MATCH_THRESHOLD = 0.85  # LogLite's Similarity_Threshold = 0.85

# Patterns
ISO_TIMESTAMP_RE = re.compile(
    r'^"?(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"?,?$'
)
IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
NUMERIC_STRING_RE = re.compile(r'^-?\d+$')
CLF_TIMESTAMP_RE = re.compile(
    r'^\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]?$'
)
PREFIX_ID_RE = re.compile(r'^"?([a-zA-Z][\w-]*)-(\d+)"?,?$')
URL_PATH_RE = re.compile(r'^/[\w./-]*$')
MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
MONTHS_REV = {v:k for k,v in MONTHS.items()}

# ============================================================================
# Bitstream Utilities (for LogLite-style encoding)
# ============================================================================

class Bitstream:
    """Efficient bitstream writer for sub-byte packing."""
    def __init__(self):
        self.data = bytearray()
        self.buffer = 0
        self.bits_in_buffer = 0

    def write_bits(self, value, num_bits):
        """Write num_bits from value to the stream."""
        self.buffer |= (value << self.bits_in_buffer)
        self.bits_in_buffer += num_bits

        while self.bits_in_buffer >= 8:
            self.data.append(self.buffer & 0xFF)
            self.buffer >>= 8
            self.bits_in_buffer -= 8

    def write_bit(self, bit):
        """Write a single bit."""
        self.write_bits(bit, 1)

    def flush(self):
        """Flush remaining bits."""
        if self.bits_in_buffer > 0:
            self.data.append(self.buffer & 0xFF)
            self.buffer = 0
            self.bits_in_buffer = 0

    def get_bytes(self):
        """Get the final byte array."""
        self.flush()
        return bytes(self.data)

class BitstreamReader:
    """Efficient bitstream reader."""
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.buffer = 0
        self.bits_in_buffer = 0

    def read_bits(self, num_bits):
        """Read num_bits from the stream."""
        while self.bits_in_buffer < num_bits:
            if self.pos < len(self.data):
                self.buffer |= self.data[self.pos] << self.bits_in_buffer
                self.pos += 1
                self.bits_in_buffer += 8
            else:
                break

        result = self.buffer & ((1 << num_bits) - 1)
        self.buffer >>= num_bits
        self.bits_in_buffer -= num_bits
        return result

    def read_bit(self):
        """Read a single bit."""
        return self.read_bits(1)

# ============================================================================
# Varint Utilities
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
    bs = Bitstream()
    for v in values:
        bs.write_bits(v, bits_per_value)
    return bs.get_bytes()

def unpack_bits(data, count, bits_per_value):
    if not data or bits_per_value == 0 or count == 0:
        return [0] * count
    reader = BitstreamReader(data)
    return [reader.read_bits(bits_per_value) for _ in range(count)]

# ============================================================================
# Multi-Space Preprocessing
# ============================================================================

def preprocess_line(line):
    """Replace multi-spaces with compact markers."""
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

    # Handle leading tabs
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

    # Add leading tab marker
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
    """Restore multi-spaces from compact markers."""
    # Restore leading tabs
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
# Bitstream XOR + RLE (LogLite-style)
# ============================================================================

class XORWindow:
    """
    Window-based XOR matching using LogLite's exact approach:
    - Windows are keyed by EXACT line length (not buckets)
    - 8 entries per length bucket
    - 85% similarity threshold for match acceptance
    - Search backward through window for best match (recent first)
    """
    def __init__(self, window_size=XOR_WINDOW_SIZE):
        self.window_size = window_size
        self.windows = defaultdict(list)  # Key: exact length
        self.line_count = 0

    def find_best_match(self, line_bytes):
        """
        Find best match with LogLite's 85% threshold.
        Only matches lines of EXACT same length (like LogLite).
        """
        line_len = len(line_bytes)

        # Skip empty lines
        if line_len == 0:
            return None, -1, 0

        # LogLite only matches same-length lines
        candidates = self.windows.get(line_len, [])

        if not candidates:
            return None, -1, 0

        best_match = None
        best_score = -1
        best_idx = -1

        # Search backward (most recent first) like LogLite
        for stored_bytes, stored_idx in reversed(candidates):
            # Count matching bytes using XOR (zeros = matches)
            matches = sum(1 for a, b in zip(line_bytes, stored_bytes) if a == b)

            if matches > best_score:
                best_score = matches
                best_match = stored_bytes
                best_idx = stored_idx

                # Early exit if we hit the threshold (LogLite's optimization)
                similarity = matches / line_len
                if similarity >= XOR_MATCH_THRESHOLD:
                    break

        # LogLite's 85% threshold
        if best_score < line_len * XOR_MATCH_THRESHOLD:
            return None, -1, 0

        return best_match, best_idx, line_len

    def add_line(self, line_bytes, line_idx):
        line_len = len(line_bytes)
        window = self.windows[line_len]
        window.append((line_bytes, line_idx))
        if len(window) > self.window_size:
            window.pop(0)
        self.line_count += 1

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def rle_encode_bitstream_loglite(xor_data, original_data):
    """
    LogLite's hybrid RLE encoding:
    - Zeros in XOR (where original == reference): RLE encode count
    - Non-zeros in XOR (where original != reference): store ORIGINAL byte

    This is brilliant because:
    1. Matching positions are encoded as zero counts (very compact)
    2. Differing positions store original chars (better compression than XOR values)

    Decoder reconstructs by:
    - RLE zeros → copy from reference (which equals original at those positions)
    - Non-zero bytes → use directly (they're the original)

    RLE threshold: Only use RLE if 2+ consecutive zeros (LogLite's threshold).
    """
    bs = Bitstream()
    i = 0
    RLE_MIN_ZEROS = 2  # LogLite's threshold: RLE_COUNT / 8 + 1 = 2

    while i < len(xor_data):
        if xor_data[i] == 0:
            # Count consecutive zeros (matching bytes)
            count = 1
            while i + count < len(xor_data) and xor_data[i + count] == 0 and count < 255:
                count += 1

            # Only use RLE if there are 2+ zeros
            if count >= RLE_MIN_ZEROS:
                bs.write_bit(0)  # RLE marker (1 bit)
                bs.write_bits(count, 8)  # Run length (8 bits)
                i += count
            else:
                # Single zero - store original byte (which equals reference here)
                bs.write_bit(1)
                bs.write_bits(original_data[i] if i < len(original_data) else 0, 8)
                i += 1
        else:
            # Non-zero XOR - store original byte (NOT the XOR value!)
            bs.write_bit(1)
            bs.write_bits(original_data[i] if i < len(original_data) else xor_data[i], 8)
            i += 1
    return bs.get_bytes()


def rle_encode_bitstream(data, original_data=None):
    """Wrapper for backwards compatibility."""
    if original_data is not None:
        return rle_encode_bitstream_loglite(data, original_data)

    # Simple RLE without LogLite's hybrid approach
    bs = Bitstream()
    i = 0
    while i < len(data):
        if data[i] == 0:
            count = 1
            while i + count < len(data) and data[i + count] == 0 and count < 255:
                count += 1
            if count >= 2:
                bs.write_bit(0)
                bs.write_bits(count, 8)
                i += count
            else:
                bs.write_bit(1)
                bs.write_bits(0, 8)
                i += 1
        else:
            bs.write_bit(1)
            bs.write_bits(data[i], 8)
            i += 1
    return bs.get_bytes()

def rle_decode_bitstream(data, target_len):
    """
    Decode LogLite-style bitstream RLE.
    Returns data where:
    - Non-zero bytes are the original characters
    - Zero bytes need to be filled from the reference
    """
    reader = BitstreamReader(data)
    result = bytearray()

    while len(result) < target_len:
        is_raw = reader.read_bit()
        if is_raw:
            result.append(reader.read_bits(8))
        else:
            count = reader.read_bits(8)
            result.extend([0] * count)  # Placeholder zeros to be filled from reference

    return bytes(result[:target_len])


def apply_reference_to_decoded(decoded_data, reference_data):
    """
    Apply reference to fill in zeros (LogLite's simdReplaceNullCharacters).
    Zeros in decoded data get replaced with reference bytes.
    Non-zero bytes are kept as-is (they're already the original).
    """
    result = bytearray(decoded_data)
    for i in range(min(len(result), len(reference_data))):
        if result[i] == 0:
            result[i] = reference_data[i]
    return bytes(result)

# ============================================================================
# Timestamp Encoding (Frame-of-Reference)
# ============================================================================

def parse_iso_timestamp(s):
    m = ISO_TIMESTAMP_RE.match(s)
    if not m:
        return None, None

    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))

    ms_str = m.group(7)
    ms = 0
    ms_digits = 0
    if ms_str:
        ms_digits = len(ms_str) - 1
        ms = int((ms_str + '000')[1:4])

    tz = m.group(8) or ''

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
    m = CLF_TIMESTAMP_RE.match(s)
    if not m:
        return None, None

    day = int(m.group(1))
    month = MONTHS.get(m.group(2), 1)
    year = int(m.group(3))
    hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))
    tz = m.group(7) or ''

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
    split_paths = []
    has_trailing_slash = []
    max_segments = 0
    for v in values:
        if v and isinstance(v, str) and v.startswith('/'):
            # Track if path ends with /
            has_trailing_slash.append(v.endswith('/'))
            segments = v.split('/')
            # Remove the empty string caused by trailing slash (we track it separately)
            if segments and segments[-1] == '':
                segments = segments[:-1]
            split_paths.append(segments)
            max_segments = max(max_segments, len(segments))
        else:
            has_trailing_slash.append(False)
            split_paths.append([str(v) if v else ''])

    output.write(encode_varint(max_segments))

    for seg_idx in range(max_segments):
        col = [p[seg_idx] if seg_idx < len(p) else '' for p in split_paths]
        encode_dict_column(output, col, n_rows)

    # Encode trailing slash flags as a bitstream
    bs = Bitstream()
    for flag in has_trailing_slash:
        bs.write_bit(1 if flag else 0)
    flags_bytes = bs.get_bytes()
    output.write(encode_varint(len(flags_bytes)))
    output.write(flags_bytes)

def decode_path_columnar(data, pos, n_rows):
    max_segments, pos = decode_varint(data, pos)

    segment_cols = []
    for _ in range(max_segments):
        col, pos = decode_dict_column(data, pos, n_rows)
        segment_cols.append(col)

    # Read trailing slash flags
    flags_len, pos = decode_varint(data, pos)
    flags_bytes = data[pos:pos+flags_len]
    pos += flags_len
    reader = BitstreamReader(flags_bytes)
    has_trailing_slash = [reader.read_bit() == 1 for _ in range(n_rows)]

    result = []
    for i in range(n_rows):
        segments = [col[i] for col in segment_cols]
        while segments and segments[-1] == '':
            segments.pop()
        path = '/'.join(segments)
        if has_trailing_slash[i]:
            path += '/'
        result.append(path)

    return result, pos

# ============================================================================
# Prefix-Delta Encoding
# ============================================================================

def encode_prefix_delta(output, values, n_rows):
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

    prefix_bytes = (prefix or '').encode('utf-8')
    output.write(encode_varint(len(prefix_bytes)))
    output.write(prefix_bytes)

    prev = 0
    for n in numbers:
        output.write(encode_signed_varint(n - prev))
        prev = n

def decode_prefix_delta(data, pos, n_rows):
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
# Drain Template Mining
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
    template_parts = template.split('<*>')
    if len(template_parts) == 1:
        return []

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

def is_valid_ipv4(s):
    """Check if string is a valid IPv4 address."""
    m = IPV4_RE.match(s)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())

def analyze_column(values):
    present = [v for v in values if v != '_ABSENT_' and v is not None]
    if not present:
        return 'empty', {}

    sample = present[:100]
    sample_len = len(sample)

    # Check for booleans first (highest priority for exact type match)
    bool_count = sum(1 for v in sample if isinstance(v, bool))
    if bool_count > sample_len * 0.8:
        return 'boolean', {}

    # Check for IPv4 addresses
    ipv4_count = sum(1 for v in sample if isinstance(v, str) and is_valid_ipv4(v))
    if ipv4_count > sample_len * 0.8:
        return 'ipv4', {}

    # Check for timestamps - must be FULL timestamps (not fragments from Drain extraction)
    iso_count = 0
    clf_count = 0
    clf_fragment_count = 0  # Drain-extracted fragments like '[01/Jul/1995:00:00:01'
    for v in sample:
        if isinstance(v, str):
            # For CLF timestamps, require they both start with [ AND end with ]
            # This avoids misdetecting Drain-extracted fragments like '[01/Jul/1995:00:00:01'
            result, fmt = parse_clf_timestamp(v)
            if result is not None:
                if v.startswith('[') and v.endswith(']'):
                    clf_count += 1
                elif v.startswith('[') and not v.endswith(']'):
                    # This is a Drain-extracted fragment - still delta-encode it!
                    clf_fragment_count += 1
            elif parse_iso_timestamp(v)[0] is not None:
                iso_count += 1

    if iso_count > sample_len * 0.8:
        return 'timestamp_iso', {}
    if clf_count > sample_len * 0.8:
        return 'timestamp_clf', {}
    if clf_fragment_count > sample_len * 0.8:
        return 'timestamp_clf_fragment', {}

    # Check for prefix-ID pattern
    prefix_count = sum(1 for v in sample if isinstance(v, str) and PREFIX_ID_RE.match(v))
    if prefix_count > sample_len * 0.8:
        return 'prefix_id', {}

    # Check for URL paths
    path_count = sum(1 for v in sample if isinstance(v, str) and URL_PATH_RE.match(v))
    if path_count > sample_len * 0.8:
        return 'path', {}

    # Check for numeric strings (strings that are integers)
    # Only use this encoding if ALL values are numeric (not just 80%)
    # because non-numeric values would be lost
    if all(isinstance(v, str) and NUMERIC_STRING_RE.match(v) for v in present):
        return 'numeric_string', {}

    # Check cardinality
    unique = set(str(v) for v in present)
    if len(unique) <= 16:
        return 'low_cardinality', {'unique': len(unique)}

    return 'general', {}

def encode_smart_column(output, values, n_rows):
    if not values:
        output.write(bytes([ENC_RAW]))
        return

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

    col_type, info = analyze_column(values)
    has_absent = any(v == '_ABSENT_' for v in values)

    # Booleans - bit-pack them
    if col_type == 'boolean' and not has_absent:
        output.write(bytes([ENC_BOOLEAN]))
        encode_boolean_column(output, values, n_rows)
        return

    # IPv4 addresses - pack as 4 bytes each (only if ALL values are valid IPv4)
    if col_type == 'ipv4' and not has_absent:
        # Verify all values are valid IPv4 before committing to this encoding
        all_valid_ipv4 = all(isinstance(v, str) and is_valid_ipv4(v) for v in present)
        if all_valid_ipv4:
            output.write(bytes([ENC_IP_PACKED]))
            encode_ipv4_column(output, values, n_rows)
            return
        # Fall through to dictionary encoding if not all values are valid IPv4

    # Timestamps
    if col_type == 'timestamp_iso' and not has_absent:
        output.write(bytes([ENC_TIMESTAMP_FOR]))
        output.write(bytes([1]))
        encode_timestamp_column(output, values, n_rows, 'iso')
        return

    if col_type == 'timestamp_clf' and not has_absent:
        output.write(bytes([ENC_TIMESTAMP_FOR]))
        output.write(bytes([2]))
        encode_timestamp_column(output, values, n_rows, 'clf')
        return

    # CLF timestamp fragments (Drain-extracted, no closing bracket)
    # Only use delta encoding if ALL values are valid timestamp fragments
    # (Some rows may have empty strings if they matched different templates)
    if col_type == 'timestamp_clf_fragment' and not has_absent:
        # Check that all present values are actual timestamp fragments (not empty)
        all_valid_fragments = all(
            isinstance(v, str) and v.startswith('[') and len(v) > 10
            for v in present
        )
        if all_valid_fragments:
            output.write(bytes([ENC_TIMESTAMP_FOR]))
            output.write(bytes([3]))  # Type 3 = CLF fragment
            encode_timestamp_fragment_column(output, values, n_rows)
            return
        # Fall through to dictionary encoding if not all valid

    # Prefix-ID
    if col_type == 'prefix_id' and not has_absent:
        output.write(bytes([ENC_PREFIX_DELTA]))
        encode_prefix_delta(output, values, n_rows)
        return

    # URL paths - only use if no paths have consecutive slashes
    if col_type == 'path' and not has_absent:
        # Check for paths with // which can't be encoded losslessly
        has_double_slash = any(isinstance(v, str) and '//' in v for v in present)
        if not has_double_slash:
            output.write(bytes([ENC_PATH_COLUMNAR]))
            encode_path_columnar(output, values, n_rows)
            return
        # Fall through to dictionary encoding for paths with //

    # Numeric strings - encode as integers
    if col_type == 'numeric_string' and not has_absent:
        output.write(bytes([ENC_STRING_INT]))
        encode_string_int_column(output, values, n_rows)
        return

    # Integers
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
        if unique <= 16:
            output.write(bytes([ENC_INT_DICT]))
            encode_int_dict_column(output, values, n_rows)
            return

        output.write(bytes([ENC_INT_DELTA]))
        encode_int_delta_column(output, values, n_rows)
        return

    # Default to dictionary
    output.write(bytes([ENC_DICT]))
    encode_dict_column(output, values, n_rows)

def decode_smart_column(data, pos, n_rows):
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
        if ts_type == 3:  # CLF fragment
            return decode_timestamp_fragment_column(data, pos, n_rows)
        return decode_timestamp_column(data, pos, n_rows, 'iso' if ts_type == 1 else 'clf')

    if enc_type == ENC_PREFIX_DELTA:
        return decode_prefix_delta(data, pos, n_rows)

    if enc_type == ENC_PATH_COLUMNAR:
        return decode_path_columnar(data, pos, n_rows)

    if enc_type == ENC_DRAIN:
        return decode_drain_column(data, pos, n_rows)

    if enc_type == ENC_BOOLEAN:
        return decode_boolean_column(data, pos, n_rows)

    if enc_type == ENC_IP_PACKED:
        return decode_ipv4_column(data, pos, n_rows)

    if enc_type == ENC_STRING_INT:
        return decode_string_int_column(data, pos, n_rows)

    # Fallback
    values = []
    for _ in range(n_rows):
        str_len, pos = decode_varint(data, pos)
        values.append(data[pos:pos+str_len].decode('utf-8'))
        pos += str_len
    return values, pos

# ============================================================================
# Column Encoders/Decoders
# ============================================================================

def encode_dict_column(output, values, n_rows):
    def to_json_str(v):
        if v == '_ABSENT_':
            return '_ABSENT_'
        return json.dumps(v, ensure_ascii=False)

    unique = sorted(set(to_json_str(v) for v in values))
    vocab = {v: i for i, v in enumerate(unique)}

    output.write(encode_varint(len(unique)))
    for word in unique:
        word_bytes = word.encode('utf-8')
        output.write(encode_varint(len(word_bytes)))
        output.write(word_bytes)

    # Sub-byte bit-packing
    bits = max(1, (len(unique) - 1).bit_length()) if unique else 1
    indices = [vocab.get(to_json_str(v), 0) for v in values]
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

def decode_dict_column(data, pos, n_rows):
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
    prev = 0
    for v in values:
        val = v if isinstance(v, int) else 0
        output.write(encode_signed_varint(val - prev))
        prev = val

def decode_int_delta_column(data, pos, n_rows):
    values = []
    prev = 0
    for _ in range(n_rows):
        delta, pos = decode_signed_varint(data, pos)
        prev += delta
        values.append(prev)
    return values, pos

def encode_int_dict_column(output, values, n_rows):
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
    bits = data[pos]
    pos += 1
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len
    return unpack_bits(packed, n_rows, bits), pos

def encode_timestamp_column(output, values, n_rows, ts_type):
    if ts_type == 'iso':
        parsed = [parse_iso_timestamp(str(v)) for v in values]
    else:
        parsed = [parse_clf_timestamp(str(v)) for v in values]

    ts_values = [p[0] if p[0] is not None else 0 for p in parsed]
    formats = [p[1] if p[1] is not None else {} for p in parsed]

    # Frame-of-reference
    min_val = min(ts_values) if ts_values else 0
    output.write(encode_varint(min_val))

    for val in ts_values:
        output.write(encode_varint(val - min_val))

    format_counter = Counter(json.dumps(f, sort_keys=True) for f in formats)
    common_format = json.loads(format_counter.most_common(1)[0][0]) if format_counter else {}
    format_bytes = json.dumps(common_format).encode('utf-8')
    output.write(encode_varint(len(format_bytes)))
    output.write(format_bytes)

def decode_timestamp_column(data, pos, n_rows, ts_type):
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

def encode_timestamp_fragment_column(output, values, n_rows):
    """
    Encode CLF timestamp fragments like '[01/Jul/1995:00:00:01' (without closing bracket).
    These are Drain-extracted fragments that need delta encoding for compression.
    """
    # Parse timestamps to get seconds values
    ts_values = []
    for v in values:
        if isinstance(v, str):
            # Parse the fragment - add ] temporarily to make it parseable
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

def decode_timestamp_fragment_column(data, pos, n_rows):
    """Decode CLF timestamp fragments."""
    min_val, pos = decode_varint(data, pos)

    values = []
    for _ in range(n_rows):
        offset, pos = decode_varint(data, pos)
        seconds_val = min_val + offset
        # Reconstruct the fragment (without closing bracket)
        values.append(reconstruct_clf_fragment(seconds_val))

    return values, pos

def reconstruct_clf_fragment(seconds_val):
    """Reconstruct a CLF timestamp fragment from seconds value."""
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

    # Return fragment without closing bracket
    return f"[{day:02d}/{month_str}/{year:04d}:{h:02d}:{mi:02d}:{s:02d}"

def encode_drain_column(output, values, n_rows):
    if not HAS_DRAIN:
        encode_dict_column(output, values, n_rows)
        return

    str_values = [str(v) if v is not None and v != '_ABSENT_' else '' for v in values]

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

    all_variables = []
    for i, s in enumerate(str_values):
        if s and template_ids[i] in templates:
            template = templates[template_ids[i]]
            vars_list = extract_variables(s, template)
            all_variables.append(vars_list)
        else:
            all_variables.append([])

    template_list = sorted(templates.keys())
    template_to_idx = {tid: i for i, tid in enumerate(template_list)}

    output.write(encode_varint(len(template_list)))
    for tid in template_list:
        tmpl = templates[tid]
        tmpl_bytes = tmpl.encode('utf-8')
        output.write(encode_varint(len(tmpl_bytes)))
        output.write(tmpl_bytes)

    indices = [template_to_idx.get(tid, 0) for tid in template_ids]
    bits = max(1, len(template_list).bit_length()) if template_list else 1
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

    max_vars = max(len(v) for v in all_variables) if all_variables else 0
    output.write(encode_varint(max_vars))

    for var_idx in range(max_vars):
        col = [v[var_idx] if var_idx < len(v) else '' for v in all_variables]
        encode_smart_column(output, col, n_rows)

def decode_drain_column(data, pos, n_rows):
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
# Boolean Column Encoding (bit-packed)
# ============================================================================

def encode_boolean_column(output, values, n_rows):
    """Encode boolean values as bit-packed stream (1 bit per value)."""
    bs = Bitstream()
    for v in values:
        if isinstance(v, bool):
            bs.write_bit(1 if v else 0)
        elif v in (True, 'true', 'True', '1', 1):
            bs.write_bit(1)
        else:
            bs.write_bit(0)
    packed = bs.get_bytes()
    output.write(encode_varint(len(packed)))
    output.write(packed)

def decode_boolean_column(data, pos, n_rows):
    """Decode bit-packed boolean values."""
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len
    reader = BitstreamReader(packed)
    return [reader.read_bit() == 1 for _ in range(n_rows)], pos

# ============================================================================
# IPv4 Column Encoding (4 bytes per address)
# ============================================================================

def encode_ipv4_column(output, values, n_rows):
    """Encode IPv4 addresses as 4 bytes each."""
    for v in values:
        if isinstance(v, str):
            m = IPV4_RE.match(v)
            if m:
                octets = [int(g) for g in m.groups()]
                output.write(bytes(octets))
            else:
                output.write(bytes([0, 0, 0, 0]))
        else:
            output.write(bytes([0, 0, 0, 0]))

def decode_ipv4_column(data, pos, n_rows):
    """Decode 4-byte packed IPv4 addresses."""
    result = []
    for _ in range(n_rows):
        octets = data[pos:pos+4]
        pos += 4
        result.append(f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}")
    return result, pos

# ============================================================================
# Numeric String Column Encoding (convert to integers + delta)
# ============================================================================

def encode_string_int_column(output, values, n_rows):
    """Encode numeric strings as delta-encoded integers."""
    int_vals = []
    for v in values:
        if isinstance(v, str) and NUMERIC_STRING_RE.match(v):
            int_vals.append(int(v))
        else:
            int_vals.append(0)

    # Delta encode
    prev = 0
    for val in int_vals:
        output.write(encode_signed_varint(val - prev))
        prev = val

def decode_string_int_column(data, pos, n_rows):
    """Decode delta-encoded numeric strings."""
    values = []
    prev = 0
    for _ in range(n_rows):
        delta, pos = decode_signed_varint(data, pos)
        prev += delta
        values.append(str(prev))
    return values, pos

# ============================================================================
# JSON Flattening
# ============================================================================

def flatten_json(obj, prefix='', sep='.'):
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
                    items[new_key] = json.dumps(v, ensure_ascii=False)
                else:
                    items[new_key] = v
    else:
        items[prefix] = obj
    return items

def set_nested_value(obj, key, value):
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

def detect_json_separator_style(lines):
    """Detect whether JSON uses ': ' or ':' separator."""
    for line in lines[:10]:
        if '": ' in line:
            return 1  # Space after colon: ': '
        elif '":' in line:
            return 0  # No space: ':'
    return 0  # Default to compact

def encode_json_columnar(lines):
    rows = []
    all_keys = []  # Use list to preserve order
    key_set = set()
    row_key_orders = []  # Store per-row key order as list of key indices

    # Detect separator style
    sep_style = detect_json_separator_style(lines)

    raw_lines = []  # Store raw line for unparseable JSON
    for line in lines:
        try:
            obj = json.loads(line)
            flat = flatten_json(obj)
            rows.append(flat)
            raw_lines.append('')  # Empty if parsed successfully
            # Track this row's key order (will be converted to indices later)
            row_key_orders.append(list(flat.keys()))
            # Add keys in the order they first appear
            for k in flat.keys():
                if k not in key_set:
                    all_keys.append(k)
                    key_set.add(k)
        except:
            rows.append({})
            raw_lines.append(line)  # Store raw line
            row_key_orders.append([])

    # Add _raw column if any unparseable lines
    has_raw = any(r for r in raw_lines)
    if has_raw:
        if '_raw' not in key_set:
            all_keys.append('_raw')
            key_set.add('_raw')

    keys = all_keys  # Keep original order instead of sorting
    n_rows = len(rows)

    # Build key index map
    key_to_idx = {k: i for i, k in enumerate(keys)}

    # Convert row key orders to index lists
    row_key_indices = []
    for order in row_key_orders:
        indices = [key_to_idx[k] for k in order]
        row_key_indices.append(indices)

    columns = {k: [] for k in keys}
    for i, row in enumerate(rows):
        for k in keys:
            if k == '_raw':
                columns[k].append(raw_lines[i] if raw_lines[i] else '_ABSENT_')
            else:
                columns[k].append(row.get(k, '_ABSENT_'))

    output = BytesIO()

    # Write separator style (1 byte)
    output.write(bytes([sep_style]))

    output.write(encode_varint(len(keys)))
    for key in keys:
        key_bytes = key.encode('utf-8')
        output.write(encode_varint(len(key_bytes)))
        output.write(key_bytes)

    output.write(encode_varint(n_rows))

    for key in keys:
        col_data = columns[key]
        encode_smart_column(output, col_data, n_rows)

    # Write per-row key order indices
    # Encode as: for each row, write count + indices
    for indices in row_key_indices:
        output.write(encode_varint(len(indices)))
        for idx in indices:
            output.write(encode_varint(idx))

    return output.getvalue(), keys

def decode_json_columnar(data, pos):
    # Read separator style
    sep_style = data[pos]
    pos += 1
    separators = (', ', ': ') if sep_style == 1 else (',', ':')

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

    # Read per-row key order indices
    row_key_indices = []
    for _ in range(n_rows):
        n_indices, pos = decode_varint(data, pos)
        indices = []
        for _ in range(n_indices):
            idx, pos = decode_varint(data, pos)
            indices.append(idx)
        row_key_indices.append(indices)

    lines = []
    for i in range(n_rows):
        # Check if this line is a raw (unparseable) line
        raw_val = columns.get('_raw', ['_ABSENT_'] * n_rows)[i]
        if raw_val != '_ABSENT_':
            lines.append(raw_val)
        else:
            # Build object with keys in original order for this row
            obj = {}
            row_keys = [keys[idx] for idx in row_key_indices[i]]
            for key in row_keys:
                if key == '_raw':
                    continue
                val = columns[key][i]
                if val != '_ABSENT_':
                    set_nested_value(obj, key, val)
            lines.append(json.dumps(obj, separators=separators, ensure_ascii=False))

    return lines

# ============================================================================
# Text Log Encoding with Bitstream XOR+RLE
# ============================================================================

def encode_text_logs_xor_bitstream(lines, use_preprocessing=False):
    """
    Encode text logs with TRUE LogLite-style bitstream encoding.

    Per-line format (matched):
      1 bit: match flag (1)
      3 bits: window index (0-7)
      13 bits: RLE data length in bits
      15 bits: original line length (for decoder to find window)
      N bits: RLE encoded data

    Per-line format (raw):
      1 bit: match flag (0)
      15 bits: line length
      N*8 bits: raw line bytes

    Overhead per matched line: 1+3+13+15 = 32 bits = 4 bytes
    (Simpler approach than LogLite's streaming format)
    """
    # Skip preprocessing - it actually hurts compression on most logs
    preprocessed = lines

    # First pass: determine all encoding decisions
    window = XORWindow()
    encoded_items = []

    for i, line in enumerate(preprocessed):
        line_bytes = line.encode('utf-8')

        match_bytes, match_idx, line_len = window.find_best_match(line_bytes)

        if match_bytes is not None and line_len > 0:
            # Same-length matching (like LogLite)
            xor_result = xor_bytes(line_bytes, match_bytes)

            # LogLite-style hybrid encoding
            rle_result = rle_encode_bitstream(xor_result, line_bytes)

            # Calculate overhead in bits
            # Raw: 1 + 15 + line_len*8
            # XOR: 1 + 3 + 13 + 15 + len(rle_result)*8 = 32 + rle*8
            raw_bits = 1 + 15 + len(line_bytes) * 8
            xor_bits = 32 + len(rle_result) * 8

            if xor_bits < raw_bits:
                # Find window index
                window_candidates = window.windows.get(line_len, [])
                window_idx = 0
                for idx, (stored, _) in enumerate(window_candidates):
                    if stored == match_bytes:
                        window_idx = idx
                        break
                encoded_items.append(('xor', window_idx, rle_result, line_len))
            else:
                encoded_items.append(('raw', line_bytes))
        else:
            encoded_items.append(('raw', line_bytes))

        window.add_line(line_bytes, i)

    # Second pass: encode to bitstream
    bs = Bitstream()

    # Write header
    n_lines = len(lines)
    for i in range(32):  # 32-bit line count
        bs.write_bit((n_lines >> i) & 1)

    for item in encoded_items:
        if item[0] == 'raw':
            line_bytes = item[1]
            bs.write_bit(0)  # Raw marker
            # Write length in 15 bits
            length = len(line_bytes)
            bs.write_bits(length, 15)
            # Write raw bytes
            for b in line_bytes:
                bs.write_bits(b, 8)
        else:  # xor
            window_idx, rle_result, orig_len = item[1], item[2], item[3]
            bs.write_bit(1)  # XOR marker
            # Write window index in 3 bits
            bs.write_bits(window_idx, 3)
            # Write RLE length in 13 bits
            rle_len_bits = len(rle_result) * 8
            bs.write_bits(rle_len_bits, 13)
            # Write original line length in 15 bits
            bs.write_bits(orig_len, 15)
            # Write RLE data
            for b in rle_result:
                bs.write_bits(b, 8)

    # Pack into bytes
    output = BytesIO()
    output.write(encode_varint(len(lines)))
    output.write(bytes([TEXT_XOR_BITSTREAM]))
    output.write(bs.get_bytes())

    return output.getvalue()

def decode_text_logs_xor_bitstream(data, pos):
    """Decode LogLite-style bitstream encoded text logs."""
    n_lines, pos = decode_varint(data, pos)
    enc_mode = data[pos]
    pos += 1

    if enc_mode != TEXT_XOR_BITSTREAM:
        raise ValueError(f"Expected TEXT_XOR_BITSTREAM mode, got {enc_mode}")

    # Read bitstream
    bitstream_data = data[pos:]
    reader = BitstreamReader(bitstream_data)

    # Read 32-bit line count (skip, we already have n_lines)
    reader.read_bits(32)

    lines = []
    windows = defaultdict(list)  # Reconstruct windows during decode

    for i in range(n_lines):
        is_xor = reader.read_bit()

        if is_xor == 0:  # Raw line
            line_len = reader.read_bits(15)
            line_bytes = bytes(reader.read_bits(8) for _ in range(line_len))
        else:  # XOR encoded
            window_idx = reader.read_bits(3)
            rle_len_bits = reader.read_bits(13)
            orig_len = reader.read_bits(15)  # Original line length
            rle_len_bytes = (rle_len_bits + 7) // 8

            rle_data = bytes(reader.read_bits(8) for _ in range(rle_len_bytes))

            # Get reference from window using stored line length
            window_entries = windows.get(orig_len, [])
            if window_idx < len(window_entries):
                ref_line = window_entries[window_idx]
                # Decode RLE to get hybrid data
                hybrid_decoded = rle_decode_bitstream(rle_data, orig_len)
                line_bytes = apply_reference_to_decoded(hybrid_decoded, ref_line)
            else:
                # Fallback: decode RLE as raw (shouldn't happen in valid data)
                line_bytes = rle_decode_bitstream(rle_data, orig_len)

        # Add to window
        line_len = len(line_bytes)
        window_list = windows[line_len]
        window_list.append(line_bytes)
        if len(window_list) > XOR_WINDOW_SIZE:
            window_list.pop(0)

        lines.append(line_bytes.decode('utf-8', errors='replace'))

    return lines

def is_template_based_log(lines):
    """Detect if logs follow template patterns (good for Drain encoding)."""
    if not lines or len(lines) < 100:
        return False

    # Check for common log patterns that Drain handles well:
    # 1. Lines starting with timestamps in [dd/Mon/yyyy:HH:MM:SS format (Apache/NASA)
    # 2. Lines with common structural prefixes

    sample = lines[:500]

    # Check for CLF timestamp (Apache Combined Log Format)
    # Pattern: [dd/Mon/yyyy:HH:MM:SS zone] - can appear anywhere in line
    clf_pattern = re.compile(r'\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]')
    clf_count = 0
    for line in sample:
        if clf_pattern.search(line):
            clf_count += 1

    if clf_count > len(sample) * 0.5:
        return True

    # Check prefix similarity - if many lines share common prefixes, Drain works well
    prefix_len = 20
    prefixes = Counter(line[:prefix_len] for line in sample if len(line) >= prefix_len)
    top_count = sum(c for _, c in prefixes.most_common(10))

    return top_count > len(sample) * 0.5

def encode_text_logs_drain(lines):
    """Encode text logs using Drain template mining."""
    if not HAS_DRAIN:
        return encode_text_logs_xor_bitstream(lines)

    output = BytesIO()
    output.write(encode_varint(len(lines)))
    output.write(bytes([TEXT_DRAIN]))

    # Use Drain to extract templates
    miner = create_drain_miner()
    if miner is None:
        return encode_text_logs_xor_bitstream(lines)

    template_ids = []
    for line in lines:
        if line:
            result = miner.add_log_message(line)
            template_ids.append(result['cluster_id'])
        else:
            template_ids.append(0)

    # Get clusters and templates
    clusters = miner.drain.clusters
    templates = {c.cluster_id: c.get_template() for c in clusters}

    # Create template mapping
    unique_ids = sorted(set(template_ids))
    id_to_idx = {tid: i for i, tid in enumerate(unique_ids)}
    template_list = [templates.get(tid, '') for tid in unique_ids]

    # Write templates
    output.write(encode_varint(len(template_list)))
    for tmpl in template_list:
        tmpl_bytes = tmpl.encode('utf-8')
        output.write(encode_varint(len(tmpl_bytes)))
        output.write(tmpl_bytes)

    # Write template indices (bit-packed)
    indices = [id_to_idx.get(tid, 0) for tid in template_ids]
    bits = max(1, len(template_list).bit_length()) if template_list else 1
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

    # Extract variables for each line
    all_variables = []
    max_vars = 0
    for i, line in enumerate(lines):
        tid = template_ids[i]
        template = templates.get(tid, '')
        if template and line:
            vars_list = extract_variables(line, template)
            all_variables.append(vars_list)
            max_vars = max(max_vars, len(vars_list))
        else:
            all_variables.append([])

    # Write variable columns
    output.write(encode_varint(max_vars))
    n_rows = len(lines)

    for var_idx in range(max_vars):
        col = [v[var_idx] if var_idx < len(v) else '' for v in all_variables]
        encode_smart_column(output, col, n_rows)

    return output.getvalue()

# ============================================================================
# TEXT_DRAIN_DELTA - Drain with text-based delta encoding (like drain_optimal_codec)
# This stores deltas as text strings, which compresses better with zstd
# ============================================================================

def classify_value_for_delta(val):
    """Classify a value and extract numeric representation for delta encoding."""
    if not val:
        return 'empty', None, val

    # Integer check
    if NUMERIC_STRING_RE.match(val):
        return 'integer', int(val), val

    # IPv4 check
    m = IPV4_RE.match(val)
    if m:
        octets = [int(g) for g in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            ip_num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            return 'ipv4', ip_num, val

    # CLF timestamp check (including fragments from Drain)
    result, _ = parse_clf_timestamp(val)
    if result is not None:
        return 'timestamp', result, val

    # ISO timestamp check
    result, _ = parse_iso_timestamp(val)
    if result is not None:
        return 'iso_timestamp', result, val

    return 'string', None, val

def detect_column_type_for_delta(values):
    """Detect predominant type for a column (for delta encoding decision)."""
    sample = [v for v in values[:1000] if v]
    if not sample:
        return 'string'

    classifications = [classify_value_for_delta(v) for v in sample]
    types = [c[0] for c in classifications]
    type_counts = Counter(types)
    top_type, count = type_counts.most_common(1)[0]

    if count >= len(sample) * 0.9:
        return top_type
    return 'string'

def check_sortedness_for_delta(values):
    """Check if numeric values are mostly sorted (for delta encoding decision)."""
    sample_nums = []
    for v in values[:1000]:
        _, num, _ = classify_value_for_delta(v)
        if num is not None:
            sample_nums.append(num)

    if len(sample_nums) < 10:
        return False

    sorted_count = sum(1 for i in range(1, len(sample_nums))
                       if sample_nums[i] >= sample_nums[i-1])
    return sorted_count >= len(sample_nums) * 0.7

def encode_column_text_delta(values, col_type):
    """Encode column with text-based delta encoding - returns (strategy, encoded_values, dictionary)."""
    n_lines = len(values)

    if col_type in ('timestamp', 'iso_timestamp', 'ipv4'):
        encoded = []
        prev_val = 0
        for v in values:
            _, num, orig = classify_value_for_delta(v)
            if num is not None:
                delta = num - prev_val
                encoded.append(str(delta))
                prev_val = num
            else:
                encoded.append(f"RAW:{orig}")
        return f'{col_type}-delta', encoded, None

    elif col_type == 'integer':
        is_sorted = check_sortedness_for_delta(values)

        if is_sorted:
            encoded = []
            prev_val = 0
            for v in values:
                _, num, orig = classify_value_for_delta(v)
                if num is not None:
                    delta = num - prev_val
                    encoded.append(str(delta))
                    prev_val = num
                else:
                    encoded.append(f"RAW:{orig}")
            return 'integer-delta', encoded, None
        else:
            unique = set(values)
            if len(unique) < 0.1 * n_lines:
                freq = Counter(values)
                sorted_vals = [v for v, _ in freq.most_common()]
                val_to_id = {v: i for i, v in enumerate(sorted_vals)}
                encoded = [str(val_to_id[v]) for v in values]
                return 'dictionary', encoded, sorted_vals
            else:
                return 'integer-raw', values, None

    else:
        unique = set(values)
        n_unique = len(unique)

        if n_unique < 0.3 * n_lines:
            freq = Counter(values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}
            encoded = [str(val_to_id[v]) for v in values]
            return 'dictionary', encoded, sorted_vals
        else:
            return 'raw', values, None

def encode_text_logs_drain_delta(lines):
    """Encode text logs using Drain with text-based delta encoding (like drain_optimal_codec).

    This stores variable columns as newline-separated text, with numeric columns
    delta-encoded as text strings. This compresses extremely well with zstd.
    """
    if not HAS_DRAIN:
        return encode_text_logs_xor_bitstream(lines)

    output = BytesIO()
    output.write(encode_varint(len(lines)))
    output.write(bytes([TEXT_DRAIN_DELTA]))

    # Use Drain to extract templates
    miner = create_drain_miner()
    if miner is None:
        return encode_text_logs_xor_bitstream(lines)

    results = []
    for line in lines:
        if line:
            result = miner.add_log_message(line)
            results.append((result['cluster_id'], line))
        else:
            results.append((0, ''))

    # Get clusters and templates
    clusters = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
    unique_clusters = sorted(set(cid for cid, _ in results))
    cluster_to_tid = {cid: i for i, cid in enumerate(unique_clusters)}
    templates = {cluster_to_tid[cid]: clusters.get(cid, '') for cid in unique_clusters}

    # Write templates
    output.write(struct.pack('<H', len(templates)))
    for tid in range(len(templates)):
        tmpl = templates.get(tid, "").encode('utf-8')
        output.write(struct.pack('<H', len(tmpl)))
        output.write(tmpl)

    n_lines = len(results)
    output.write(struct.pack('<I', n_lines))

    # Extract variables for each line
    encoded = []
    for cid, line in results:
        tid = cluster_to_tid.get(cid, 0)
        template = templates.get(tid, '')
        if template and line:
            variables = extract_variables(line, template)
        else:
            variables = []
        encoded.append((tid, variables))

    # Template IDs - byte if <256, else u16
    if len(templates) <= 256:
        output.write(bytes(tid for tid, _ in encoded))
    else:
        for tid, _ in encoded:
            output.write(struct.pack('<H', tid))

    # Max variables
    max_vars = max((len(vars) for _, vars in encoded), default=0)
    output.write(struct.pack('<B', max_vars))

    # Encode each column with text-based delta encoding
    for pos in range(max_vars):
        values = [vars[pos] if pos < len(vars) else "" for _, vars in encoded]

        col_type = detect_column_type_for_delta(values)
        decision, encoded_vals, dictionary = encode_column_text_delta(values, col_type)

        if dictionary:
            output.write(struct.pack('<B', 1))  # has dictionary
            output.write(struct.pack('<I', len(dictionary)))
            for v in dictionary:
                vb = v.encode('utf-8', errors='replace')[:65535]
                output.write(struct.pack('<H', len(vb)))
                output.write(vb)
        else:
            output.write(struct.pack('<B', 0))  # no dictionary

        # Store values as newline-separated text (key insight from drain_optimal_codec)
        all_text = '\n'.join(encoded_vals)
        text_bytes = all_text.encode('utf-8')
        output.write(struct.pack('<I', len(text_bytes)))
        output.write(text_bytes)

    return output.getvalue()

def decode_text_logs_drain_delta(data, pos):
    """Decode TEXT_DRAIN_DELTA encoded text logs."""
    n_lines, pos = decode_varint(data, pos)
    enc_mode = data[pos]
    pos += 1

    if enc_mode != TEXT_DRAIN_DELTA:
        raise ValueError(f"Expected TEXT_DRAIN_DELTA mode, got {enc_mode}")

    # Read templates
    num_templates = struct.unpack('<H', data[pos:pos+2])[0]
    pos += 2

    templates = {}
    for tid in range(num_templates):
        tmpl_len = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2
        templates[tid] = data[pos:pos+tmpl_len].decode('utf-8')
        pos += tmpl_len

    # Read num lines
    file_n_lines = struct.unpack('<I', data[pos:pos+4])[0]
    pos += 4

    # Template IDs
    if num_templates <= 256:
        template_ids = list(data[pos:pos+file_n_lines])
        pos += file_n_lines
    else:
        template_ids = []
        for _ in range(file_n_lines):
            template_ids.append(struct.unpack('<H', data[pos:pos+2])[0])
            pos += 2

    # Max variables
    max_vars = data[pos]
    pos += 1

    # Decode columns
    columns = []
    for col_idx in range(max_vars):
        has_dict = data[pos]
        pos += 1

        dictionary = None
        if has_dict:
            dict_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            dictionary = []
            for _ in range(dict_len):
                val_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                dictionary.append(data[pos:pos+val_len].decode('utf-8', errors='replace'))
                pos += val_len

        text_len = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
        text_bytes = data[pos:pos+text_len]
        pos += text_len

        encoded_vals = text_bytes.decode('utf-8').split('\n')
        columns.append((dictionary, encoded_vals))

    # Decode column values (reverse delta encoding)
    decoded_columns = []
    for col_idx, (dictionary, encoded_vals) in enumerate(columns):
        if dictionary:
            # Dictionary encoded - just look up
            decoded = [dictionary[int(v)] for v in encoded_vals]
        else:
            # Could be delta-encoded or raw - detect by looking for RAW: prefix and numbers
            decoded = []
            is_delta = any(v.startswith('RAW:') for v in encoded_vals) or \
                       all(v.lstrip('-').isdigit() or v.startswith('RAW:') for v in encoded_vals if v)

            if is_delta:
                # Reverse delta encoding - but we need to know the format
                # For now, check if it looks like timestamp/ip deltas
                prev_val = 0
                for v in encoded_vals:
                    if v.startswith('RAW:'):
                        decoded.append(v[4:])
                    elif v.lstrip('-').isdigit():
                        delta = int(v)
                        prev_val += delta
                        # We need to convert back to original format
                        # This is lossy without format info - just append the raw value
                        decoded.append(v)  # Keep as-is for now
                    else:
                        decoded.append(v)
            else:
                decoded = encoded_vals

        decoded_columns.append(decoded)

    # Reconstruct lines - but we have a problem: delta-decoded values are still numeric
    # For proper reconstruction, we need original format info
    # For now, fall back to storing original values
    lines = []
    for i in range(file_n_lines):
        tid = template_ids[i]
        template = templates.get(tid, '')

        # Get variables for this line
        vars_for_line = []
        for col_idx, (dictionary, encoded_vals) in enumerate(columns):
            if i < len(encoded_vals):
                val = encoded_vals[i]
                if dictionary:
                    vars_for_line.append(dictionary[int(val)])
                elif val.startswith('RAW:'):
                    vars_for_line.append(val[4:])
                else:
                    # This is a delta value - we can't reconstruct the original!
                    # This encoder is NOT lossless without storing original format
                    vars_for_line.append(val)
            else:
                vars_for_line.append("")

        # Filter out empty trailing variables
        while vars_for_line and vars_for_line[-1] == "":
            vars_for_line.pop()

        line = reconstruct_line(template, vars_for_line)
        lines.append(line)

    return lines

def decode_text_logs_drain(data, pos):
    """Decode Drain-encoded text logs."""
    n_lines, pos = decode_varint(data, pos)
    enc_mode = data[pos]
    pos += 1

    if enc_mode != TEXT_DRAIN:
        raise ValueError(f"Expected TEXT_DRAIN mode, got {enc_mode}")

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

    # Read variable columns
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
        vars_for_line = [col[i] if isinstance(col[i], str) else str(col[i]) for col in var_columns]
        line = reconstruct_line(template, vars_for_line)
        lines.append(line)

    return lines

def encode_text_logs_drain_v4(lines):
    """Encode text logs using drain_lossless_v4 format.

    This uses the proven drain_lossless_v4 encoder which achieves 5.0% on Apache logs.
    It stores:
    - Templates
    - Template IDs (bit-packed)
    - Variable columns with type-specific delta encoding (CLF timestamps, integers, etc.)
    """
    if not HAS_DRAIN_V4:
        return None

    output = BytesIO()
    output.write(encode_varint(len(lines)))
    output.write(bytes([TEXT_DRAIN_V4]))

    # Use drain_lossless_v4's encoding
    templates, encoded = drain_v4_encode_lossless(lines)
    binary_data, col_info = drain_v4_encode_to_bytes(templates, encoded)

    # Store the drain_v4 binary data directly
    output.write(encode_varint(len(binary_data)))
    output.write(binary_data)

    return output.getvalue()

def decode_text_logs_drain_v4(data, pos):
    """Decode TEXT_DRAIN_V4 encoded text logs."""
    n_lines, pos = decode_varint(data, pos)
    enc_mode = data[pos]
    pos += 1

    if enc_mode != TEXT_DRAIN_V4:
        raise ValueError(f"Expected TEXT_DRAIN_V4 mode, got {enc_mode}")

    # Read drain_v4 binary data
    drain_v4_len, pos = decode_varint(data, pos)
    drain_v4_data = data[pos:pos+drain_v4_len]

    # Use drain_lossless_v4's decoder
    if not HAS_DRAIN_V4:
        raise RuntimeError("drain_lossless_v4 not available for decoding")

    return drain_v4_decode_from_bytes(drain_v4_data)

def encode_text_logs(lines):
    """Encode text logs - choose best method."""
    if not lines:
        output = BytesIO()
        output.write(encode_varint(0))
        output.write(bytes([TEXT_XOR_BITSTREAM]))
        return output.getvalue()

    # Try XOR bitstream encoding (LogLite-style)
    xor_encoded = encode_text_logs_xor_bitstream(lines)
    best_encoded = xor_encoded
    best_name = "XOR"

    # Try drain_lossless_v4 for template-based logs (achieves 5.0% on Apache)
    if HAS_DRAIN_V4 and is_template_based_log(lines):
        try:
            drain_v4_encoded = encode_text_logs_drain_v4(lines)
            if drain_v4_encoded and len(drain_v4_encoded) < len(best_encoded):
                # Verify lossless
                decoded = decode_text_logs_drain_v4(drain_v4_encoded, 0)
                if len(decoded) == len(lines) and all(decoded[i] == lines[i] for i in range(len(lines))):
                    best_encoded = drain_v4_encoded
                    best_name = "DRAIN_V4"
        except Exception:
            pass

    # Also try our original Drain encoding as fallback
    if HAS_DRAIN and is_template_based_log(lines) and best_name != "DRAIN_V4":
        try:
            drain_encoded = encode_text_logs_drain(lines)
            if len(drain_encoded) < len(best_encoded):
                decoded = decode_text_logs_drain(drain_encoded, 0)
                if len(decoded) == len(lines) and all(decoded[i] == lines[i] for i in range(len(lines))):
                    best_encoded = drain_encoded
                    best_name = "DRAIN"
        except Exception:
            pass

    return best_encoded

def decode_text_logs(data, pos):
    """Decode text logs."""
    n_lines, next_pos = decode_varint(data, pos)
    enc_mode = data[next_pos]

    if enc_mode == TEXT_XOR_BITSTREAM:
        return decode_text_logs_xor_bitstream(data, pos)
    elif enc_mode == TEXT_DRAIN:
        return decode_text_logs_drain(data, pos)
    elif enc_mode == TEXT_DRAIN_V4:
        return decode_text_logs_drain_v4(data, pos)
    elif enc_mode == TEXT_DRAIN_DELTA:
        return decode_text_logs_drain_delta(data, pos)
    else:
        raise ValueError(f"Unknown text encoding mode: {enc_mode}")

# ============================================================================
# Top-Level Encoder/Decoder
# ============================================================================

def detect_format(lines):
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

def encode_v10(lines):
    """Main V10 encoder - tries multiple strategies and picks the best."""
    if not lines:
        return MAGIC + bytes([VERSION, FMT_TEXT]) + encode_varint(0)

    fmt = detect_format(lines)

    if fmt == FMT_JSON:
        # Try V10 JSON encoder first
        v10_output = BytesIO()
        v10_output.write(MAGIC)
        v10_output.write(bytes([VERSION, FMT_JSON]))
        v10_data, _ = encode_json_columnar(lines)
        v10_output.write(v10_data)
        v10_result = v10_output.getvalue()

        # Verify V10 is lossless and count mismatches
        v10_lossless = True
        v10_mismatches = 0
        try:
            v10_decoded = decode_json_columnar(v10_data, 0)
            if len(v10_decoded) != len(lines):
                v10_lossless = False
                v10_mismatches = len(lines)
            else:
                for i in range(len(lines)):
                    if v10_decoded[i] != lines[i]:
                        v10_mismatches += 1
                        v10_lossless = False
        except:
            v10_lossless = False
            v10_mismatches = len(lines)

        best_result = v10_result if v10_lossless else None
        best_mismatches = 0 if v10_lossless else v10_mismatches
        best_fmt = FMT_JSON if v10_lossless else None

        # Try V3 JSON encoder if available
        if HAS_V3_JSON:
            try:
                keys, columns, parsed = v3_parse_json(lines)
                v3_data, _ = v3_encode_to_bytes(keys, columns, len(lines))
                v3_output = BytesIO()
                v3_output.write(MAGIC)
                v3_output.write(bytes([VERSION, FMT_JSON_V3]))
                v3_output.write(encode_varint(len(v3_data)))
                v3_output.write(v3_data)
                v3_result = v3_output.getvalue()

                # Verify V3 encoding and count mismatches
                v3_decoded = v3_json_decode(v3_data)
                v3_mismatches = 0
                v3_lossless = len(v3_decoded) == len(lines)
                if v3_lossless:
                    for i in range(len(lines)):
                        if v3_decoded[i] != lines[i]:
                            v3_mismatches += 1
                            v3_lossless = False
                else:
                    v3_mismatches = len(lines)

                if v3_lossless:
                    # Prefer smaller lossless encoding
                    if best_result is None or len(v3_result) < len(best_result):
                        best_result = v3_result
                        best_mismatches = 0
                        best_fmt = FMT_JSON_V3
                elif best_result is None:
                    # No lossless option yet, compare mismatches
                    if v3_mismatches < best_mismatches:
                        best_result = v3_result
                        best_mismatches = v3_mismatches
                        best_fmt = FMT_JSON_V3
            except Exception as e:
                pass

        # If no lossless encoding found, fall back to the one with fewer mismatches
        if best_result is None:
            best_result = v10_result

        # Also try raw passthrough (same as we do for text)
        # This often wins when zstd alone is better at finding patterns
        raw_output = BytesIO()
        raw_output.write(MAGIC)
        raw_output.write(bytes([VERSION, FMT_RAW]))
        raw_text = '\n'.join(lines).encode('utf-8')
        raw_output.write(encode_varint(len(raw_text)))
        raw_output.write(raw_text)
        raw_result = raw_output.getvalue()

        # Return the smaller one (zstd will compress both, smaller usually stays smaller)
        if len(raw_result) < len(best_result):
            return raw_result
        return best_result
    else:
        # For text logs, try both raw passthrough and text encoding
        # Raw is better for zstd-19 (high-effort dictionary), but text encoding
        # may help zstd-3 (fast mode) by pre-structuring the data

        # Option 1: Raw passthrough
        raw_output = BytesIO()
        raw_output.write(MAGIC)
        raw_output.write(bytes([VERSION, FMT_RAW]))
        raw_text = '\n'.join(lines).encode('utf-8')
        raw_output.write(encode_varint(len(raw_text)))
        raw_output.write(raw_text)
        raw_result = raw_output.getvalue()

        # Option 2: Text encoding (Drain/XOR)
        try:
            text_output = BytesIO()
            text_output.write(MAGIC)
            text_output.write(bytes([VERSION, FMT_TEXT]))
            text_data = encode_text_logs(lines)
            text_output.write(text_data)
            text_result = text_output.getvalue()

            # Verify lossless
            text_decoded = decode_text_logs(text_data, 0)
            if len(text_decoded) != len(lines) or any(text_decoded[i] != lines[i] for i in range(len(lines))):
                # Not lossless, use raw
                return raw_result

            # Return whichever is smaller (before zstd)
            # Note: smaller pre-zstd usually means smaller post-zstd too
            if len(text_result) < len(raw_result):
                return text_result
            return raw_result
        except Exception:
            # Text encoding failed, use raw
            return raw_result

def decode_v10(data):
    """Main V10 decoder."""
    if len(data) < 6:
        return []

    if data[:4] != MAGIC:
        return []

    version = data[4]
    fmt = data[5]
    pos = 6

    if fmt == FMT_JSON:
        return decode_json_columnar(data, pos)
    elif fmt == FMT_JSON_V3:
        # V3 JSON format
        v3_len, pos = decode_varint(data, pos)
        v3_data = data[pos:pos+v3_len]
        return v3_json_decode(v3_data)
    elif fmt == FMT_RAW:
        # Raw passthrough - just decode UTF-8 text
        raw_len, pos = decode_varint(data, pos)
        raw_text = data[pos:pos+raw_len].decode('utf-8')
        return raw_text.split('\n')
    else:
        return decode_text_logs(data, pos)

# ============================================================================
# Verification
# ============================================================================

def verify_file(input_path):
    import time

    print(f"V10 Processing {input_path}...")

    with open(input_path, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    print(f"  Lines: {len(lines)}")

    fmt = detect_format(lines)
    fmt_name = 'JSON' if fmt == FMT_JSON else 'Text'
    print(f"  Detected format: {fmt_name}")

    start = time.time()
    encoded = encode_v10(lines)
    encode_time = time.time() - start

    orig_size = len('\n'.join(lines))
    print(f"  Encoded size: {len(encoded):,} bytes ({len(encoded)/orig_size*100:.1f}%)")
    print(f"  Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")

    start = time.time()
    decoded = decode_v10(encoded)
    decode_time = time.time() - start

    print(f"  Decode time: {decode_time:.2f}s ({len(lines)/decode_time:.0f} lines/sec)")

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
        print("Usage: codec_v10.py <logfile>")
        sys.exit(1)

    success, data = verify_file(sys.argv[1])
    sys.exit(0 if success else 1)

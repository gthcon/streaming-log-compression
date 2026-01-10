#!/usr/bin/env python3
"""
V5 Unified Log Codec - Combines best strategies from all algorithms:

Key learnings incorporated:
1. LogLite: Variable-width encoding, XOR delta for similar strings
2. CLP: Dictionary-based log type encoding, timestamp specialization
3. Drain: Template mining for text logs, columnar variable storage
4. V3: Nested JSON recursive encoding, bitpacking
5. V4: Flattened columnar JSON, sparse column handling, grouped presence

Strategy selection:
- JSON logs: Use V4-style flattened columnar with sparse optimization
- Text logs: Use Drain template mining + LogLite-style variable encoding
- HTTP access logs: Specialized CLF/Combined parser with delta encoding
- Timestamps: Binary delta encoding (8 bytes for ms precision)
- IPs: 4-byte packed encoding
- Numbers: Varint + delta encoding
- Strings: Dictionary or raw based on cardinality
"""

import sys
import struct
import json
import re
import time
from collections import Counter, defaultdict
from datetime import datetime
from io import BytesIO

# Try to import drain3, fall back to simple template matching
try:
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig
    HAS_DRAIN = True
except ImportError:
    HAS_DRAIN = False

# ============================================================================
# Constants and Magic
# ============================================================================

MAGIC = b'LGV5'  # Log codec V5
VERSION = 1

# Format types
FMT_JSON_FLAT = 1      # Flat or simple nested JSON
FMT_JSON_NESTED = 2    # Deeply nested JSON (use recursive)
FMT_TEXT_SYSLOG = 3    # Syslog-style text
FMT_TEXT_HTTP = 4      # HTTP access logs (CLF/Combined)
FMT_TEXT_GENERIC = 5   # Generic text with Drain

# Column encoding types
ENC_RAW = 0
ENC_DICTIONARY = 1
ENC_DICT_VARLEN = 2      # Dictionary with variable-length indices
ENC_INTEGER_DELTA = 3
ENC_INTEGER_DICT = 4
ENC_TIMESTAMP_DELTA = 5  # 8-byte millisecond delta
ENC_TIMESTAMP_4BYTE = 6  # 4-byte second delta
ENC_IP_PACKED = 7        # 4-byte IPv4
ENC_BITPACK = 8          # Bitpacked small integers
ENC_SPARSE = 9           # Sparse column (indices + values)
ENC_BOOLEAN = 10
ENC_STRING_INT = 11      # Numeric strings as integers
ENC_XOR_DELTA = 12       # XOR delta for similar strings (LogLite-style)
ENC_TEMPLATE_VARS = 13   # Drain template variables

# Patterns
IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
ISO_TS_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')
CLF_TS_RE = re.compile(r'^\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]?$')
NUMERIC_RE = re.compile(r'^-?\d+$')
FLOAT_RE = re.compile(r'^-?\d+\.\d+$')

# HTTP log pattern (CLF/Combined)
HTTP_LOG_RE = re.compile(
    r'^(\S+)\s+'           # IP/host
    r'(\S+)\s+'            # ident
    r'(\S+)\s+'            # user
    r'\[([^\]]+)\]\s+'     # timestamp
    r'"([^"]*(?:""[^"]*)*)"\s+'  # request (handle escaped quotes)
    r'(\d+)\s+'            # status
    r'(\S+)'               # bytes
    r'(?:\s+"([^"]*)")?'   # referer (optional)
    r'(?:\s+"([^"]*)")?'   # user-agent (optional)
)

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
MONTHS_REV = {v:k for k,v in MONTHS.items()}

# ============================================================================
# Utility Functions
# ============================================================================

def encode_varint(n):
    """Encode unsigned integer as varint"""
    result = []
    while n >= 0x80:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n)
    return bytes(result)

def decode_varint(data, pos):
    """Decode varint, return (value, new_pos)"""
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
    """Encode signed integer using zigzag encoding"""
    zigzag = (n << 1) ^ (n >> 63)
    return encode_varint(zigzag)

def decode_signed_varint(data, pos):
    """Decode signed varint"""
    zigzag, pos = decode_varint(data, pos)
    return (zigzag >> 1) ^ (-(zigzag & 1)), pos

def pack_bits(values, bits_per_value):
    """Pack values into minimal bytes"""
    if not values or bits_per_value == 0:
        return b''

    result = bytearray()
    current_byte = 0
    bits_in_byte = 0

    for val in values:
        remaining_bits = bits_per_value
        while remaining_bits > 0:
            space = 8 - bits_in_byte
            take = min(space, remaining_bits)

            # Extract 'take' bits from val
            shift = remaining_bits - take
            bits = (val >> shift) & ((1 << take) - 1)

            current_byte |= bits << (space - take)
            bits_in_byte += take
            remaining_bits -= take

            if bits_in_byte == 8:
                result.append(current_byte)
                current_byte = 0
                bits_in_byte = 0

    if bits_in_byte > 0:
        result.append(current_byte)

    return bytes(result)

def unpack_bits(data, count, bits_per_value):
    """Unpack bitpacked values"""
    if not data or bits_per_value == 0 or count == 0:
        return [0] * count

    result = []
    bit_pos = 0

    for _ in range(count):
        val = 0
        remaining = bits_per_value

        while remaining > 0:
            byte_idx = bit_pos // 8
            bit_offset = bit_pos % 8
            available = 8 - bit_offset
            take = min(available, remaining)

            byte_val = data[byte_idx] if byte_idx < len(data) else 0
            shift = available - take
            bits = (byte_val >> shift) & ((1 << take) - 1)

            val = (val << take) | bits
            bit_pos += take
            remaining -= take

        result.append(val)

    return result

def parse_clf_timestamp(ts_str):
    """Parse CLF timestamp to milliseconds since epoch"""
    match = CLF_TS_RE.match(ts_str)
    if not match:
        return None
    day, mon, year, hour, minute, sec, tz = match.groups()
    try:
        dt = datetime(int(year), MONTHS.get(mon, 1), int(day),
                     int(hour), int(minute), int(sec))
        return int(dt.timestamp() * 1000)
    except:
        return None

def format_clf_timestamp(ms, tz_str='-0400'):
    """Format milliseconds to CLF timestamp"""
    dt = datetime.fromtimestamp(ms / 1000)
    return f"[{dt.day:02d}/{MONTHS_REV[dt.month]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} {tz_str}]"

def parse_iso_timestamp(ts_str):
    """Parse ISO timestamp to milliseconds"""
    match = ISO_TS_RE.match(ts_str.strip('"'))
    if not match:
        return None
    year, month, day, hour, minute, sec, frac, tz = match.groups()
    try:
        ms = 0
        if frac:
            ms = int(float(frac) * 1000)
        dt = datetime(int(year), int(month), int(day),
                     int(hour), int(minute), int(sec))
        return int(dt.timestamp() * 1000) + ms
    except:
        return None

def pack_ipv4(ip_str):
    """Pack IPv4 to 4 bytes"""
    match = IPV4_RE.match(ip_str)
    if not match:
        return None
    try:
        parts = [int(x) for x in match.groups()]
        if all(0 <= p <= 255 for p in parts):
            return bytes(parts)
    except:
        pass
    return None

def unpack_ipv4(data):
    """Unpack 4 bytes to IPv4 string"""
    return f"{data[0]}.{data[1]}.{data[2]}.{data[3]}"

# ============================================================================
# Format Detection
# ============================================================================

def detect_format(lines):
    """Detect log format from sample lines"""
    if not lines:
        return FMT_TEXT_GENERIC

    # Check first few lines
    sample = lines[:min(100, len(lines))]

    # Try JSON
    json_count = 0
    nested_depth = 0
    for line in sample:
        try:
            obj = json.loads(line)
            json_count += 1
            # Check nesting depth
            depth = get_json_depth(obj)
            nested_depth = max(nested_depth, depth)
        except:
            pass

    if json_count > len(sample) * 0.9:  # 90%+ JSON
        if nested_depth > 3:
            return FMT_JSON_NESTED
        return FMT_JSON_FLAT

    # Try HTTP access log
    http_count = 0
    for line in sample:
        if HTTP_LOG_RE.match(line):
            http_count += 1

    if http_count > len(sample) * 0.8:
        return FMT_TEXT_HTTP

    # Check for syslog pattern (Month Day Time Host Process)
    syslog_re = re.compile(r'^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+')
    syslog_count = sum(1 for line in sample if syslog_re.match(line))

    if syslog_count > len(sample) * 0.8:
        return FMT_TEXT_SYSLOG

    return FMT_TEXT_GENERIC

def get_json_depth(obj, current=0):
    """Get maximum nesting depth of JSON object"""
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(get_json_depth(v, current + 1) for v in obj.values())
    elif isinstance(obj, list):
        if not obj:
            return current
        return max(get_json_depth(v, current + 1) for v in obj)
    return current

# ============================================================================
# Column Type Detection
# ============================================================================

def detect_column_type(values, key_hint=None, preserve_strings=False):
    """Detect best encoding for a column of values.

    Args:
        values: List of values in the column
        key_hint: Optional key name hint for type detection
        preserve_strings: If True, don't convert numeric strings to integers
                         (important for lossless text log compression)
    """
    if not values:
        return ENC_RAW, {}

    # Filter out absent markers
    present = [v for v in values if v != '_ABSENT_']
    if not present:
        return ENC_SPARSE, {'present_count': 0}

    # Check sparsity
    sparsity = 1 - len(present) / len(values)
    if sparsity > 0.8:
        # Encode sparse column
        inner_type, inner_info = detect_column_type(present, key_hint, preserve_strings)
        return ENC_SPARSE, {'inner_type': inner_type, 'inner_info': inner_info,
                           'present_count': len(present)}

    # Check for booleans (must be actual bool type, not int 0/1)
    bool_vals = set()
    for v in present:
        if isinstance(v, bool):
            bool_vals.add(v)
        elif isinstance(v, str) and v.lower() in ('true', 'false'):
            bool_vals.add(v.lower() == 'true')
        else:
            break
    else:
        if bool_vals:
            return ENC_BOOLEAN, {}

    # Check for integers (only actual ints, not numeric strings in preserve mode)
    int_vals = []
    for v in present:
        if isinstance(v, int) and not isinstance(v, bool):
            int_vals.append(v)
        elif isinstance(v, str) and NUMERIC_RE.match(v) and not preserve_strings:
            # Only convert numeric strings if not preserving (JSON types get preserved)
            int_vals.append(int(v))
        else:
            break
    else:
        if int_vals:
            unique = len(set(int_vals))
            if unique < len(int_vals) * 0.1:  # High repetition
                return ENC_INTEGER_DICT, {'values': int_vals}

            # Check if delta encoding is efficient
            sorted_check = sorted(int_vals[:100])
            deltas = [sorted_check[i+1] - sorted_check[i] for i in range(len(sorted_check)-1)]
            if deltas and max(deltas) < 1000:
                return ENC_INTEGER_DELTA, {'values': int_vals}

            # Check if fits in bitpack
            max_val = max(int_vals)
            if max_val >= 0:
                bits = max_val.bit_length()
                if bits <= 16:
                    return ENC_BITPACK, {'bits': bits, 'values': int_vals}

            return ENC_INTEGER_DELTA, {'values': int_vals}

    # For timestamps, use dictionary encoding to preserve original format
    # (timestamp delta encoding is lossy due to format conversion)
    if key_hint and any(x in key_hint.lower() for x in ['time', 'date', 'ts', 'timestamp']):
        str_vals = [str(v) for v in present]
        unique = set(str_vals)
        # Timestamps usually have moderate cardinality - use dictionary
        if len(unique) < len(str_vals) * 0.9:  # Some repetition
            return ENC_DICTIONARY, {'unique': unique}

    # Check for IPs
    if key_hint and any(x in key_hint.lower() for x in ['ip', 'addr', 'host', 'client']):
        ip_vals = []
        for v in present:
            if isinstance(v, str):
                packed = pack_ipv4(v)
                if packed:
                    ip_vals.append(packed)
                else:
                    break
        else:
            if ip_vals and len(ip_vals) == len(present):
                return ENC_IP_PACKED, {'values': ip_vals}

    # String analysis
    str_vals = [str(v) for v in present]
    unique = set(str_vals)

    # Dictionary encoding for low cardinality
    if len(unique) < len(str_vals) * 0.5 or len(unique) < 256:
        return ENC_DICTIONARY, {'unique': unique}

    # Check for numeric strings
    if all(NUMERIC_RE.match(s) for s in str_vals):
        return ENC_STRING_INT, {}

    # XOR delta for similar strings (LogLite-style)
    if len(str_vals) > 10:
        # Check if strings have common prefixes/structure
        lens = [len(s) for s in str_vals]
        if max(lens) - min(lens) < 10:  # Similar lengths
            # Could use XOR delta
            return ENC_XOR_DELTA, {}

    return ENC_RAW, {}

# ============================================================================
# JSON Encoder (V4-style flattened columnar)
# ============================================================================

def flatten_json(obj, prefix='', sep='.'):
    """Flatten nested JSON to dot-notation keys"""
    items = {}

    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}{sep}{k}" if prefix else k
            if isinstance(v, dict):
                items.update(flatten_json(v, new_key, sep))
            elif isinstance(v, list):
                # Store list as JSON string for now (can optimize later)
                items[new_key] = json.dumps(v)
            else:
                items[new_key] = v
    else:
        items[prefix] = obj

    return items

def encode_json_columnar(lines):
    """Encode JSON logs using flattened columnar format"""
    # Parse and flatten all JSON, preserving key order
    rows = []
    all_keys = set()
    key_orders = []  # Track key order per row

    for line in lines:
        try:
            obj = json.loads(line)
            flat = flatten_json(obj)
            rows.append(flat)
            all_keys.update(flat.keys())
            # Preserve original key order
            key_orders.append(list(flat.keys()))
        except:
            rows.append({})
            key_orders.append([])

    # Sort keys for consistent column storage
    keys = sorted(all_keys)
    n_rows = len(rows)

    # Build columns
    columns = {k: [] for k in keys}
    for row in rows:
        for k in keys:
            columns[k].append(row.get(k, '_ABSENT_'))

    # Detect types and encode each column
    output = BytesIO()

    # Write header
    output.write(encode_varint(len(keys)))
    for key in keys:
        key_bytes = key.encode('utf-8')
        output.write(encode_varint(len(key_bytes)))
        output.write(key_bytes)

    output.write(encode_varint(n_rows))

    # Encode each column (preserve_strings=True to keep JSON types)
    for key in keys:
        col_data = columns[key]
        enc_type, info = detect_column_type(col_data, key, preserve_strings=True)

        output.write(bytes([enc_type]))
        encode_column(output, col_data, enc_type, info, n_rows)

    return output.getvalue(), keys

def encode_column(output, values, enc_type, info, n_rows):
    """Encode a single column"""

    if enc_type == ENC_SPARSE:
        # Write indices of present values
        indices = [i for i, v in enumerate(values) if v != '_ABSENT_']
        present_vals = [v for v in values if v != '_ABSENT_']

        output.write(encode_varint(len(indices)))

        # Delta encode indices
        prev = 0
        for idx in indices:
            output.write(encode_varint(idx - prev))
            prev = idx

        # Recursively encode present values
        inner_type = info.get('inner_type', ENC_RAW)
        inner_info = info.get('inner_info', {})
        output.write(bytes([inner_type]))
        encode_column(output, present_vals, inner_type, inner_info, len(present_vals))
        return

    if enc_type == ENC_BOOLEAN:
        # Pack booleans as bits
        bits = []
        for v in values:
            if isinstance(v, bool):
                bits.append(1 if v else 0)
            elif v in ('true', True):
                bits.append(1)
            else:
                bits.append(0)
        packed = pack_bits(bits, 1)
        output.write(encode_varint(len(packed)))
        output.write(packed)
        return

    if enc_type == ENC_DICTIONARY:
        # Use JSON encoding to preserve types (None, bool, int, str)
        def to_json_str(v):
            if v == '_ABSENT_':
                return '_ABSENT_'
            return json.dumps(v)  # Preserves type information

        unique = sorted(set(to_json_str(v) for v in values if v != '_ABSENT_'))
        vocab = {v: i for i, v in enumerate(unique)}

        # Write vocabulary
        output.write(encode_varint(len(unique)))
        for word in unique:
            word_bytes = word.encode('utf-8')
            output.write(encode_varint(len(word_bytes)))
            output.write(word_bytes)

        # Write indices
        bits = (len(unique) - 1).bit_length() if unique else 1
        indices = [vocab.get(to_json_str(v), 0) for v in values]
        packed = pack_bits(indices, bits)
        output.write(bytes([bits]))
        output.write(encode_varint(len(packed)))
        output.write(packed)
        return

    if enc_type == ENC_INTEGER_DICT:
        # Dictionary encoding for integers with high repetition
        int_vals = []
        for v in values:
            if isinstance(v, int) and not isinstance(v, bool):
                int_vals.append(v)
            elif isinstance(v, str) and NUMERIC_RE.match(v):
                int_vals.append(int(v))
            else:
                int_vals.append(0)

        unique = sorted(set(int_vals))
        vocab = {v: i for i, v in enumerate(unique)}

        # Write vocabulary size and values
        output.write(encode_varint(len(unique)))
        for val in unique:
            output.write(encode_signed_varint(val))

        # Write indices as bitpacked
        bits = (len(unique) - 1).bit_length() if len(unique) > 1 else 1
        indices = [vocab[v] for v in int_vals]
        packed = pack_bits(indices, bits)
        output.write(bytes([bits]))
        output.write(encode_varint(len(packed)))
        output.write(packed)
        return

    if enc_type == ENC_INTEGER_DELTA:
        int_vals = []
        for v in values:
            if isinstance(v, int) and not isinstance(v, bool):
                int_vals.append(v)
            elif isinstance(v, str) and NUMERIC_RE.match(v):
                int_vals.append(int(v))
            else:
                int_vals.append(0)

        # Delta encode
        prev = 0
        for val in int_vals:
            output.write(encode_signed_varint(val - prev))
            prev = val
        return

    if enc_type == ENC_TIMESTAMP_DELTA:
        # 8-byte millisecond timestamps with delta encoding
        ts_vals = info.get('values', [0] * n_rows)
        if len(ts_vals) < n_rows:
            ts_vals.extend([ts_vals[-1] if ts_vals else 0] * (n_rows - len(ts_vals)))

        prev = 0
        for ts in ts_vals:
            output.write(encode_signed_varint(ts - prev))
            prev = ts
        return

    if enc_type == ENC_IP_PACKED:
        ip_vals = info.get('values', [])
        for v in values:
            if isinstance(v, str):
                packed = pack_ipv4(v)
                if packed:
                    output.write(packed)
                else:
                    output.write(b'\x00\x00\x00\x00')
            else:
                output.write(b'\x00\x00\x00\x00')
        return

    if enc_type == ENC_BITPACK:
        bits = info.get('bits', 8)
        int_vals = []
        for v in values:
            if isinstance(v, int):
                int_vals.append(v)
            elif isinstance(v, str) and NUMERIC_RE.match(v):
                int_vals.append(int(v))
            else:
                int_vals.append(0)

        packed = pack_bits(int_vals, bits)
        output.write(bytes([bits]))
        output.write(encode_varint(len(packed)))
        output.write(packed)
        return

    # ENC_RAW - write as length-prefixed strings
    for v in values:
        s = '' if v == '_ABSENT_' else str(v)
        s_bytes = s.encode('utf-8')
        output.write(encode_varint(len(s_bytes)))
        output.write(s_bytes)

# ============================================================================
# HTTP Access Log Encoder
# ============================================================================

def encode_http_logs(lines):
    """Specialized encoder for HTTP access logs (CLF/Combined)"""
    # Parse all lines
    parsed = []
    for line in lines:
        match = HTTP_LOG_RE.match(line)
        if match:
            groups = match.groups()
            parsed.append({
                'ip': groups[0],
                'ident': groups[1],
                'user': groups[2],
                'timestamp': groups[3],
                'request': groups[4],
                'status': groups[5],
                'bytes': groups[6],
                'referer': groups[7] if len(groups) > 7 else None,
                'agent': groups[8] if len(groups) > 8 else None,
            })
        else:
            parsed.append(None)

    output = BytesIO()
    n_rows = len(parsed)
    output.write(encode_varint(n_rows))

    # Track which lines parsed successfully
    success_bits = pack_bits([1 if p else 0 for p in parsed], 1)
    output.write(encode_varint(len(success_bits)))
    output.write(success_bits)

    # Write raw lines for failed parses
    failed_lines = [lines[i] for i, p in enumerate(parsed) if not p]
    output.write(encode_varint(len(failed_lines)))
    for line in failed_lines:
        line_bytes = line.encode('utf-8')
        output.write(encode_varint(len(line_bytes)))
        output.write(line_bytes)

    # Get successful parses only
    success = [p for p in parsed if p]
    if not success:
        return output.getvalue()

    # Encode IPs/hostnames (use dictionary since hostnames can't be packed)
    ips = [p['ip'] for p in success]
    encode_string_column(output, ips)

    # Encode ident (usually "-", use dictionary)
    idents = [p['ident'] for p in success]
    encode_string_column(output, idents)

    # Encode user (usually "-", use dictionary)
    users = [p['user'] for p in success]
    encode_string_column(output, users)

    # Encode timestamps (use dictionary to preserve original format)
    timestamps = [p['timestamp'] for p in success]
    encode_string_column(output, timestamps)

    # Encode requests (usually have patterns, use dictionary)
    requests = [p['request'] for p in success]
    encode_string_column(output, requests)

    # Encode status codes (small integers, bitpack)
    statuses = [int(p['status']) for p in success]
    max_status = max(statuses) if statuses else 0
    bits = max_status.bit_length()
    output.write(bytes([bits]))
    packed = pack_bits(statuses, bits)
    output.write(encode_varint(len(packed)))
    output.write(packed)

    # Encode bytes (as string to preserve "-" values)
    bytes_vals = [p['bytes'] for p in success]
    encode_string_column(output, bytes_vals)

    # Encode referer (dictionary) - None means field not present
    referers = [p['referer'] if p['referer'] is not None else '_NONE_' for p in success]
    encode_string_column(output, referers)

    # Encode user-agent (dictionary) - None means field not present
    agents = [p['agent'] if p['agent'] is not None else '_NONE_' for p in success]
    encode_string_column(output, agents)

    return output.getvalue()

def encode_string_column(output, values):
    """Encode a string column with dictionary if beneficial"""
    unique = list(set(values))

    if len(unique) < len(values) * 0.3 or len(unique) < 256:
        # Use dictionary
        output.write(bytes([1]))  # Dictionary flag
        vocab = {v: i for i, v in enumerate(unique)}

        output.write(encode_varint(len(unique)))
        for word in unique:
            word_bytes = word.encode('utf-8')
            output.write(encode_varint(len(word_bytes)))
            output.write(word_bytes)

        bits = (len(unique) - 1).bit_length() if len(unique) > 1 else 1
        indices = [vocab[v] for v in values]
        packed = pack_bits(indices, bits)
        output.write(bytes([bits]))
        output.write(encode_varint(len(packed)))
        output.write(packed)
    else:
        # Raw encoding
        output.write(bytes([0]))  # Raw flag
        for v in values:
            v_bytes = v.encode('utf-8')
            output.write(encode_varint(len(v_bytes)))
            output.write(v_bytes)

# ============================================================================
# Text Log Encoder (Drain-based)
# ============================================================================

def create_drain_miner():
    """Create a Drain template miner"""
    if not HAS_DRAIN:
        return None

    config = TemplateMinerConfig()
    config.load(f"""
[MASKING]
[DRAIN]
sim_th = 0.4
depth = 4
max_children = 100
""")
    return TemplateMiner(config=config)

def encode_text_logs(lines):
    """Encode text logs using Drain template mining"""
    output = BytesIO()
    n_lines = len(lines)
    output.write(encode_varint(n_lines))

    if not HAS_DRAIN:
        # Fallback to raw encoding
        output.write(bytes([0]))  # No templates
        for line in lines:
            line_bytes = line.encode('utf-8')
            output.write(encode_varint(len(line_bytes)))
            output.write(line_bytes)
        return output.getvalue()

    # First pass: Mine templates to get final cluster assignments
    miner = create_drain_miner()
    template_ids = []

    for line in lines:
        result = miner.add_log_message(line)
        template_ids.append(result['cluster_id'])

    # Get all final templates (after all lines processed)
    clusters = miner.drain.clusters
    templates = {c.cluster_id: c.get_template() for c in clusters}

    # Second pass: Extract variables using final templates
    variables = []
    for i, line in enumerate(lines):
        cluster_id = template_ids[i]
        final_template = templates.get(cluster_id, line)
        vars_in_line = extract_variables(line, final_template)
        variables.append(vars_in_line)

    output.write(bytes([1]))  # Has templates

    # Write templates
    output.write(encode_varint(len(templates)))
    template_list = sorted(templates.keys())
    template_to_idx = {tid: i for i, tid in enumerate(template_list)}

    for tid in template_list:
        tmpl = templates[tid]
        tmpl_bytes = tmpl.encode('utf-8')
        output.write(encode_varint(len(tmpl_bytes)))
        output.write(tmpl_bytes)

    # Write template indices (bitpacked)
    indices = [template_to_idx.get(tid, 0) for tid in template_ids]
    bits = (len(templates) - 1).bit_length() if len(templates) > 1 else 1
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

    # Encode variables columnar (preserve_strings=True for lossless text)
    max_vars = max(len(v) for v in variables) if variables else 0
    output.write(encode_varint(max_vars))

    for var_idx in range(max_vars):
        col = [v[var_idx] if var_idx < len(v) else '' for v in variables]
        enc_type, info = detect_column_type(col, preserve_strings=True)
        output.write(bytes([enc_type]))
        encode_column(output, col, enc_type, info, n_lines)

    return output.getvalue()

def extract_variables(line, template):
    """Extract variable values from line given template"""
    template_parts = template.split()
    line_parts = line.split()

    variables = []
    t_idx = 0
    l_idx = 0

    while t_idx < len(template_parts) and l_idx < len(line_parts):
        t_part = template_parts[t_idx]
        l_part = line_parts[l_idx]

        if t_part == '<*>':
            variables.append(l_part)

        t_idx += 1
        l_idx += 1

    # Handle remaining line parts
    while l_idx < len(line_parts):
        variables.append(line_parts[l_idx])
        l_idx += 1

    return variables

# ============================================================================
# Main Encoder
# ============================================================================

def encode_v5(lines):
    """Main V5 encoder - detects format and applies best strategy"""
    if not lines:
        return MAGIC + bytes([VERSION, FMT_TEXT_GENERIC]) + encode_varint(0)

    # Detect format
    fmt = detect_format(lines)

    output = BytesIO()
    output.write(MAGIC)
    output.write(bytes([VERSION, fmt]))

    if fmt == FMT_JSON_FLAT or fmt == FMT_JSON_NESTED:
        data, keys = encode_json_columnar(lines)
        output.write(data)
    elif fmt == FMT_TEXT_HTTP:
        data = encode_http_logs(lines)
        output.write(data)
    else:  # FMT_TEXT_SYSLOG, FMT_TEXT_GENERIC
        data = encode_text_logs(lines)
        output.write(data)

    return output.getvalue()

# ============================================================================
# Decoder
# ============================================================================

def decode_v5(data):
    """Decode V5 encoded data back to lines"""
    if len(data) < 6 or data[:4] != MAGIC:
        raise ValueError("Invalid V5 data")

    version = data[4]
    fmt = data[5]
    pos = 6

    if fmt in (FMT_JSON_FLAT, FMT_JSON_NESTED):
        return decode_json_columnar(data, pos)
    elif fmt == FMT_TEXT_HTTP:
        return decode_http_logs(data, pos)
    else:
        return decode_text_logs(data, pos)

def decode_json_columnar(data, pos):
    """Decode JSON columnar format"""
    # Read keys
    n_keys, pos = decode_varint(data, pos)
    keys = []
    for _ in range(n_keys):
        key_len, pos = decode_varint(data, pos)
        keys.append(data[pos:pos+key_len].decode('utf-8'))
        pos += key_len

    n_rows, pos = decode_varint(data, pos)

    # Decode columns
    columns = {}
    for key in keys:
        enc_type = data[pos]
        pos += 1
        col_values, pos = decode_column(data, pos, enc_type, n_rows)
        columns[key] = col_values

    # Reconstruct JSON lines
    lines = []
    for i in range(n_rows):
        obj = {}
        for key in keys:
            val = columns[key][i]
            if val != '_ABSENT_':
                set_nested_value(obj, key, val)
        lines.append(json.dumps(obj, separators=(',', ':')))

    return lines

def set_nested_value(obj, key, value):
    """Set a value in nested dict using dot notation key"""
    parts = key.split('.')
    current = obj
    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        current = current[part]

    # Try to parse JSON arrays/objects
    if isinstance(value, str):
        if value.startswith('[') or value.startswith('{'):
            try:
                value = json.loads(value)
            except:
                pass

    current[parts[-1]] = value

def decode_column(data, pos, enc_type, n_rows):
    """Decode a single column"""

    if enc_type == ENC_SPARSE:
        n_present, pos = decode_varint(data, pos)

        # Decode delta-encoded indices
        indices = []
        prev = 0
        for _ in range(n_present):
            delta, pos = decode_varint(data, pos)
            prev += delta
            indices.append(prev)

        # Decode inner values
        inner_type = data[pos]
        pos += 1
        inner_vals, pos = decode_column(data, pos, inner_type, n_present)

        # Reconstruct full column
        result = ['_ABSENT_'] * n_rows
        for idx, val in zip(indices, inner_vals):
            if idx < n_rows:
                result[idx] = val

        return result, pos

    if enc_type == ENC_BOOLEAN:
        packed_len, pos = decode_varint(data, pos)
        packed = data[pos:pos+packed_len]
        pos += packed_len
        bits = unpack_bits(packed, n_rows, 1)
        return [bool(b) for b in bits], pos

    if enc_type == ENC_DICTIONARY:
        vocab_size, pos = decode_varint(data, pos)
        vocab = []
        for _ in range(vocab_size):
            word_len, pos = decode_varint(data, pos)
            word_str = data[pos:pos+word_len].decode('utf-8')
            pos += word_len
            # Parse JSON to restore types (null, bool, int, str)
            try:
                vocab.append(json.loads(word_str))
            except:
                vocab.append(word_str)  # Fallback for non-JSON

        bits = data[pos]
        pos += 1
        packed_len, pos = decode_varint(data, pos)
        packed = data[pos:pos+packed_len]
        pos += packed_len

        indices = unpack_bits(packed, n_rows, bits)
        return [vocab[i] if i < len(vocab) else '' for i in indices], pos

    if enc_type == ENC_INTEGER_DICT:
        # Dictionary encoding for integers
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

    if enc_type == ENC_INTEGER_DELTA:
        values = []
        prev = 0
        for _ in range(n_rows):
            delta, pos = decode_signed_varint(data, pos)
            prev += delta
            values.append(prev)
        return values, pos

    if enc_type == ENC_TIMESTAMP_DELTA:
        values = []
        prev = 0
        for _ in range(n_rows):
            delta, pos = decode_signed_varint(data, pos)
            prev += delta
            values.append(prev)
        # Convert back to ISO format
        return [datetime.fromtimestamp(ts/1000).isoformat() + 'Z' for ts in values], pos

    if enc_type == ENC_IP_PACKED:
        values = []
        for _ in range(n_rows):
            values.append(unpack_ipv4(data[pos:pos+4]))
            pos += 4
        return values, pos

    if enc_type == ENC_BITPACK:
        bits = data[pos]
        pos += 1
        packed_len, pos = decode_varint(data, pos)
        packed = data[pos:pos+packed_len]
        pos += packed_len
        return unpack_bits(packed, n_rows, bits), pos

    # ENC_RAW
    values = []
    for _ in range(n_rows):
        str_len, pos = decode_varint(data, pos)
        values.append(data[pos:pos+str_len].decode('utf-8'))
        pos += str_len
    return values, pos

def decode_http_logs(data, pos):
    """Decode HTTP access logs"""
    n_rows, pos = decode_varint(data, pos)

    # Read success bits
    success_bits_len, pos = decode_varint(data, pos)
    success_bits = data[pos:pos+success_bits_len]
    pos += success_bits_len
    successes = unpack_bits(success_bits, n_rows, 1)

    # Read failed lines
    n_failed, pos = decode_varint(data, pos)
    failed_lines = []
    for _ in range(n_failed):
        line_len, pos = decode_varint(data, pos)
        failed_lines.append(data[pos:pos+line_len].decode('utf-8'))
        pos += line_len

    n_success = sum(successes)
    if n_success == 0:
        return failed_lines

    # Decode IPs/hostnames (dictionary encoded)
    ips, pos = decode_string_column(data, pos, n_success)

    # Decode ident
    idents, pos = decode_string_column(data, pos, n_success)

    # Decode user
    users, pos = decode_string_column(data, pos, n_success)

    # Decode timestamps (dictionary encoded)
    timestamps, pos = decode_string_column(data, pos, n_success)

    # Decode requests
    requests, pos = decode_string_column(data, pos, n_success)

    # Decode statuses
    status_bits = data[pos]
    pos += 1
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len
    statuses = unpack_bits(packed, n_success, status_bits)

    # Decode bytes (string to preserve "-")
    bytes_vals, pos = decode_string_column(data, pos, n_success)

    # Decode referer
    referers, pos = decode_string_column(data, pos, n_success)

    # Decode agents
    agents, pos = decode_string_column(data, pos, n_success)

    # Reconstruct lines
    lines = []
    success_idx = 0
    failed_idx = 0

    for i in range(n_rows):
        if successes[i]:
            ts_str = timestamps[success_idx]

            line = f'{ips[success_idx]} {idents[success_idx]} {users[success_idx]} [{ts_str}] "{requests[success_idx]}" {statuses[success_idx]} {bytes_vals[success_idx]}'

            # Add referer/agent only if they were present in original
            if referers[success_idx] != '_NONE_':
                line += f' "{referers[success_idx]}"'
            if agents[success_idx] != '_NONE_':
                line += f' "{agents[success_idx]}"'

            lines.append(line)
            success_idx += 1
        else:
            lines.append(failed_lines[failed_idx])
            failed_idx += 1

    return lines

def decode_string_column(data, pos, n_rows):
    """Decode a string column"""
    flag = data[pos]
    pos += 1

    if flag == 1:  # Dictionary
        vocab_size, pos = decode_varint(data, pos)
        vocab = []
        for _ in range(vocab_size):
            word_len, pos = decode_varint(data, pos)
            vocab.append(data[pos:pos+word_len].decode('utf-8'))
            pos += word_len

        bits = data[pos]
        pos += 1
        packed_len, pos = decode_varint(data, pos)
        packed = data[pos:pos+packed_len]
        pos += packed_len

        indices = unpack_bits(packed, n_rows, bits)
        return [vocab[i] if i < len(vocab) else '' for i in indices], pos
    else:  # Raw
        values = []
        for _ in range(n_rows):
            val_len, pos = decode_varint(data, pos)
            values.append(data[pos:pos+val_len].decode('utf-8'))
            pos += val_len
        return values, pos

def decode_text_logs(data, pos):
    """Decode text logs"""
    n_lines, pos = decode_varint(data, pos)
    has_templates = data[pos]
    pos += 1

    if not has_templates:
        # Raw encoding
        lines = []
        for _ in range(n_lines):
            line_len, pos = decode_varint(data, pos)
            lines.append(data[pos:pos+line_len].decode('utf-8'))
            pos += line_len
        return lines

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
        enc_type = data[pos]
        pos += 1
        col_vals, pos = decode_column(data, pos, enc_type, n_lines)
        var_columns.append(col_vals)

    # Reconstruct lines
    lines = []
    for i in range(n_lines):
        tmpl_idx = template_indices[i]
        template = templates[tmpl_idx] if tmpl_idx < len(templates) else ''

        # Substitute variables
        vars_for_line = [col[i] for col in var_columns]
        line = reconstruct_line(template, vars_for_line)
        lines.append(line)

    return lines

def reconstruct_line(template, variables):
    """Reconstruct line from template and variables"""
    parts = template.split()
    result = []
    var_idx = 0

    for part in parts:
        if part == '<*>' and var_idx < len(variables):
            result.append(str(variables[var_idx]))
            var_idx += 1
        else:
            result.append(part)

    # Append remaining non-empty variables
    while var_idx < len(variables):
        var = str(variables[var_idx])
        if var:  # Skip empty padding
            result.append(var)
        var_idx += 1

    return ' '.join(result)

# ============================================================================
# Verification
# ============================================================================

def verify_file(input_path):
    """Encode, decode, and verify a file"""
    print(f"V5 Processing {input_path}...")

    with open(input_path, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    print(f"  Lines: {len(lines)}")

    # Detect format
    fmt = detect_format(lines)
    fmt_names = {
        FMT_JSON_FLAT: 'JSON (flat)',
        FMT_JSON_NESTED: 'JSON (nested)',
        FMT_TEXT_HTTP: 'HTTP access',
        FMT_TEXT_SYSLOG: 'Syslog',
        FMT_TEXT_GENERIC: 'Generic text'
    }
    print(f"  Detected format: {fmt_names.get(fmt, 'Unknown')}")

    # Encode
    start = time.time()
    encoded = encode_v5(lines)
    encode_time = time.time() - start

    print(f"  Encoded size: {len(encoded):,} bytes ({len(encoded)/len(''.join(lines))*100:.1f}%)")
    print(f"  Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")

    # Decode
    start = time.time()
    decoded = decode_v5(encoded)
    decode_time = time.time() - start

    print(f"  Decode time: {decode_time:.2f}s ({len(lines)/decode_time:.0f} lines/sec)")

    # Verify (use semantic comparison for JSON)
    mismatches = 0
    for i, (orig, dec) in enumerate(zip(lines, decoded)):
        if orig != dec:
            # Try semantic JSON comparison
            try:
                orig_obj = json.loads(orig)
                dec_obj = json.loads(dec)
                if orig_obj == dec_obj:
                    continue  # Semantically equal
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

# ============================================================================
# Main
# ============================================================================

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: codec_v5.py <logfile>")
        sys.exit(1)

    success, data = verify_file(sys.argv[1])
    sys.exit(0 if success else 1)

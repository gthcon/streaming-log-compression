#!/usr/bin/env python3
"""
V6 Unified Recursive Log Codec

Key innovation: Recursively apply optimal encoding at each level:
1. JSON fields that contain log-like text → apply Drain
2. Text variables that contain JSON → apply JSON columnar
3. Nested structures → recurse with appropriate encoding

This creates a unified pipeline that automatically applies the right
compression at each point in the data structure.
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

MAGIC = b'LGV6'
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

# Patterns for detecting content type
HTTP_LOG_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[^"]*"\s+\d+\s+\S+'
)
JSON_RE = re.compile(r'^\s*[\[{]')
NUMERIC_RE = re.compile(r'^-?\d+$')
IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

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
    current_byte = 0
    bits_in_byte = 0
    for val in values:
        remaining_bits = bits_per_value
        while remaining_bits > 0:
            space = 8 - bits_in_byte
            take = min(space, remaining_bits)
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

# ============================================================================
# Content Type Detection
# ============================================================================

def looks_like_http_log(s):
    """Check if string looks like an HTTP access log line"""
    if not isinstance(s, str) or len(s) < 20:
        return False
    return bool(HTTP_LOG_RE.match(s))

def looks_like_json(s):
    """Check if string looks like JSON"""
    if not isinstance(s, str) or len(s) < 2:
        return False
    return bool(JSON_RE.match(s))

def analyze_string_column(values):
    """Analyze a column of strings to determine optimal encoding"""
    if not values:
        return 'dict', {}

    present = [v for v in values if v is not None and v != '_ABSENT_']
    if not present:
        return 'dict', {}

    # Check if all are HTTP log-like
    http_count = sum(1 for v in present if isinstance(v, str) and looks_like_http_log(v))
    if http_count > len(present) * 0.8:
        return 'drain', {'type': 'http'}

    # Check if all are JSON-like
    json_count = sum(1 for v in present if isinstance(v, str) and looks_like_json(v))
    if json_count > len(present) * 0.8:
        return 'nested_json', {}

    # Check uniqueness for dictionary
    unique = set(str(v) for v in present)
    if len(unique) < len(present) * 0.5 or len(unique) < 256:
        return 'dict', {}

    return 'raw', {}

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

def encode_drain_column(output, values, n_rows):
    """Encode a column of text using Drain template mining"""
    if not HAS_DRAIN:
        # Fallback to dictionary
        encode_dict_column(output, values, n_rows)
        return

    # Filter to strings only
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

    # Get final templates
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
    bits = (len(template_list)).bit_length() if template_list else 1
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

    # Write variables columnar (recursively encode)
    max_vars = max(len(v) for v in all_variables) if all_variables else 0
    output.write(encode_varint(max_vars))

    for var_idx in range(max_vars):
        col = [v[var_idx] if var_idx < len(v) else '' for v in all_variables]
        # Recursively determine best encoding for this variable column
        encode_smart_column(output, col, n_rows)

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

def decode_drain_column(data, pos, n_rows):
    """Decode a Drain-encoded column"""
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
    template_indices = unpack_bits(packed, n_rows, bits)

    # Read variables
    max_vars, pos = decode_varint(data, pos)
    var_columns = []
    for _ in range(max_vars):
        col_vals, pos = decode_smart_column(data, pos, n_rows)
        var_columns.append(col_vals)

    # Reconstruct strings
    result = []
    for i in range(n_rows):
        tmpl_idx = template_indices[i]
        template = templates[tmpl_idx] if tmpl_idx < len(templates) else ''

        vars_for_line = [col[i] for col in var_columns]
        line = reconstruct_line(template, vars_for_line)
        result.append(line)

    return result, pos

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
        if var:
            result.append(var)
        var_idx += 1

    return ' '.join(result)

# ============================================================================
# Smart Column Encoder/Decoder (Recursive)
# ============================================================================

def encode_smart_column(output, values, n_rows):
    """Intelligently encode a column, recursively applying best encoding"""
    if not values:
        output.write(bytes([ENC_RAW]))
        return

    # Filter out absent markers
    present = [v for v in values if v != '_ABSENT_']
    if not present:
        output.write(bytes([ENC_SPARSE]))
        output.write(encode_varint(0))
        return

    # Check sparsity - use >= 0.5 to handle any significant sparsity
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

        # Recursively encode present values
        encode_smart_column(output, present_vals, len(present_vals))
        return

    # Check for actual integers (not strings that look like numbers)
    # Only use integer encoding if there are no absent values (or they were already handled by sparse)
    has_absent = any(v == '_ABSENT_' for v in values)

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
        if unique < len(int_vals) * 0.1:
            # High repetition - use integer dictionary
            output.write(bytes([ENC_INT_DICT]))
            encode_int_dict_column(output, values, n_rows)
            return

        max_val = max(int_vals)
        min_val = min(int_vals)
        if min_val >= 0 and max_val.bit_length() <= 16:
            # Bitpack
            output.write(bytes([ENC_BITPACK]))
            encode_bitpack_column(output, values, n_rows, max_val.bit_length())
            return

        # Delta encoding
        output.write(bytes([ENC_INT_DELTA]))
        encode_int_delta_column(output, values, n_rows)
        return

    # Check for strings - analyze content
    str_vals = [v for v in present if isinstance(v, str)]
    if len(str_vals) == len(present):
        # All strings - check for special patterns
        content_type, info = analyze_string_column(str_vals)

        if content_type == 'drain' and HAS_DRAIN:
            output.write(bytes([ENC_DRAIN]))
            encode_drain_column(output, values, n_rows)
            return

        if content_type == 'nested_json':
            output.write(bytes([ENC_NESTED_JSON]))
            encode_nested_json_column(output, values, n_rows)
            return

    # Default to dictionary encoding with type preservation
    output.write(bytes([ENC_DICT]))
    encode_dict_column(output, values, n_rows)

def decode_smart_column(data, pos, n_rows):
    """Decode a column, handling recursive encodings"""
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

    if enc_type == ENC_DRAIN:
        return decode_drain_column(data, pos, n_rows)

    if enc_type == ENC_NESTED_JSON:
        return decode_nested_json_column(data, pos, n_rows)

    # Unknown - try raw
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
    """Dictionary encoding with JSON type preservation"""
    def to_json_str(v):
        if v == '_ABSENT_':
            return '_ABSENT_'
        return json.dumps(v)

    # Include _ABSENT_ in vocabulary if present
    unique = sorted(set(to_json_str(v) for v in values))
    vocab = {v: i for i, v in enumerate(unique)}

    output.write(encode_varint(len(unique)))
    for word in unique:
        word_bytes = word.encode('utf-8')
        output.write(encode_varint(len(word_bytes)))
        output.write(word_bytes)

    bits = (len(unique) - 1).bit_length() if len(unique) > 1 else 1
    indices = [vocab.get(to_json_str(v), 0) for v in values]
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

def decode_dict_column(data, pos, n_rows):
    """Decode dictionary-encoded column"""
    vocab_size, pos = decode_varint(data, pos)
    vocab = []
    for _ in range(vocab_size):
        word_len, pos = decode_varint(data, pos)
        word_str = data[pos:pos+word_len].decode('utf-8')
        pos += word_len
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
    """Delta encoding for integers"""
    prev = 0
    for v in values:
        val = v if isinstance(v, int) else 0
        output.write(encode_signed_varint(val - prev))
        prev = val

def decode_int_delta_column(data, pos, n_rows):
    """Decode delta-encoded integers"""
    values = []
    prev = 0
    for _ in range(n_rows):
        delta, pos = decode_signed_varint(data, pos)
        prev += delta
        values.append(prev)
    return values, pos

def encode_int_dict_column(output, values, n_rows):
    """Dictionary encoding for integers"""
    int_vals = [v if isinstance(v, int) else 0 for v in values]
    unique = sorted(set(int_vals))
    vocab = {v: i for i, v in enumerate(unique)}

    output.write(encode_varint(len(unique)))
    for val in unique:
        output.write(encode_signed_varint(val))

    bits = (len(unique) - 1).bit_length() if len(unique) > 1 else 1
    indices = [vocab[v] for v in int_vals]
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

def decode_int_dict_column(data, pos, n_rows):
    """Decode integer dictionary column"""
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

def encode_bitpack_column(output, values, n_rows, bits):
    """Bitpack encoding for small integers"""
    int_vals = [v if isinstance(v, int) else 0 for v in values]
    output.write(bytes([bits]))
    packed = pack_bits(int_vals, bits)
    output.write(encode_varint(len(packed)))
    output.write(packed)

def decode_bitpack_column(data, pos, n_rows):
    """Decode bitpacked column"""
    bits = data[pos]
    pos += 1
    packed_len, pos = decode_varint(data, pos)
    packed = data[pos:pos+packed_len]
    pos += packed_len
    return unpack_bits(packed, n_rows, bits), pos

def encode_nested_json_column(output, values, n_rows):
    """Encode column where each value is a JSON string - parse and encode recursively"""
    parsed = []
    for v in values:
        if isinstance(v, str):
            try:
                parsed.append(json.loads(v))
            except:
                parsed.append(v)
        else:
            parsed.append(v)

    # Treat as a mini-JSON columnar encoding
    # For now, just use dictionary encoding on the JSON strings
    encode_dict_column(output, [json.dumps(p) if not isinstance(p, str) else p for p in parsed], n_rows)

def decode_nested_json_column(data, pos, n_rows):
    """Decode nested JSON column"""
    values, pos = decode_dict_column(data, pos, n_rows)
    # Values are already JSON-decoded by dict column
    return values, pos

# ============================================================================
# JSON Flattening with Recursive Encoding
# ============================================================================

def flatten_json(obj, prefix='', sep='.'):
    """Flatten nested JSON to dot-notation keys"""
    items = {}

    if isinstance(obj, dict):
        if not obj:
            # Empty dict - use marker to preserve
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

def encode_json_columnar(lines):
    """Encode JSON logs with recursive smart encoding for each column"""
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

    # Build columns
    columns = {k: [] for k in keys}
    for row in rows:
        for k in keys:
            columns[k].append(row.get(k, '_ABSENT_'))

    output = BytesIO()

    # Write header
    output.write(encode_varint(len(keys)))
    for key in keys:
        key_bytes = key.encode('utf-8')
        output.write(encode_varint(len(key_bytes)))
        output.write(key_bytes)

    output.write(encode_varint(n_rows))

    # Encode each column with smart recursive encoding
    for key in keys:
        col_data = columns[key]
        encode_smart_column(output, col_data, n_rows)

    return output.getvalue(), keys

def decode_json_columnar(data, pos):
    """Decode JSON columnar format"""
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
    # Handle empty dict marker
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
# Text Log Encoding with Smart Variable Handling
# ============================================================================

def encode_text_logs(lines):
    """Encode text logs using Drain with smart variable encoding"""
    output = BytesIO()
    n_lines = len(lines)
    output.write(encode_varint(n_lines))

    if not HAS_DRAIN:
        output.write(bytes([0]))
        for line in lines:
            line_bytes = line.encode('utf-8')
            output.write(encode_varint(len(line_bytes)))
            output.write(line_bytes)
        return output.getvalue()

    # Mine templates
    miner = create_drain_miner()
    template_ids = []

    for line in lines:
        result = miner.add_log_message(line)
        template_ids.append(result['cluster_id'])

    clusters = miner.drain.clusters
    templates = {c.cluster_id: c.get_template() for c in clusters}

    # Extract variables using final templates
    variables = []
    for i, line in enumerate(lines):
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
    bits = (len(templates) - 1).bit_length() if len(templates) > 1 else 1
    packed = pack_bits(indices, bits)
    output.write(bytes([bits]))
    output.write(encode_varint(len(packed)))
    output.write(packed)

    # Encode variables with SMART encoding (key difference from V5)
    max_vars = max(len(v) for v in variables) if variables else 0
    output.write(encode_varint(max_vars))

    for var_idx in range(max_vars):
        col = [v[var_idx] if var_idx < len(v) else '' for v in variables]
        # Use smart encoding - will detect JSON/text patterns in variables
        encode_smart_column(output, col, n_lines)

    return output.getvalue()

def decode_text_logs(data, pos):
    """Decode text logs"""
    n_lines, pos = decode_varint(data, pos)
    has_templates = data[pos]
    pos += 1

    if not has_templates:
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

    # Read variables with smart decoding
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
        lines.append(line)

    return lines

# ============================================================================
# Top-Level Encoder/Decoder
# ============================================================================

def detect_format(lines):
    """Detect log format"""
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

def encode_v6(lines):
    """Main V6 encoder"""
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

def decode_v6(data):
    """Main V6 decoder"""
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
    """Encode, decode, and verify a file"""
    import time

    print(f"V6 Processing {input_path}...")

    with open(input_path, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    print(f"  Lines: {len(lines)}")

    fmt = detect_format(lines)
    fmt_name = 'JSON' if fmt == FMT_JSON else 'Text'
    print(f"  Detected format: {fmt_name}")

    start = time.time()
    encoded = encode_v6(lines)
    encode_time = time.time() - start

    orig_size = len(''.join(lines))
    print(f"  Encoded size: {len(encoded):,} bytes ({len(encoded)/orig_size*100:.1f}%)")
    print(f"  Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")

    start = time.time()
    decoded = decode_v6(encoded)
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
        print("Usage: codec_v6.py <logfile>")
        sys.exit(1)

    success, data = verify_file(sys.argv[1])
    sys.exit(0 if success else 1)

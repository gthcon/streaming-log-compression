#!/usr/bin/env python3
"""
JSON Codec V4 - Flattened columnar encoding

Key difference from V3: Instead of recursive nested encoding, we flatten
all nested structures to root-level keys like "a.b.c". This is similar to
what CLP and Elasticsearch do.

Benefits:
- Simpler encoding/decoding (no recursion)
- Better compression for deeply nested JSON
- Each leaf value becomes its own column, maximizing columnar benefits

Trade-offs:
- More columns to manage (can be 10x+ more)
- Need to handle array flattening carefully
"""
import json
import struct
import time
import re
import sys
from collections import Counter

# Encoding types (must match V3 for compatibility)
ENC_RAW = 0
ENC_DICTIONARY = 1
ENC_DELTA_INTEGER = 2
ENC_DELTA_TIMESTAMP = 3  # Not used in V4
ENC_BINARY_INT = 9       # Binary packed integers (1/2/4/8 bytes based on range)
ENC_BINARY_TIMESTAMP = 10
ENC_BITPACK_DICT = 11
ENC_BITPACK_INT = 12     # Bit-packed integers for sub-byte precision
ENC_STRING_INT = 14
ENC_DICTIONARY_INT = 15
ENC_NESTED_ARRAY = 17
ENC_BOOLEAN = 18
ENC_SPARSE = 19  # Sparse column encoding - only store present values with indices
ENC_INTEGER_DELTA = 2  # Alias

# Regex for ISO timestamps
ISO_TIMESTAMP_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')

# Marker for None/null values
NONE_MARKER = '\x00__NULL__\x00'


def parse_iso_timestamp(ts):
    """Parse ISO timestamp, return (milliseconds, format_info) or (None, None)"""
    m = ISO_TIMESTAMP_RE.match(ts)
    if not m:
        return None, None

    year, mon, day, h, mi, s, ms, tz = m.groups()
    y, mo, d = int(year), int(mon), int(day)
    hr, mn, sc = int(h), int(mi), int(s)

    # Cumulative days before each month (non-leap year)
    DAYS_BEFORE = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]

    # Calculate days since 1970-01-01
    years_since = y - 1970
    leap_years = (y - 1969) // 4 - (y - 1901) // 100 + (y - 1601) // 400
    days = years_since * 365 + leap_years

    # Month contribution
    days += DAYS_BEFORE[mo - 1]
    is_leap = (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0)
    if mo > 2 and is_leap:
        days += 1

    days += d - 1
    ms_val = days * 86400000 + hr * 3600000 + mn * 60000 + sc * 1000
    if ms:
        ms_val += int(float(ms) * 1000)

    format_info = {
        'ms_digits': len(ms) - 1 if ms else 0,
        'tz': tz or '',
        'separator': 'T'
    }

    return ms_val, format_info


def reconstruct_iso_timestamp(ms_val, format_info):
    """Reconstruct ISO timestamp from milliseconds"""
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
    for m in range(12):
        days_in_month = DAYS_IN_MONTH[m]
        if m == 1 and is_leap:
            days_in_month = 29
        if days < days_in_month:
            month = m + 1
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

    return result


def pack_bits(values, bits_per_value):
    """Pack integers into a byte array using specified bits per value."""
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

    # Flush remaining bits
    if bits_in_buffer > 0:
        result.append(buffer & 0xFF)

    return bytes(result)


def unpack_bits(data, count, bits_per_value):
    """Unpack integers from a byte array using specified bits per value."""
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

# Magic number for V4 format
MAGIC_V4 = b'JSN4'


# Marker for empty objects
EMPTY_OBJECT_MARKER = '\x00__EMPTY_OBJ__\x00'
# Marker for empty arrays
EMPTY_ARRAY_MARKER = '\x00__EMPTY_ARR__\x00'
# Delimiter for array values stored in a single column
ARRAY_VALUE_DELIM = '\x00\x01'
# Prefix for JSON-stringified list/dict values (to distinguish from plain strings)
JSON_VALUE_PREFIX = '\x00J:'


def flatten_object(obj, prefix='', sep='.'):
    """Flatten a nested dict to dot-notation keys.

    Example: {"a": {"b": 1}} -> {"a.b": 1}

    Arrays of objects are flattened specially:
    - Each field in the array objects becomes a column
    - Values are stored as delimited strings: "val1\x00\x01val2\x00\x01val3"
    - This preserves columnar benefits for array elements

    Empty objects get a special marker to preserve their existence.
    """
    result = {}

    for k, v in obj.items():
        key = f'{prefix}{sep}{k}' if prefix else k

        if isinstance(v, dict):
            if len(v) == 0:
                # Empty object - store marker to preserve its existence
                result[key] = EMPTY_OBJECT_MARKER
            else:
                # Recursively flatten nested dicts
                result.update(flatten_object(v, key, sep))
        elif isinstance(v, list):
            if len(v) == 0:
                # Empty array
                result[key] = EMPTY_ARRAY_MARKER
            elif all(isinstance(item, dict) for item in v):
                # Array of objects - flatten each object's fields into columns
                # Store array length for reconstruction
                result[f'{key}._len'] = len(v)

                # Collect all keys from all array elements
                all_array_keys = set()
                for item in v:
                    all_array_keys.update(item.keys())

                # For each key, store delimited values
                # Use JSON encoding to preserve types (strings get quoted, ints don't)
                for array_key in all_array_keys:
                    values_for_key = []
                    for item in v:
                        item_val = item.get(array_key, None)
                        if item_val is None:
                            values_for_key.append(NONE_MARKER)
                        else:
                            # JSON encode to preserve type info
                            values_for_key.append(json.dumps(item_val, separators=(',', ':'), ensure_ascii=False))
                    result[f'{key}.*.{array_key}'] = ARRAY_VALUE_DELIM.join(values_for_key)
            else:
                # Array of primitives or mixed - store with JSON prefix to distinguish from plain strings
                result[key] = JSON_VALUE_PREFIX + json.dumps(v, separators=(',', ':'), ensure_ascii=False)
        else:
            # Leaf value (including nulls, primitives)
            result[key] = v

    return result


def unflatten_object(flat, sep='.'):
    """Reconstruct a nested dict from dot-notation keys.

    Example: {"a.b": 1} -> {"a": {"b": 1}}
    Handles EMPTY_OBJECT_MARKER to recreate empty objects.
    Handles array reconstruction from ._len and .*.field patterns.
    """
    result = {}

    # First pass: identify arrays and their lengths
    array_lengths = {}  # "payload.commits" -> 3
    array_fields = {}   # "payload.commits" -> {"sha": [...], "message": [...]}

    regular_keys = []

    for key, value in flat.items():
        if key.endswith('._len'):
            # Array length marker
            array_path = key[:-5]  # Remove "._len"
            array_lengths[array_path] = int(value)
        elif '.*.' in key:
            # Array field: "payload.commits.*.sha" -> ("payload.commits", "sha")
            idx = key.index('.*.')
            array_path = key[:idx]
            field_name = key[idx+3:]  # Skip ".*."

            if array_path not in array_fields:
                array_fields[array_path] = {}

            # Split delimited values back into list
            # Note: value is a string, never Python None (None is stored as _ABSENT_)
            if value == '':
                values_list = ['']
            else:
                values_list = value.split(ARRAY_VALUE_DELIM)
            array_fields[array_path][field_name] = values_list
        else:
            regular_keys.append((key, value))

    # Reconstruct arrays
    for array_path in array_lengths:
        length = array_lengths[array_path]
        fields = array_fields.get(array_path, {})

        # Build array of objects
        array_result = []
        for i in range(length):
            obj = {}
            for field_name, values in fields.items():
                if i < len(values):
                    val = values[i]
                    if val == NONE_MARKER:
                        obj[field_name] = None
                    else:
                        # All values were JSON encoded, so parse them
                        try:
                            obj[field_name] = json.loads(val)
                        except json.JSONDecodeError:
                            # Fallback for malformed values
                            obj[field_name] = val
            array_result.append(obj)

        # Place the array in the result structure
        parts = array_path.split(sep)
        current = result
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = array_result

    # Process regular keys
    for key, value in regular_keys:
        parts = key.split(sep)
        current = result

        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {}
            elif not isinstance(current[part], dict):
                # Already set as array, skip
                break
            current = current[part]
        else:
            # Handle special markers
            if value == EMPTY_OBJECT_MARKER:
                current[parts[-1]] = {}
            elif value == EMPTY_ARRAY_MARKER:
                current[parts[-1]] = []
            elif isinstance(value, str) and value.startswith(JSON_VALUE_PREFIX):
                # JSON-prefixed value - parse it back
                json_str = value[len(JSON_VALUE_PREFIX):]
                try:
                    current[parts[-1]] = json.loads(json_str)
                except json.JSONDecodeError:
                    current[parts[-1]] = json_str
            else:
                # Keep value as-is - don't try to JSON parse regular fields
                # because strings like '[]' or '{}' are legitimate string values
                current[parts[-1]] = value

    return result


def encode_json_logs_flat(lines):
    """Parse JSON lines, flatten nested structure, extract columns."""
    parsed = []
    all_keys = []
    key_orders = []  # Per-line key order (flattened keys in original order)

    # Detect separator style
    separator_style = 0
    for line in lines:
        line_stripped = line.strip()
        if line_stripped and line_stripped.startswith('{'):
            if '": ' in line_stripped:
                separator_style = 1
            break

    for line in lines:
        line = line.strip()
        if not line:
            parsed.append({})
            key_orders.append(())
            continue

        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                # Flatten the object
                flat = flatten_object(obj)
                parsed.append(flat)
                key_orders.append(tuple(flat.keys()))

                for k in flat.keys():
                    if k not in all_keys:
                        all_keys.append(k)
            else:
                parsed.append({'_value': obj})
                key_orders.append(('_value',))
                if '_value' not in all_keys:
                    all_keys.append('_value')
        except json.JSONDecodeError:
            parsed.append({'_raw': line})
            key_orders.append(('_raw',))
            if '_raw' not in all_keys:
                all_keys.append('_raw')

    # Build columns
    columns = {}
    for key in all_keys:
        col_values = []
        for obj in parsed:
            if key in obj:
                col_values.append(obj[key])
            else:
                col_values.append('_ABSENT_')
        columns[key] = col_values

    columns['_sep_style'] = separator_style
    columns['_key_orders'] = key_orders

    return all_keys, columns, parsed


def detect_column_type_v4(values, key_hint=None):
    """Detect column type for V4 (simplified - no nested objects)."""
    # Use all non-null values
    sample = [v for v in values if v is not None and v != '' and v != '_ABSENT_']
    if not sample:
        return 'string', None

    # Subsample for large columns
    if len(sample) > 5000:
        import random
        sample = random.sample(sample, 5000)

    non_null_sample = [v for v in sample if v is not None and v != '_ABSENT_']
    if not non_null_sample:
        return 'string', None

    # Check for booleans
    bool_count = sum(1 for v in non_null_sample if isinstance(v, bool))
    if bool_count >= len(non_null_sample) * 0.9:
        return 'boolean', None

    # Check for arrays (will be JSON-stringified)
    list_count = sum(1 for v in non_null_sample if isinstance(v, list))
    if list_count >= len(non_null_sample) * 0.9:
        return 'array', None

    # Check for dicts (shouldn't happen after flattening, but fallback)
    dict_count = sum(1 for v in non_null_sample if isinstance(v, dict))
    if dict_count >= len(non_null_sample) * 0.9:
        return 'dict', None

    str_sample = [str(v) for v in non_null_sample]

    # Check for ISO timestamps
    iso_count = sum(1 for v in str_sample if ISO_TIMESTAMP_RE.match(v))
    if iso_count >= len(str_sample) * 0.9:
        return 'iso_timestamp', None

    # Check for integers
    int_like = sum(1 for v in non_null_sample if isinstance(v, int) and not isinstance(v, bool))
    if int_like >= len(non_null_sample) * 0.9:
        return 'integer', None

    # Check for string integers (numeric strings that should stay strings)
    numeric_str_count = 0
    for v in non_null_sample:
        if isinstance(v, str):
            try:
                int(v)
                numeric_str_count += 1
            except ValueError:
                pass
    if numeric_str_count >= len(non_null_sample) * 0.9:
        if all(isinstance(v, str) for v in non_null_sample if v is not None):
            return 'string_integer', None
        return 'integer', None

    return 'string', None


ENC_RAW_JSON_CHUNK = 20  # Store extremely sparse columns as raw JSON chunks
ENC_GROUPED_SPARSE = 21  # Grouped sparse columns sharing presence patterns
ENC_TEMPLATE_SPARSE = 22  # Template-based sparse encoding - row templates define column presence

def encode_to_bytes_v4(keys, columns, n_lines):
    """Encode flattened columnar data to bytes."""
    output = bytearray()
    output.extend(MAGIC_V4)

    # Separator style
    sep_style = columns.get('_sep_style', 0)
    output.append(sep_style)
    separators = (',', ':') if sep_style == 0 else (', ', ': ')

    # Analyze columns to determine which are "sparse" and should be grouped
    # For datasets with many sparse columns, group them into raw JSON chunks
    # This avoids massive per-column overhead

    dense_keys = []
    sparse_keys = []

    # Calculate sparsity for each column
    for key in keys:
        values = columns[key]
        present_count = sum(1 for v in values if v != '_ABSENT_')
        # A column is "extremely sparse" if present in <5% of rows
        # These columns have high per-column overhead relative to data stored
        if present_count < n_lines * 0.05:
            sparse_keys.append(key)
        else:
            dense_keys.append(key)

    # Use chunk encoding if we have many extremely sparse columns
    # This trades some columnar benefits for reduced overhead
    # Disabled for now to test pure columnar approach
    use_chunk_encoding = False  # len(sparse_keys) > 50

    if use_chunk_encoding:
        # Build per-line JSON chunks for sparse columns
        sparse_chunks = []
        for i in range(n_lines):
            chunk = {}
            for key in sparse_keys:
                val = columns[key][i]
                if val != '_ABSENT_':
                    chunk[key] = val
            if chunk:
                sparse_chunks.append(json.dumps(chunk, separators=separators, ensure_ascii=False))
            else:
                sparse_chunks.append('')

        # Add a special column for the sparse chunk data
        columns['_sparse_chunk'] = sparse_chunks
        active_keys = dense_keys + ['_sparse_chunk']

        # Store the sparse key list so decoder knows which keys came from chunks
        columns['_sparse_keys'] = sparse_keys
    else:
        active_keys = keys
        sparse_keys = []

    # Pre-analyze sparse columns for grouped encoding
    # Group columns by their presence pattern to share index bitmaps
    sparse_column_keys = []
    non_sparse_keys = []
    grouped_patterns = {}
    use_template_encoding = False
    row_templates = None
    template_to_id = None
    template_columns = None

    for key in active_keys:
        if key == '_sparse_chunk':
            non_sparse_keys.append(key)
            continue
        values = columns[key]
        absent_count = sum(1 for v in values if v == '_ABSENT_')
        # Columns with >80% absent values are sparse
        if absent_count > len(values) * 0.80:
            sparse_column_keys.append(key)
        else:
            non_sparse_keys.append(key)

    # Try template-based encoding if we have many sparse columns
    # Template encoding: detect row templates (which columns present per row)
    # and store template ID per row instead of indices per column
    # Compare cost with grouped sparse to decide which is better
    if len(sparse_column_keys) > 50:
        # Compute row templates for sparse columns
        row_templates = []
        for i in range(n_lines):
            present_cols = frozenset(k for k in sparse_column_keys
                                    if columns[k][i] != '_ABSENT_')
            row_templates.append(present_cols)

        # Count template frequencies
        template_counts = Counter(row_templates)

        # Calculate template encoding cost
        n_templates = len(template_counts)
        top_template_coverage = sum(c for _, c in template_counts.most_common(min(256, n_templates)))

        if n_templates <= 256 and top_template_coverage >= n_lines * 0.95:
            # Template encoding cost: template definitions + template IDs per row
            template_cost = 2 + sum(2 + len(tmpl) * 2 for tmpl in template_counts.keys())
            template_cost += n_lines * 1  # 1 byte template ID per row

            # Calculate grouped sparse cost for comparison
            presence_groups_tmp = {}
            for key in sparse_column_keys:
                values = columns[key]
                pattern = tuple(i for i, v in enumerate(values) if v != '_ABSENT_')
                if pattern not in presence_groups_tmp:
                    presence_groups_tmp[pattern] = []
                presence_groups_tmp[pattern].append(key)

            # Grouped sparse cost: indices for each unique pattern
            grouped_cost = sum(len(p) * 2 for p in presence_groups_tmp.keys())

            # Only use template encoding if it's actually cheaper
            if template_cost < grouped_cost:
                use_template_encoding = True
                # Build template ID mapping (most common first for better compression)
                sorted_templates = [t for t, _ in template_counts.most_common()]
                template_to_id = {t: i for i, t in enumerate(sorted_templates)}
                # Get all columns covered by templates
                template_columns = set()
                for tmpl in sorted_templates:
                    template_columns.update(tmpl)

    if use_template_encoding:
        # Template encoding handles all sparse columns
        ungrouped_sparse = []
        grouped_patterns = {}
        grouped_column_set = set()
    else:
        # Fall back to grouped sparse encoding
        row_templates = None
        template_to_id = None
        template_columns = None

        # Group sparse columns by presence pattern
        presence_groups = {}  # pattern -> list of keys
        ungrouped_sparse = sparse_column_keys
        grouped_column_set = set()

        if len(sparse_column_keys) > 10:  # Only use grouped encoding if many sparse cols
            for key in sparse_column_keys:
                values = columns[key]
                pattern = tuple(i for i, v in enumerate(values) if v != '_ABSENT_')
                if pattern not in presence_groups:
                    presence_groups[pattern] = []
                presence_groups[pattern].append(key)

            # Only group patterns that have >1 column (saves index storage)
            grouped_patterns = {p: cols for p, cols in presence_groups.items() if len(cols) > 1}
            ungrouped_sparse = [k for k in sparse_column_keys
                               if all(k not in cols for cols in grouped_patterns.values())]

            # Mark grouped columns as handled
            for cols in grouped_patterns.values():
                grouped_column_set.update(cols)

    # Build final active_keys list for schema
    if use_template_encoding:
        # Template encoding: _template_sparse_ + non-sparse keys
        final_active_keys = ['_template_sparse_'] + non_sparse_keys
    elif grouped_patterns:
        # Grouped sparse: _grouped_sparse_ before non-sparse keys, include ungrouped sparse
        final_active_keys = ['_grouped_sparse_'] + non_sparse_keys + ungrouped_sparse
    else:
        final_active_keys = non_sparse_keys + ungrouped_sparse

    # Schema - only write final active keys
    output.extend(struct.pack('<H', len(final_active_keys)))
    for key in final_active_keys:
        kb = key.encode('utf-8')
        output.extend(struct.pack('<H', len(kb)))
        output.extend(kb)

    output.extend(struct.pack('<I', n_lines))

    # Key orders (per-line)
    key_orders = columns.get('_key_orders', None)
    if key_orders is not None:
        order_strs = [','.join(ko) for ko in key_orders]
        unique_orders = list(dict.fromkeys(order_strs))
        order_to_id = {o: i for i, o in enumerate(unique_orders)}

        output.extend(struct.pack('<H', len(unique_orders)))
        for o in unique_orders:
            ob = o.encode('utf-8')
            output.extend(struct.pack('<I', len(ob)))  # 4 bytes for potentially long key lists
            output.extend(ob)

        if len(unique_orders) <= 256:
            output.append(1)
            output.extend(bytes(order_to_id[o] for o in order_strs))
        else:
            output.append(2)
            output.extend(b''.join(struct.pack('<H', order_to_id[o]) for o in order_strs))
    else:
        output.extend(struct.pack('<H', 0))

    col_info = []
    # separators already defined above

    # Process all columns using final_active_keys
    for key in final_active_keys:
        # Special handling for _grouped_sparse_ - encode all grouped sparse columns
        if key == '_grouped_sparse_':
            output.append(ENC_GROUPED_SPARSE)

            # Number of groups
            output.extend(struct.pack('<H', len(grouped_patterns)))

            group_info = []
            for pattern, group_keys in grouped_patterns.items():
                # Write pattern (indices where values are present)
                output.extend(struct.pack('<H', len(pattern)))
                if len(pattern) > 0:
                    if n_lines <= 0xFFFF:
                        output.extend(struct.pack(f'<{len(pattern)}H', *pattern))
                    else:
                        output.extend(struct.pack(f'<{len(pattern)}I', *pattern))

                # Write number of columns in this group
                output.extend(struct.pack('<H', len(group_keys)))

                # For each column, write key name and values at the pattern indices
                for gkey in group_keys:
                    kb = gkey.encode('utf-8')
                    output.extend(struct.pack('<H', len(kb)))
                    output.extend(kb)

                    # Get values at pattern indices
                    gvalues = columns[gkey]
                    present_vals = [gvalues[i] for i in pattern]

                    # Dictionary encode the values
                    val_strs = []
                    for v in present_vals:
                        if v is None:
                            val_strs.append(NONE_MARKER)
                        else:
                            val_strs.append(json.dumps(v, separators=separators, ensure_ascii=False))

                    freq = Counter(val_strs)
                    sorted_vals = [v for v, _ in freq.most_common()]
                    val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                    # Write dictionary
                    output.extend(struct.pack('<H', len(sorted_vals)))
                    for v in sorted_vals:
                        vb = v.encode('utf-8')
                        output.extend(struct.pack('<I', len(vb)))  # 4 bytes for large values
                        output.extend(vb)

                    # Write indices into dictionary
                    if len(sorted_vals) <= 256:
                        output.append(1)
                        output.extend(bytes(val_to_id[v] for v in val_strs))
                    else:
                        output.append(2)
                        output.extend(b''.join(struct.pack('<H', val_to_id[v]) for v in val_strs))

                group_info.append(f'{len(group_keys)}@{len(pattern)}')

            col_info.append(f'grouped-sparse({"+".join(group_info[:5])}{"..." if len(group_info) > 5 else ""})')
            continue

        # Special handling for _template_sparse_ - template-based sparse encoding
        if key == '_template_sparse_':
            output.append(ENC_TEMPLATE_SPARSE)

            # Get sorted templates (most common first)
            sorted_templates = [t for t, _ in Counter(row_templates).most_common()]

            # Write number of templates
            output.extend(struct.pack('<H', len(sorted_templates)))

            # Write each template definition (list of column keys)
            template_col_lists = []
            for tmpl in sorted_templates:
                # Sort columns for consistent order
                tmpl_cols = sorted(tmpl)
                template_col_lists.append(tmpl_cols)

                # Write number of columns in this template
                output.extend(struct.pack('<H', len(tmpl_cols)))
                # Write column indices (reference into sparse_column_keys)
                sparse_key_to_idx = {k: i for i, k in enumerate(sparse_column_keys)}
                for col in tmpl_cols:
                    output.extend(struct.pack('<H', sparse_key_to_idx[col]))

            # Write template ID per row (1 byte since <= 256 templates)
            template_to_id_local = {frozenset(t): i for i, t in enumerate(sorted_templates)}
            row_template_ids = [template_to_id_local[t] for t in row_templates]
            output.extend(bytes(row_template_ids))

            # Write sparse column keys
            output.extend(struct.pack('<H', len(sparse_column_keys)))
            for sk in sparse_column_keys:
                skb = sk.encode('utf-8')
                output.extend(struct.pack('<H', len(skb)))
                output.extend(skb)

            # For each sparse column, write values only for rows where it's present
            # Group rows by template and write values in template order
            for col_idx, col_key in enumerate(sparse_column_keys):
                col_values = columns[col_key]

                # Collect present values (across all templates that include this column)
                present_vals = []
                for i, tmpl in enumerate(row_templates):
                    if col_key in tmpl:
                        present_vals.append(col_values[i])

                if not present_vals:
                    # Column has no values (shouldn't happen but handle it)
                    output.extend(struct.pack('<H', 0))
                    output.append(1)
                    continue

                # Dictionary encode the values
                val_strs = []
                for v in present_vals:
                    if v is None:
                        val_strs.append(NONE_MARKER)
                    else:
                        val_strs.append(json.dumps(v, separators=separators, ensure_ascii=False))

                freq = Counter(val_strs)
                sorted_vals = [v for v, _ in freq.most_common()]
                val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                # Write dictionary
                output.extend(struct.pack('<H', len(sorted_vals)))
                for v in sorted_vals:
                    vb = v.encode('utf-8')
                    output.extend(struct.pack('<I', len(vb)))
                    output.extend(vb)

                # Write value indices
                if len(sorted_vals) <= 256:
                    output.append(1)
                    output.extend(bytes(val_to_id[v] for v in val_strs))
                else:
                    output.append(2)
                    output.extend(b''.join(struct.pack('<H', val_to_id[v]) for v in val_strs))

            col_info.append(f'template-sparse({len(sorted_templates)} templates, {len(sparse_column_keys)} cols)')
            continue

        values = columns[key]

        # Special handling for _sparse_chunk - encode as raw JSON chunk column
        if key == '_sparse_chunk':
            output.append(ENC_RAW_JSON_CHUNK)

            # Store the sparse keys list so decoder can reconstruct
            sparse_keys_str = '\n'.join(sparse_keys)
            skb = sparse_keys_str.encode('utf-8')
            output.extend(struct.pack('<I', len(skb)))
            output.extend(skb)

            # The chunk values are already JSON strings (or empty strings)
            # Use dictionary encoding for the chunks
            freq = Counter(values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            output.extend(struct.pack('<I', len(sorted_vals)))
            for v in sorted_vals:
                vb = v.encode('utf-8')
                output.extend(struct.pack('<I', len(vb)))
                output.extend(vb)

            if len(sorted_vals) <= 256:
                output.append(1)
                output.extend(bytes(val_to_id[v] for v in values))
            elif len(sorted_vals) <= 65536:
                output.append(2)
                output.extend(b''.join(struct.pack('<H', val_to_id[v]) for v in values))
            else:
                output.append(4)
                output.extend(b''.join(struct.pack('<I', val_to_id[v]) for v in values))

            col_info.append(f'raw-json-chunk({len(sparse_keys)} sparse cols)')
            continue

        col_type, _ = detect_column_type_v4(values, key)

        # Check for sparse column - if >80% absent, use sparse encoding
        absent_count = sum(1 for v in values if v == '_ABSENT_')
        if absent_count > len(values) * 0.80:
            # Sparse encoding: only store (index, value) pairs for present values
            output.append(ENC_SPARSE)

            # Collect present values with their indices
            present = [(i, v) for i, v in enumerate(values) if v != '_ABSENT_']

            # Build dictionary for present values (excluding None)
            # Always use JSON encoding to preserve types
            non_null = [v for _, v in present if v is not None]
            freq = Counter(json.dumps(v, separators=separators, ensure_ascii=False) for v in non_null)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            # Write dictionary
            output.extend(struct.pack('<I', len(sorted_vals)))
            for v in sorted_vals:
                vb = v.encode('utf-8')
                output.extend(struct.pack('<I', len(vb)))
                output.extend(vb)

            # Write number of present values
            output.extend(struct.pack('<I', len(present)))

            # Determine index byte width
            if len(values) <= 0xFFFF:
                output.append(2)
                for idx, val in present:
                    output.extend(struct.pack('<H', idx))
                    if val is None:
                        output.extend(struct.pack('<I', 0xFFFFFFFF))  # Special marker for null
                    else:
                        json_val = json.dumps(val, separators=separators, ensure_ascii=False)
                        output.extend(struct.pack('<I', val_to_id[json_val]))
            else:
                output.append(4)
                for idx, val in present:
                    output.extend(struct.pack('<I', idx))
                    if val is None:
                        output.extend(struct.pack('<I', 0xFFFFFFFF))
                    else:
                        json_val = json.dumps(val, separators=separators, ensure_ascii=False)
                        output.extend(struct.pack('<I', val_to_id[json_val]))

            col_info.append(f'sparse({len(present)}/{len(values)})')
            continue

        # Boolean encoding
        if col_type == 'boolean':
            output.append(ENC_BOOLEAN)
            null_mask = []
            bits = []
            for v in values:
                if isinstance(v, bool):
                    null_mask.append(0)
                    bits.append(1 if v else 0)
                elif v is None:
                    null_mask.append(1)
                    bits.append(0)
                elif v == '_ABSENT_':
                    null_mask.append(2)
                    bits.append(0)
                else:
                    null_mask.append(0)
                    bits.append(1 if v else 0)

            packed_mask = pack_bits(null_mask, 2)
            output.extend(struct.pack('<I', len(packed_mask)))
            output.extend(packed_mask)

            packed_bits = pack_bits(bits, 1)
            output.extend(struct.pack('<I', len(packed_bits)))
            output.extend(packed_bits)

            col_info.append('boolean')
            continue

        # Array encoding (JSON-stringify)
        if col_type == 'array':
            output.append(ENC_NESTED_ARRAY)
            json_strs = []
            for v in values:
                if isinstance(v, list):
                    json_strs.append(json.dumps(v, separators=separators, ensure_ascii=False))
                elif v is None:
                    json_strs.append(NONE_MARKER)
                elif v == '_ABSENT_':
                    json_strs.append('_ABSENT_')
                else:
                    json_strs.append(str(v))

            freq = Counter(json_strs)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            output.extend(struct.pack('<I', len(sorted_vals)))
            for v in sorted_vals:
                vb = v.encode('utf-8')
                output.extend(struct.pack('<I', len(vb)))
                output.extend(vb)

            if len(sorted_vals) <= 256:
                output.append(1)
                output.extend(bytes(val_to_id[v] for v in json_strs))
            elif len(sorted_vals) <= 65536:
                output.append(2)
                output.extend(b''.join(struct.pack('<H', val_to_id[v]) for v in json_strs))
            else:
                output.append(4)
                output.extend(b''.join(struct.pack('<I', val_to_id[v]) for v in json_strs))

            col_info.append(f'array({len(sorted_vals)})')
            continue

        # Dict encoding (shouldn't happen, fallback)
        if col_type == 'dict':
            output.append(ENC_DICTIONARY)
            json_strs = []
            for v in values:
                if isinstance(v, dict):
                    json_strs.append(json.dumps(v, separators=separators, ensure_ascii=False))
                elif v is None:
                    json_strs.append(NONE_MARKER)
                elif v == '_ABSENT_':
                    json_strs.append('_ABSENT_')
                else:
                    json_strs.append(str(v))

            freq = Counter(json_strs)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            output.extend(struct.pack('<I', len(sorted_vals)))
            for v in sorted_vals:
                vb = v.encode('utf-8')
                output.extend(struct.pack('<I', len(vb)))
                output.extend(vb)

            if len(sorted_vals) <= 256:
                output.append(1)
                output.extend(bytes(val_to_id[v] for v in json_strs))
            elif len(sorted_vals) <= 65536:
                output.append(2)
                output.extend(b''.join(struct.pack('<H', val_to_id[v]) for v in json_strs))
            else:
                output.append(4)
                output.extend(b''.join(struct.pack('<I', val_to_id[v]) for v in json_strs))

            col_info.append(f'dict({len(sorted_vals)})')
            continue

        # ISO timestamp encoding - binary frame-of-reference compression
        # Only use binary encoding if column has >50% valid timestamps
        if col_type == 'iso_timestamp':
            # Count valid vs absent/null
            absent_count = sum(1 for v in values if v == '_ABSENT_' or v is None)
            if absent_count > len(values) * 0.5:
                # Too sparse - fall through to dictionary encoding
                pass
            else:
                output.append(ENC_BINARY_TIMESTAMP)

                parsed = []
                format_set = set()
                raw_fallbacks = []
                ms_values = []

                for i, v in enumerate(values):
                    if v is None or v == '_ABSENT_':
                        parsed.append((0, None))
                        ms_values.append(0)
                        if v == '_ABSENT_':
                            raw_fallbacks.append((i, '_ABSENT_'))
                        else:
                            raw_fallbacks.append((i, NONE_MARKER))
                    else:
                        ms_val, fmt = parse_iso_timestamp(str(v))
                        if ms_val is not None:
                            fmt_key = (fmt['ms_digits'], fmt['tz'], fmt['separator'])
                            format_set.add(fmt_key)
                            parsed.append((ms_val, fmt_key))
                            ms_values.append(ms_val)
                        else:
                            parsed.append((0, None))
                            ms_values.append(0)
                            raw_fallbacks.append((i, str(v)))

                # Store format info
                format_list = sorted(format_set)
                fmt_to_id = {f: i for i, f in enumerate(format_list)}
                output.extend(struct.pack('<B', len(format_list)))
                for fmt in format_list:
                    output.append(fmt[0])  # ms_digits
                    tz = fmt[1].encode('utf-8')
                    output.append(len(tz))
                    output.extend(tz)
                    output.append(ord(fmt[2]))  # separator

                # Frame-of-reference: store min value + relative offsets
                valid_ms = [ms for ms, fmt in parsed if fmt is not None]
                min_ms = min(valid_ms) if valid_ms else 0
                max_relative = max(ms - min_ms for ms in valid_ms) if valid_ms else 0

                output.extend(struct.pack('<Q', min_ms))

                # Determine byte width for relative values
                if max_relative <= 0xFFFF:
                    byte_width = 2
                    output.append(2)
                    binary = b''.join(struct.pack('<H', ms - min_ms if fmt else 0) for ms, fmt in parsed)
                elif max_relative <= 0xFFFFFFFF:
                    byte_width = 4
                    output.append(4)
                    binary = b''.join(struct.pack('<I', ms - min_ms if fmt else 0) for ms, fmt in parsed)
                else:
                    byte_width = 8
                    output.append(8)
                    binary = b''.join(struct.pack('<Q', ms - min_ms if fmt else 0) for ms, fmt in parsed)

                output.extend(struct.pack('<I', len(binary)))
                output.extend(binary)

                # Format indices
                if len(format_list) == 1:
                    output.append(0xFF)  # Single-format mode
                else:
                    output.append(len(format_list))
                    fmt_indices = bytes(fmt_to_id.get(fmt, 0) for ms, fmt in parsed)
                    output.extend(fmt_indices)

                # Raw fallbacks
                output.extend(struct.pack('<H', len(raw_fallbacks)))
                for idx, val in raw_fallbacks:
                    output.extend(struct.pack('<I', idx))
                    val_bytes = val.encode('utf-8')
                    output.extend(struct.pack('<H', len(val_bytes)))
                    output.extend(val_bytes)

                col_info.append(f'binary-timestamp{byte_width}')
                continue

        # Integer encoding - use V3's cost-based approach
        if col_type == 'integer':
            # Build nums list with fallbacks for None/_ABSENT_
            nums = []
            raw_fallbacks = []  # (index, value) for non-integer entries
            for i, v in enumerate(values):
                if isinstance(v, int) and not isinstance(v, bool):
                    nums.append(v)
                elif v is None:
                    nums.append(0)  # placeholder
                    raw_fallbacks.append((i, NONE_MARKER))
                elif v == '_ABSENT_':
                    nums.append(0)  # placeholder
                    raw_fallbacks.append((i, '_ABSENT_'))
                else:
                    try:
                        nums.append(int(v))
                    except (ValueError, TypeError):
                        nums.append(0)
                        raw_fallbacks.append((i, str(v)))

            # Check if values are mostly sorted (for delta encoding)
            sorted_count = sum(1 for i in range(1, len(nums)) if nums[i] >= nums[i-1]) if len(nums) > 1 else 0
            use_delta = sorted_count >= len(nums) * 0.7 if nums else False
            unique = set(nums)

            # Calculate costs to choose optimal encoding
            min_val = min(nums) if nums else 0
            max_val = max(nums) if nums else 0

            # Binary cost: byte_width * n_lines
            if min_val >= 0 and max_val <= 255:
                binary_width = 1
            elif min_val >= 0 and max_val <= 65535:
                binary_width = 2
            elif min_val >= -2147483648 and max_val <= 2147483647:
                binary_width = 4
            else:
                binary_width = 8
            binary_cost = binary_width * n_lines

            # Bit-pack cost: calculate exact bits needed
            bits_needed = max_val.bit_length() if max_val > 0 else 1
            bitpack_cost = (bits_needed * n_lines + 7) // 8 + 5  # +5 for metadata

            # Dictionary cost: dict_overhead + index_width * n_lines
            dict_overhead = sum(len(str(v)) + 2 for v in unique)
            if len(unique) <= 256:
                dict_idx_width = 1
            elif len(unique) <= 65536:
                dict_idx_width = 2
            else:
                dict_idx_width = 4
            dict_cost = dict_overhead + dict_idx_width * n_lines

            # Choose best encoding
            use_binary = (binary_cost < dict_cost) or (len(unique) > n_lines * 0.3)
            use_bitpack = (min_val >= 0 and bitpack_cost < binary_cost and bitpack_cost < dict_cost
                          and bits_needed < binary_width * 8)

            if use_bitpack and not use_delta:
                output.append(ENC_BITPACK_INT)
                output.append(bits_needed)

                packed = pack_bits(nums, bits_needed)
                output.extend(struct.pack('<I', len(packed)))
                output.extend(packed)

                # Write fallbacks
                output.extend(struct.pack('<H', len(raw_fallbacks)))
                for idx, val in raw_fallbacks:
                    output.extend(struct.pack('<I', idx))
                    val_bytes = val.encode('utf-8')
                    output.extend(struct.pack('<H', len(val_bytes)))
                    output.extend(val_bytes)

                col_info.append(f'bitpack-int{bits_needed}b')

            elif use_binary and not use_delta:
                output.append(ENC_BINARY_INT)

                if min_val >= 0 and max_val <= 255:
                    byte_width = 1
                    output.append(1)
                    binary = bytes(nums)
                elif min_val >= 0 and max_val <= 65535:
                    byte_width = 2
                    output.append(2)
                    binary = b''.join(struct.pack('<H', n) for n in nums)
                elif min_val >= -2147483648 and max_val <= 2147483647:
                    byte_width = 4
                    output.append(4)
                    binary = b''.join(struct.pack('<i', n) for n in nums)
                else:
                    byte_width = 8
                    output.append(8)
                    binary = b''.join(struct.pack('<q', n) for n in nums)

                output.extend(struct.pack('<I', len(binary)))
                output.extend(binary)

                # Write fallbacks
                output.extend(struct.pack('<H', len(raw_fallbacks)))
                for idx, val in raw_fallbacks:
                    output.extend(struct.pack('<I', idx))
                    val_bytes = val.encode('utf-8')
                    output.extend(struct.pack('<H', len(val_bytes)))
                    output.extend(val_bytes)

                col_info.append(f'binary-int{byte_width}')

            elif use_delta:
                output.append(ENC_DELTA_INTEGER)
                deltas = []
                prev = 0
                for i, v in enumerate(values):
                    if isinstance(v, int) and not isinstance(v, bool):
                        deltas.append(str(v - prev))
                        prev = v
                    elif v is None:
                        deltas.append(NONE_MARKER)
                    elif v == '_ABSENT_':
                        deltas.append('_ABSENT_')
                    else:
                        try:
                            n = int(v)
                            deltas.append(str(n - prev))
                            prev = n
                        except (ValueError, TypeError):
                            s = str(v)
                            escaped = s.replace('\\', '\\\\').replace('\n', '\\n')
                            deltas.append(f"R{escaped}")

                all_text = '\n'.join(deltas)
                output.extend(struct.pack('<I', len(all_text.encode('utf-8'))))
                output.extend(all_text.encode('utf-8'))
                col_info.append('int-delta')
            else:
                # Low cardinality - use dictionary for integers
                output.append(ENC_DICTIONARY_INT)
                str_values = []
                for v in values:
                    if isinstance(v, int) and not isinstance(v, bool):
                        str_values.append(str(v))
                    elif v is None:
                        str_values.append(NONE_MARKER)
                    elif v == '_ABSENT_':
                        str_values.append('_ABSENT_')
                    else:
                        try:
                            str_values.append(str(int(v)))
                        except (ValueError, TypeError):
                            str_values.append(str(v))

                freq = Counter(str_values)
                sorted_vals = [v for v, _ in freq.most_common()]
                val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                output.extend(struct.pack('<I', len(sorted_vals)))
                for v in sorted_vals:
                    vb = v.encode('utf-8')
                    output.extend(struct.pack('<I', len(vb)))
                    output.extend(vb)

                if len(sorted_vals) <= 256:
                    output.append(1)
                    output.extend(bytes(val_to_id[v] for v in str_values))
                elif len(sorted_vals) <= 65536:
                    output.append(2)
                    output.extend(b''.join(struct.pack('<H', val_to_id[v]) for v in str_values))
                else:
                    output.append(4)
                    output.extend(b''.join(struct.pack('<I', val_to_id[v]) for v in str_values))

                col_info.append(f'int-dict({len(sorted_vals)})')
            continue

        # String integer encoding
        if col_type == 'string_integer':
            output.append(ENC_STRING_INT)
            str_values = []
            prev = 0
            for v in values:
                if v is None:
                    str_values.append(NONE_MARKER)
                elif v == '_ABSENT_':
                    str_values.append('_ABSENT_')
                else:
                    try:
                        iv = int(v)
                        delta = iv - prev
                        str_values.append(str(delta))
                        prev = iv
                    except (ValueError, TypeError):
                        str_values.append(str(v))

            all_text = '\n'.join(str_values)
            output.extend(struct.pack('<I', len(all_text.encode('utf-8'))))
            output.extend(all_text.encode('utf-8'))
            col_info.append('string-int')
            continue

        # Default: string/dictionary encoding
        str_values = []
        for v in values:
            if v is None:
                str_values.append(NONE_MARKER)
            elif v == '_ABSENT_':
                str_values.append('_ABSENT_')
            elif isinstance(v, (dict, list)):
                str_values.append(json.dumps(v, separators=separators, ensure_ascii=False))
            else:
                str_values.append(str(v))

        unique = set(str_values)

        if len(unique) <= 16:
            # Bit-packed dictionary
            output.append(ENC_BITPACK_DICT)
            freq = Counter(str_values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            if len(sorted_vals) <= 2:
                bits_per = 1
            elif len(sorted_vals) <= 4:
                bits_per = 2
            elif len(sorted_vals) <= 8:
                bits_per = 3
            else:
                bits_per = 4

            output.append(len(sorted_vals))
            for v in sorted_vals:
                vb = v.encode('utf-8')
                output.extend(struct.pack('<H', len(vb)))
                output.extend(vb)

            output.append(bits_per)
            indices = [val_to_id[v] for v in str_values]
            packed = pack_bits(indices, bits_per)
            output.extend(struct.pack('<I', len(packed)))
            output.extend(packed)

            col_info.append(f'bitpack({len(sorted_vals)}@{bits_per}b)')
        elif len(unique) < n_lines * 0.3:
            # Regular dictionary - only use when <30% unique values
            output.append(ENC_DICTIONARY)
            freq = Counter(str_values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            output.extend(struct.pack('<I', len(sorted_vals)))
            for v in sorted_vals:
                vb = v.encode('utf-8')
                output.extend(struct.pack('<I', len(vb)))
                output.extend(vb)

            if len(sorted_vals) <= 256:
                output.append(1)
                output.extend(bytes(val_to_id[v] for v in str_values))
            elif len(sorted_vals) <= 65536:
                output.append(2)
                output.extend(b''.join(struct.pack('<H', val_to_id[v]) for v in str_values))
            else:
                output.append(4)
                output.extend(b''.join(struct.pack('<I', val_to_id[v]) for v in str_values))

            col_info.append(f'dict({len(sorted_vals)})')
        else:
            # Raw encoding
            output.append(ENC_RAW)
            escaped = [v.replace('\\', '\\\\').replace('\n', '\\n') for v in str_values]
            all_text = '\n'.join(escaped)
            output.extend(struct.pack('<I', len(all_text.encode('utf-8'))))
            output.extend(all_text.encode('utf-8'))
            col_info.append('raw')

    return bytes(output), col_info


def decode_from_bytes_v4(data):
    """Decode V4 bytes back to JSON lines."""
    pos = 0

    magic = data[pos:pos+4]
    pos += 4
    if magic != MAGIC_V4:
        raise ValueError(f"Invalid magic: {magic}, expected {MAGIC_V4}")

    sep_style = data[pos]
    pos += 1

    n_keys = struct.unpack('<H', data[pos:pos+2])[0]
    pos += 2
    keys = []
    for _ in range(n_keys):
        key_len = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2
        keys.append(data[pos:pos+key_len].decode('utf-8'))
        pos += key_len

    n_lines = struct.unpack('<I', data[pos:pos+4])[0]
    pos += 4

    # Read key orders
    n_unique_orders = struct.unpack('<H', data[pos:pos+2])[0]
    pos += 2

    key_orders = None
    if n_unique_orders > 0:
        unique_orders = []
        for _ in range(n_unique_orders):
            order_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            order_str = data[pos:pos+order_len].decode('utf-8')
            pos += order_len
            unique_orders.append(tuple(order_str.split(',')) if order_str else ())

        idx_mode = data[pos]
        pos += 1

        if idx_mode == 1:
            order_indices = list(data[pos:pos+n_lines])
            pos += n_lines
        else:
            order_indices = [struct.unpack('<H', data[pos+i*2:pos+(i+1)*2])[0] for i in range(n_lines)]
            pos += n_lines * 2

        key_orders = [unique_orders[i] for i in order_indices]

    # Decode columns
    columns = {}
    schema_keys = keys.copy()  # Copy keys since we may add to keys during iteration
    for key in schema_keys:
        enc_type = data[pos]
        pos += 1

        if enc_type == ENC_BOOLEAN:
            mask_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            packed_mask = data[pos:pos+mask_len]
            pos += mask_len
            null_mask = unpack_bits(packed_mask, n_lines, 2)

            bits_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            packed_bits = data[pos:pos+bits_len]
            pos += bits_len
            bits = unpack_bits(packed_bits, n_lines, 1)

            values = []
            for i in range(n_lines):
                mask_val = null_mask[i] if i < len(null_mask) else 0
                if mask_val == 1:
                    values.append(None)
                elif mask_val == 2:
                    values.append('_ABSENT_')
                else:
                    values.append(bool(bits[i] if i < len(bits) else 0))
            columns[key] = values

        elif enc_type == ENC_BINARY_TIMESTAMP:
            # Read format info
            n_formats = struct.unpack('<B', data[pos:pos+1])[0]
            pos += 1
            format_list = []
            for _ in range(n_formats):
                ms_digits = data[pos]
                pos += 1
                tz_len = data[pos]
                pos += 1
                tz = data[pos:pos+tz_len].decode('utf-8')
                pos += tz_len
                sep = chr(data[pos])
                pos += 1
                format_list.append({'ms_digits': ms_digits, 'tz': tz, 'separator': sep})

            # Read min_ms
            min_ms = struct.unpack('<Q', data[pos:pos+8])[0]
            pos += 8

            # Read byte width and relative values
            byte_width = data[pos]
            pos += 1
            binary_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            binary_data = data[pos:pos+binary_len]
            pos += binary_len

            if byte_width == 2:
                relative_values = [struct.unpack('<H', binary_data[i*2:(i+1)*2])[0] for i in range(n_lines)]
            elif byte_width == 4:
                relative_values = [struct.unpack('<I', binary_data[i*4:(i+1)*4])[0] for i in range(n_lines)]
            else:
                relative_values = [struct.unpack('<Q', binary_data[i*8:(i+1)*8])[0] for i in range(n_lines)]

            # Read format indices
            fmt_mode = data[pos]
            pos += 1
            if fmt_mode == 0xFF:
                # Single format mode
                fmt_indices = [0] * n_lines
            else:
                fmt_indices = list(data[pos:pos+n_lines])
                pos += n_lines

            # Read fallbacks
            n_fallbacks = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            fallbacks = {}
            for _ in range(n_fallbacks):
                idx = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                val_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                val = data[pos:pos+val_len].decode('utf-8')
                pos += val_len
                fallbacks[idx] = val

            # Reconstruct timestamps
            values = []
            for i, relative in enumerate(relative_values):
                if i in fallbacks:
                    fb = fallbacks[i]
                    if fb == NONE_MARKER:
                        values.append(None)
                    elif fb == '_ABSENT_':
                        values.append('_ABSENT_')
                    else:
                        values.append(fb)
                else:
                    ms_val = min_ms + relative
                    fmt = format_list[fmt_indices[i]] if fmt_indices[i] < len(format_list) else {'ms_digits': 0, 'tz': '', 'separator': 'T'}
                    values.append(reconstruct_iso_timestamp(ms_val, fmt))
            columns[key] = values

        elif enc_type == ENC_BITPACK_INT:
            bits_per_value = data[pos]
            pos += 1

            packed_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            packed_data = data[pos:pos+packed_len]
            pos += packed_len

            nums = unpack_bits(packed_data, n_lines, bits_per_value)

            # Read fallbacks
            n_fallbacks = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            fallbacks = {}
            for _ in range(n_fallbacks):
                idx = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                val_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                val = data[pos:pos+val_len].decode('utf-8')
                pos += val_len
                fallbacks[idx] = val

            values = []
            for i, num in enumerate(nums):
                if i in fallbacks:
                    fb = fallbacks[i]
                    if fb == NONE_MARKER:
                        values.append(None)
                    elif fb == '_ABSENT_':
                        values.append('_ABSENT_')
                    else:
                        values.append(fb)
                else:
                    values.append(num)
            columns[key] = values

        elif enc_type == ENC_BINARY_INT:
            byte_width = data[pos]
            pos += 1

            binary_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            binary_data = data[pos:pos+binary_len]
            pos += binary_len

            if byte_width == 1:
                nums = list(binary_data)
            elif byte_width == 2:
                nums = [struct.unpack('<H', binary_data[i:i+2])[0] for i in range(0, len(binary_data), 2)]
            elif byte_width == 4:
                nums = [struct.unpack('<i', binary_data[i:i+4])[0] for i in range(0, len(binary_data), 4)]
            else:
                nums = [struct.unpack('<q', binary_data[i:i+8])[0] for i in range(0, len(binary_data), 8)]

            # Read fallbacks
            n_fallbacks = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            fallbacks = {}
            for _ in range(n_fallbacks):
                idx = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                val_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                val = data[pos:pos+val_len].decode('utf-8')
                pos += val_len
                fallbacks[idx] = val

            values = []
            for i, num in enumerate(nums):
                if i in fallbacks:
                    fb = fallbacks[i]
                    if fb == NONE_MARKER:
                        values.append(None)
                    elif fb == '_ABSENT_':
                        values.append('_ABSENT_')
                    else:
                        values.append(fb)
                else:
                    values.append(num)
            columns[key] = values

        elif enc_type == ENC_INTEGER_DELTA:
            text_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            text = data[pos:pos+text_len].decode('utf-8')
            pos += text_len

            parts = text.split('\n')
            values = []
            prev = 0
            for p in parts:
                if p == NONE_MARKER:
                    values.append(None)
                elif p == '_ABSENT_':
                    values.append('_ABSENT_')
                elif p.startswith('R'):
                    # Raw fallback value
                    raw = p[1:].replace('\\n', '\n').replace('\\\\', '\\')
                    values.append(raw if raw else None)
                else:
                    delta = int(p)
                    val = prev + delta
                    values.append(val)
                    prev = val
            columns[key] = values

        elif enc_type == ENC_STRING_INT:
            text_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            text = data[pos:pos+text_len].decode('utf-8')
            pos += text_len

            parts = text.split('\n')
            values = []
            prev = 0
            for p in parts:
                if p == NONE_MARKER:
                    values.append(None)
                elif p == '_ABSENT_':
                    values.append('_ABSENT_')
                else:
                    try:
                        delta = int(p)
                        val = prev + delta
                        values.append(str(val))  # Keep as string
                        prev = val
                    except ValueError:
                        values.append(p)
            columns[key] = values

        elif enc_type == ENC_BITPACK_DICT:
            dict_len = data[pos]
            pos += 1
            dictionary = []
            for _ in range(dict_len):
                val_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                dictionary.append(data[pos:pos+val_len].decode('utf-8'))
                pos += val_len

            bits_per = data[pos]
            pos += 1

            packed_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            packed = data[pos:pos+packed_len]
            pos += packed_len

            indices = unpack_bits(packed, n_lines, bits_per)
            values = [dictionary[i] for i in indices]
            columns[key] = values

        elif enc_type == ENC_DICTIONARY or enc_type == ENC_DICTIONARY_INT:
            dict_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            dictionary = []
            for _ in range(dict_len):
                val_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                val_str = data[pos:pos+val_len].decode('utf-8')
                if enc_type == ENC_DICTIONARY_INT:
                    try:
                        dictionary.append(int(val_str))
                    except ValueError:
                        dictionary.append(val_str)
                else:
                    dictionary.append(val_str)
                pos += val_len

            idx_mode = data[pos]
            pos += 1

            if idx_mode == 1:
                indices = list(data[pos:pos+n_lines])
                pos += n_lines
            elif idx_mode == 2:
                indices = [struct.unpack('<H', data[pos+i*2:pos+(i+1)*2])[0] for i in range(n_lines)]
                pos += n_lines * 2
            else:
                indices = [struct.unpack('<I', data[pos+i*4:pos+(i+1)*4])[0] for i in range(n_lines)]
                pos += n_lines * 4

            values = [dictionary[i] for i in indices]
            columns[key] = values

        elif enc_type == ENC_NESTED_ARRAY:
            dict_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            dictionary = []
            for _ in range(dict_len):
                val_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                dictionary.append(data[pos:pos+val_len].decode('utf-8'))
                pos += val_len

            idx_mode = data[pos]
            pos += 1

            if idx_mode == 1:
                indices = list(data[pos:pos+n_lines])
                pos += n_lines
            elif idx_mode == 2:
                indices = [struct.unpack('<H', data[pos+i*2:pos+(i+1)*2])[0] for i in range(n_lines)]
                pos += n_lines * 2
            else:
                indices = [struct.unpack('<I', data[pos+i*4:pos+(i+1)*4])[0] for i in range(n_lines)]
                pos += n_lines * 4

            values = []
            for i in indices:
                json_str = dictionary[i]
                if json_str == NONE_MARKER:
                    values.append(None)
                elif json_str == '_ABSENT_':
                    values.append('_ABSENT_')
                else:
                    try:
                        values.append(json.loads(json_str))
                    except json.JSONDecodeError:
                        values.append(json_str)
            columns[key] = values

        elif enc_type == ENC_SPARSE:
            # Read dictionary
            n_dict = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            dict_vals = []
            for _ in range(n_dict):
                val_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                val = data[pos:pos+val_len].decode('utf-8')
                pos += val_len
                dict_vals.append(val)

            # Read number of present values
            n_present = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4

            # Read index byte width
            idx_width = data[pos]
            pos += 1

            # Start with all ABSENT
            values = ['_ABSENT_'] * n_lines

            # Read present values
            for _ in range(n_present):
                if idx_width == 2:
                    idx = struct.unpack('<H', data[pos:pos+2])[0]
                    pos += 2
                else:
                    idx = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4
                val_id = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4

                if val_id == 0xFFFFFFFF:
                    values[idx] = None
                else:
                    # JSON-parse all values to restore original types
                    json_str = dict_vals[val_id]
                    try:
                        values[idx] = json.loads(json_str)
                    except json.JSONDecodeError:
                        values[idx] = json_str

            columns[key] = values

        elif enc_type == ENC_RAW:
            text_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            text = data[pos:pos+text_len].decode('utf-8')
            pos += text_len

            raw_values = text.split('\n')
            # Unescape: \\ -> \ and \n -> newline
            # Must handle in single pass to avoid ambiguity
            def unescape(s):
                result = []
                i = 0
                while i < len(s):
                    if s[i] == '\\' and i + 1 < len(s):
                        next_char = s[i + 1]
                        if next_char == '\\':
                            result.append('\\')
                            i += 2
                        elif next_char == 'n':
                            result.append('\n')
                            i += 2
                        else:
                            result.append(s[i])
                            i += 1
                    else:
                        result.append(s[i])
                        i += 1
                return ''.join(result)
            values = [unescape(v) for v in raw_values]
            columns[key] = values

        elif enc_type == ENC_RAW_JSON_CHUNK:
            # Read sparse keys list
            sparse_keys_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            sparse_keys_str = data[pos:pos+sparse_keys_len].decode('utf-8')
            pos += sparse_keys_len
            sparse_keys_list = sparse_keys_str.split('\n') if sparse_keys_str else []

            # Read dictionary of chunk values
            n_dict = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            dict_vals = []
            for _ in range(n_dict):
                val_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                dict_vals.append(data[pos:pos+val_len].decode('utf-8'))
                pos += val_len

            # Read index mode and indices
            idx_mode = data[pos]
            pos += 1

            if idx_mode == 1:
                indices = list(data[pos:pos+n_lines])
                pos += n_lines
            elif idx_mode == 2:
                indices = [struct.unpack('<H', data[pos+i*2:pos+(i+1)*2])[0] for i in range(n_lines)]
                pos += n_lines * 2
            else:
                indices = [struct.unpack('<I', data[pos+i*4:pos+(i+1)*4])[0] for i in range(n_lines)]
                pos += n_lines * 4

            # Parse chunks and expand back into sparse columns
            # First, initialize all sparse columns with _ABSENT_
            for sk in sparse_keys_list:
                columns[sk] = ['_ABSENT_'] * n_lines

            # Then parse each chunk and populate the columns
            for i, idx in enumerate(indices):
                chunk_str = dict_vals[idx]
                if chunk_str:
                    try:
                        chunk = json.loads(chunk_str)
                        for sk, val in chunk.items():
                            if sk in columns:
                                columns[sk][i] = val
                    except json.JSONDecodeError:
                        pass

            # Don't store _sparse_chunk itself in columns - it's virtual
            # columns[key] = [dict_vals[i] for i in indices]  # Not needed

        elif enc_type == ENC_GROUPED_SPARSE:
            # Read number of groups
            n_groups = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2

            for _ in range(n_groups):
                # Read pattern (indices where values are present)
                pattern_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2

                if pattern_len > 0:
                    if n_lines <= 0xFFFF:
                        pattern = list(struct.unpack(f'<{pattern_len}H', data[pos:pos+pattern_len*2]))
                        pos += pattern_len * 2
                    else:
                        pattern = list(struct.unpack(f'<{pattern_len}I', data[pos:pos+pattern_len*4]))
                        pos += pattern_len * 4
                else:
                    pattern = []

                # Read number of columns in this group
                n_cols_in_group = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2

                for _ in range(n_cols_in_group):
                    # Read column key
                    key_len = struct.unpack('<H', data[pos:pos+2])[0]
                    pos += 2
                    col_key = data[pos:pos+key_len].decode('utf-8')
                    pos += key_len

                    # Read dictionary
                    dict_len = struct.unpack('<H', data[pos:pos+2])[0]
                    pos += 2
                    dictionary = []
                    for _ in range(dict_len):
                        val_len = struct.unpack('<I', data[pos:pos+4])[0]  # 4 bytes for large values
                        pos += 4
                        dictionary.append(data[pos:pos+val_len].decode('utf-8'))
                        pos += val_len

                    # Read value indices
                    idx_mode = data[pos]
                    pos += 1

                    if idx_mode == 1:
                        val_indices = list(data[pos:pos+pattern_len])
                        pos += pattern_len
                    else:
                        val_indices = [struct.unpack('<H', data[pos+j*2:pos+(j+1)*2])[0] for j in range(pattern_len)]
                        pos += pattern_len * 2

                    # Build full column with _ABSENT_ for missing indices
                    col_values = ['_ABSENT_'] * n_lines
                    for i, idx in enumerate(pattern):
                        val_str = dictionary[val_indices[i]]
                        if val_str == NONE_MARKER:
                            col_values[idx] = None
                        else:
                            try:
                                col_values[idx] = json.loads(val_str)
                            except json.JSONDecodeError:
                                col_values[idx] = val_str

                    columns[col_key] = col_values
                    if col_key not in keys:
                        keys.append(col_key)

        elif enc_type == ENC_TEMPLATE_SPARSE:
            # Read number of templates
            n_templates = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2

            # Read template definitions (column indices per template)
            template_col_indices = []
            for _ in range(n_templates):
                n_cols_in_tmpl = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                col_indices = list(struct.unpack(f'<{n_cols_in_tmpl}H', data[pos:pos+n_cols_in_tmpl*2]))
                pos += n_cols_in_tmpl * 2
                template_col_indices.append(col_indices)

            # Read template ID per row (1 byte each)
            row_template_ids = list(data[pos:pos+n_lines])
            pos += n_lines

            # Read sparse column keys
            n_sparse_cols = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            sparse_col_keys = []
            for _ in range(n_sparse_cols):
                key_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                sparse_col_keys.append(data[pos:pos+key_len].decode('utf-8'))
                pos += key_len

            # Initialize all sparse columns with _ABSENT_
            for sk in sparse_col_keys:
                columns[sk] = ['_ABSENT_'] * n_lines
                if sk not in keys:
                    keys.append(sk)

            # Track which row indices each column has values for (based on templates)
            col_row_indices = {sk: [] for sk in sparse_col_keys}
            for row_idx, tmpl_id in enumerate(row_template_ids):
                for col_idx in template_col_indices[tmpl_id]:
                    col_key = sparse_col_keys[col_idx]
                    col_row_indices[col_key].append(row_idx)

            # Read values for each sparse column
            for col_idx, col_key in enumerate(sparse_col_keys):
                n_present = len(col_row_indices[col_key])

                # Read dictionary
                dict_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                dictionary = []
                for _ in range(dict_len):
                    val_len = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4
                    dictionary.append(data[pos:pos+val_len].decode('utf-8'))
                    pos += val_len

                # Read value indices
                idx_mode = data[pos]
                pos += 1

                if idx_mode == 1:
                    val_indices = list(data[pos:pos+n_present])
                    pos += n_present
                else:
                    val_indices = [struct.unpack('<H', data[pos+j*2:pos+(j+1)*2])[0] for j in range(n_present)]
                    pos += n_present * 2

                # Populate column values
                row_indices = col_row_indices[col_key]
                for i, row_idx in enumerate(row_indices):
                    val_str = dictionary[val_indices[i]]
                    if val_str == NONE_MARKER:
                        columns[col_key][row_idx] = None
                    else:
                        try:
                            columns[col_key][row_idx] = json.loads(val_str)
                        except json.JSONDecodeError:
                            columns[col_key][row_idx] = val_str

        else:
            raise ValueError(f"Unknown encoding type: {enc_type}")

    # Reconstruct JSON lines
    if sep_style == 0:
        separators = (',', ':')
    else:
        separators = (', ', ': ')

    lines = []
    for i in range(n_lines):
        # Build flat dict with original key order
        if key_orders is not None:
            line_keys = key_orders[i]
        else:
            line_keys = keys

        flat = {}
        for key in line_keys:
            if key not in columns:
                continue
            val = columns[key][i]
            if val == '_ABSENT_':
                continue
            elif val == NONE_MARKER:
                # For array field columns (.*.) keep as string since unflatten will parse it
                # For regular columns, convert to Python None
                if '.*.' in key or key.endswith('._len'):
                    flat[key] = val
                else:
                    flat[key] = None
            else:
                flat[key] = val

        if '_raw' in flat:
            lines.append(flat['_raw'])
        else:
            # Unflatten and serialize
            nested = unflatten_object(flat)
            lines.append(json.dumps(nested, separators=separators, ensure_ascii=False))

    return lines


def verify_file_v4(input_file):
    """Encode and decode file, verify reconstruction."""
    with open(input_file, 'r', errors='replace') as f:
        original_lines = [l.rstrip('\n') for l in f]

    print(f"V4 Verifying {len(original_lines)} lines (flattened)...")

    start = time.time()
    keys, columns, parsed = encode_json_logs_flat(original_lines)
    binary_data, col_info = encode_to_bytes_v4(keys, columns, len(original_lines))
    encode_time = time.time() - start

    print(f"  Flattened schema: {len(keys)} columns")
    print(f"  Column encoding: {col_info}")

    start = time.time()
    decoded_lines = decode_from_bytes_v4(binary_data)
    decode_time = time.time() - start

    # Verify
    success = True
    for i, (orig, dec) in enumerate(zip(original_lines, decoded_lines)):
        orig_obj = json.loads(orig) if orig.strip() else {}
        dec_obj = json.loads(dec) if dec.strip() else {}
        if orig_obj != dec_obj:
            success = False
            print(f"\n✗ Line {i} semantic mismatch")
            # Find diff
            def find_diff(o1, o2, path=''):
                if type(o1) != type(o2):
                    return f'{path}: type {type(o1).__name__} vs {type(o2).__name__}'
                if isinstance(o1, dict):
                    for k in set(list(o1.keys()) + list(o2.keys())):
                        if k not in o1:
                            return f'{path}.{k}: missing in orig'
                        if k not in o2:
                            return f'{path}.{k}: missing in decoded'
                        result = find_diff(o1[k], o2[k], f'{path}.{k}')
                        if result:
                            return result
                elif isinstance(o1, list):
                    if len(o1) != len(o2):
                        return f'{path}: list len {len(o1)} vs {len(o2)}'
                    for j, (a, b) in enumerate(zip(o1, o2)):
                        result = find_diff(a, b, f'{path}[{j}]')
                        if result:
                            return result
                else:
                    if o1 != o2:
                        return f'{path}: {repr(o1)[:50]} vs {repr(o2)[:50]}'
                return None
            print(f"  diff: {find_diff(orig_obj, dec_obj)}")
            break

    if success:
        print(f"✓ All {len(original_lines)} lines verified!")

    print(f"  Encode: {encode_time:.2f}s ({len(original_lines)/encode_time:.0f} lines/sec)")
    print(f"  Decode: {decode_time:.2f}s ({len(original_lines)/decode_time:.0f} lines/sec)")
    print(f"  Size: {len(binary_data):,} bytes ({len(binary_data)/len(''.join(original_lines))*100:.1f}% of original)")

    if success:
        return True, binary_data
    return False, None


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python json_codec_v4.py verify <file>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == 'verify':
        verify_file_v4(sys.argv[2])

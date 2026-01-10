#!/usr/bin/env python3
"""
JSON log compression v3 - with recursive Drain template extraction.

Key insight: High-cardinality string fields often contain structure that
can be discovered using the same Drain algorithm we use for full log lines.
We treat each field's values as a mini-log and apply Drain recursively.

This is much more general than regex-based patterns - Drain will discover
templates automatically from any structured text.
"""
import sys
import struct
import time
import re
import json
from collections import Counter

# Import Drain for template discovery
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

# Encoding types
ENC_RAW = 0
ENC_DICTIONARY = 1
ENC_DELTA_INTEGER = 2
ENC_DELTA_TIMESTAMP = 3
ENC_PREFIX_DELTA = 4
ENC_TEMPLATE = 5
ENC_PREFIX_BINARY = 6
ENC_DRAIN_TEMPLATE = 7  # Drain-discovered templates
ENC_PATH_COLUMNAR = 8   # Delimiter-based columnar (for URL paths)
ENC_BINARY_INT = 9      # Binary packed integers (1/2/4 bytes based on range)
ENC_BINARY_TIMESTAMP = 10  # Binary frame-of-reference timestamp encoding
ENC_BITPACK_DICT = 11   # Bit-packed dictionary indices for very low cardinality
ENC_BITPACK_INT = 12    # Bit-packed integers for sub-byte precision
ENC_BITPACK_PREFIX = 13 # Bit-packed prefix-binary for sub-byte precision
ENC_STRING_INT = 14     # Integer-encoded values that should decode back to strings
ENC_DICTIONARY_INT = 15 # Dictionary encoding for integers (values decoded as int)
ENC_NESTED_OBJECT = 16  # Nested JSON object - recursively encoded
ENC_NESTED_ARRAY = 17   # Nested JSON array - stored as JSON strings
ENC_BOOLEAN = 18        # Boolean values (bit-packed)
ENC_UUID_BINARY = 19    # UUID as 16 bytes binary
ENC_HEX_BINARY = 20     # Hex string as binary bytes
ENC_UUID_LIKE = 21      # UUID-like strings with variable lengths (cloudtrail style)


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


def encode_varint(n):
    """Encode an unsigned integer as a variable-length integer (LEB128-style)"""
    result = bytearray()
    while n >= 0x80:
        result.append((n & 0x7F) | 0x80)
        n >>= 7
    result.append(n)
    return bytes(result)


def decode_varint(data, pos):
    """Decode a variable-length integer, returns (value, new_pos)"""
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not (byte & 0x80):
            break
        shift += 7
    return result, pos


def encode_varints(nums):
    """Encode a list of unsigned integers as concatenated varints"""
    result = bytearray()
    for n in nums:
        while n >= 0x80:
            result.append((n & 0x7F) | 0x80)
            n >>= 7
        result.append(n)
    return bytes(result)


def decode_varints(data, pos, count):
    """Decode count varints from data starting at pos"""
    result = []
    for _ in range(count):
        n = 0
        shift = 0
        while True:
            byte = data[pos]
            n |= (byte & 0x7F) << shift
            pos += 1
            if not (byte & 0x80):
                break
            shift += 7
        result.append(n)
    return result, pos


# Patterns
ISO_TIMESTAMP_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')
PREFIX_ID_RE = re.compile(r'^([a-zA-Z][\w-]*)-(\d+)$')
SAFE_INT_RE = re.compile(r'^(-?[1-9]\d*|0)$')


def create_drain_miner(use_masking=False):
    """Create a Drain template miner with config optimized for field values"""
    config = TemplateMinerConfig()
    config.drain_sim_th = 0.4  # Lower threshold to catch more variations
    config.drain_depth = 4
    config.drain_max_children = 100
    config.drain_max_clusters = 1024

    if use_masking:
        # Pre-mask numbers in URL-like patterns to help Drain generalize
        from drain3.masking import MaskingInstruction
        config.masking_instructions = [
            MaskingInstruction(pattern=r'/(\d+)(?=/|$)', mask_with='/<NUM>'),
            MaskingInstruction(pattern=r'=(\d+)(?=&|$)', mask_with='=<NUM>'),
        ]

    return TemplateMiner(config=config)


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
    # Years contribution
    years_since = y - 1970
    leap_years = (y - 1969) // 4 - (y - 1901) // 100 + (y - 1601) // 400
    days = years_since * 365 + leap_years

    # Month contribution
    days += DAYS_BEFORE[mo - 1]
    # Leap year adjustment for months after February
    is_leap = (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0)
    if mo > 2 and is_leap:
        days += 1

    # Day contribution (minus 1 because Jan 1 = day 0)
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

    # Days in each month (non-leap year)
    DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

    # Find year
    year = 1970
    while True:
        is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
        days_in_year = 366 if is_leap else 365
        if days < days_in_year:
            break
        days -= days_in_year
        year += 1

    # Find month
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

    day = days + 1  # Days are 1-indexed

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


def extract_drain_templates(values, use_masking=False):
    """
    Use Drain to discover templates in a list of string values.

    Returns: (templates_dict, assignments, n_vars_per_template) or (None, None, None)

    templates_dict: {cluster_id: template_string}
    assignments: list of (cluster_id, [var1, var2, ...]) per value
    n_vars_per_template: {cluster_id: number_of_variables}
    """
    if not values:
        return None, None, None

    str_values = [str(v) if v else '' for v in values]

    # Sample to train Drain
    sample = str_values[:min(5000, len(str_values))]

    miner = create_drain_miner(use_masking=use_masking)

    # Train on sample
    for v in sample:
        if v:
            miner.add_log_message(v)

    # Check if we found useful templates
    clusters = miner.drain.clusters
    if not clusters:
        return None, None, None

    # Count how many values match each template
    template_counts = Counter()
    for v in sample:
        if v:
            result = miner.match(v)
            if result:
                template_counts[result.cluster_id] += 1

    # Check coverage - at least 80% should match some template
    total_matched = sum(template_counts.values())
    if total_matched < len(sample) * 0.8:
        return None, None, None

    # Check that templates actually have variables (not just static strings)
    has_variables = False
    for cluster in clusters:
        if '<*>' in cluster.get_template():
            has_variables = True
            break

    if not has_variables:
        return None, None, None

    # Build templates dict
    templates_dict = {}
    n_vars_per_template = {}
    for cluster in clusters:
        template = cluster.get_template()
        templates_dict[cluster.cluster_id] = template
        n_vars_per_template[cluster.cluster_id] = template.count('<*>')

    # Assign all values to templates and extract variables
    assignments = []
    for v in str_values:
        if not v:
            assignments.append((0, []))
            continue

        result = miner.match(v)
        if result:
            # Extract variables by comparing value to template
            template = templates_dict[result.cluster_id]
            variables = extract_variables(v, template)
            assignments.append((result.cluster_id, variables))
        else:
            # Fallback - store as raw
            assignments.append((0, [v]))

    return templates_dict, assignments, n_vars_per_template


def extract_variables(value, template):
    """Extract variable values from a string given its template"""
    # Template has <*> placeholders, we need to extract what's in those positions
    # Convert template to regex
    parts = template.split('<*>')

    if len(parts) == 1:
        # No variables
        return []

    # Build regex to capture variables
    regex_parts = []
    for i, part in enumerate(parts):
        regex_parts.append(re.escape(part))
        if i < len(parts) - 1:
            regex_parts.append('(.*?)')

    pattern = '^' + ''.join(regex_parts) + '$'

    try:
        m = re.match(pattern, value)
        if m:
            return list(m.groups())
    except re.error:
        pass

    # Fallback - try greedy matching
    variables = []
    remaining = value
    for i, part in enumerate(parts[:-1]):
        if part:
            idx = remaining.find(part)
            if idx > 0:
                variables.append(remaining[:idx])
            remaining = remaining[idx + len(part):]

        # Find next static part
        next_part = parts[i + 1] if i + 1 < len(parts) else ''
        if next_part:
            idx = remaining.find(next_part)
            if idx >= 0:
                variables.append(remaining[:idx])
                remaining = remaining[idx:]
            else:
                variables.append(remaining)
                remaining = ''
        elif i == len(parts) - 2:
            variables.append(remaining)

    return variables


def detect_column_type(values, key_hint=None):
    """Detect column type from sample values"""
    # Use ALL non-null values for type detection to handle rare types correctly
    # This is important for fields that are mostly null but occasionally have dicts/lists
    sample = [v for v in values if v is not None and v != '' and v != '_ABSENT_']
    if not sample:
        return 'string', None

    # For very large columns, subsample to avoid slowness
    if len(sample) > 5000:
        import random
        sample = random.sample(sample, 5000)

    # Filter out None and absent values for type detection
    non_null_sample = [v for v in sample if v is not None and v != '_ABSENT_']

    # Check for booleans FIRST (bool is a subclass of int in Python!)
    bool_count = sum(1 for v in non_null_sample if isinstance(v, bool))
    if non_null_sample and bool_count >= len(non_null_sample) * 0.9:
        return 'boolean', None

    # Check for nested objects (dicts) - handle recursively
    dict_count = sum(1 for v in non_null_sample if isinstance(v, dict))
    if non_null_sample and dict_count >= len(non_null_sample) * 0.9:
        return 'nested_object', None

    # Check for nested arrays (lists) - store as JSON strings
    list_count = sum(1 for v in non_null_sample if isinstance(v, list))
    if non_null_sample and list_count >= len(non_null_sample) * 0.9:
        return 'nested_array', None

    str_sample = [str(v) for v in sample]

    # Check for ISO timestamps
    iso_count = sum(1 for v in str_sample if ISO_TIMESTAMP_RE.match(v))
    if iso_count >= len(str_sample) * 0.9:
        return 'iso_timestamp', None

    # Check for prefixed IDs
    prefix_count = sum(1 for v in str_sample if PREFIX_ID_RE.match(v))
    if prefix_count >= len(str_sample) * 0.9:
        prefixes = Counter()
        for v in str_sample:
            m = PREFIX_ID_RE.match(v)
            if m:
                prefixes[m.group(1)] += 1

        if len(prefixes) == 1:
            nums = []
            for v in str_sample:
                m = PREFIX_ID_RE.match(v)
                if m:
                    nums.append(int(m.group(2)))

            unique_ratio = len(set(nums)) / len(nums)

            if unique_ratio < 0.3:
                return 'string', None

            sorted_count = sum(1 for i in range(1, len(nums)) if nums[i] >= nums[i-1])
            if sorted_count >= len(nums) * 0.6:
                return 'prefix_id', None
            else:
                return 'prefix_binary', None

    # Check for integers - distinguish between real ints and string ints
    if all(isinstance(v, int) for v in sample):
        return 'integer', None

    # Check for strings that look like integers - these must stay as strings
    int_count = sum(1 for v in str_sample if SAFE_INT_RE.match(v))
    if int_count >= len(str_sample) * 0.9:
        # Check if original values were strings (not Python ints)
        if all(isinstance(v, str) for v in sample if v is not None):
            return 'string_integer', None  # Must decode back to strings
        return 'integer', None

    # NOTE: Drain template detection is disabled for byte-accurate reconstruction.
    # Drain normalizes whitespace internally which corrupts multi-space sequences.
    # The compression benefit is marginal compared to dictionary encoding.
    # If you need Drain templates, uncomment below (will lose exact reconstruction):
    #
    # unique_ratio = len(set(str_sample)) / len(str_sample)
    # if unique_ratio > 0.3:  # High cardinality - try Drain
    #     templates, assignments, n_vars = extract_drain_templates(sample)
    #     if templates and len(templates) <= 50:
    #         return 'drain_template', (templates, n_vars, False)
    #     templates, assignments, n_vars = extract_drain_templates(sample, use_masking=True)
    #     if templates and len(templates) <= 50:
    #         return 'drain_template', (templates, n_vars, True)

    # Check for UUID-like strings (hex with dashes, variable length)
    # This handles cloudtrail-style IDs like "3038ebd2-c98a-4c65-9b6e-e22506292313"
    uuid_like_pattern = re.compile(r'^[0-9a-fA-F-]+$')
    uuid_like_count = sum(1 for v in str_sample if uuid_like_pattern.match(v) and '-' in v)
    unique = set(str_sample)
    if uuid_like_count >= len(str_sample) * 0.9 and len(unique) > 100:
        return 'uuid_like', None

    # Check for pure hex strings (no dashes, even length)
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    hex_count = sum(1 for v in str_sample if hex_pattern.match(v) and len(v) % 2 == 0)
    if hex_count >= len(str_sample) * 0.9 and len(unique) > 100:
        return 'hex_binary', None

    return 'string', None


def encode_path_column(output, var_values, n_lines):
    """Encode path-like strings by splitting on / delimiter and encoding each segment"""
    output.append(ENC_PATH_COLUMNAR)

    # Check if all values have a leading slash
    has_leading_slash = all(v.startswith('/') for v in var_values if v)

    # Split all values into segments
    all_segments = []
    max_segments = 0
    for v in var_values:
        # Strip leading/trailing slashes and split
        segments = v.strip('/').split('/') if v else ['']
        all_segments.append(segments)
        max_segments = max(max_segments, len(segments))

    # Store leading slash flag (1 = has leading slash, 0 = no leading slash)
    output.append(1 if has_leading_slash else 0)

    # Pad to same length
    for segments in all_segments:
        while len(segments) < max_segments:
            segments.append('')

    output.append(max_segments)

    # Encode each segment position as a column
    encodings = []
    for pos in range(max_segments):
        seg_values = [s[pos] for s in all_segments]
        unique = set(seg_values)
        all_numeric = all(v.isdigit() for v in seg_values if v)

        # Check for constant segment (only 1 unique value)
        if len(unique) == 1:
            # Constant segment - just store the single value, no indices needed
            output.append(3)  # type=constant
            const_val = list(unique)[0]
            vb = const_val.encode('utf-8')
            output.append(len(vb))
            output.extend(vb)
            encodings.append(f'const({const_val})')
        elif all_numeric and len(unique) > 256:
            # Binary encoding for numeric segments
            nums = [int(v) if v.isdigit() else 0 for v in seg_values]
            max_val = max(nums) if nums else 0

            # Calculate costs for fixed-width vs bit-packed
            bits_needed = max_val.bit_length() if max_val > 0 else 1
            if max_val <= 0xFFFF:
                byte_width = 2
            else:
                byte_width = 4

            fixed_cost = byte_width * n_lines
            bitpack_cost = (bits_needed * n_lines + 7) // 8 + 5

            if bits_needed < byte_width * 8 and bitpack_cost < fixed_cost:
                # Use bit-packed encoding
                output.append(5)  # type=bitpack numeric
                output.append(bits_needed)
                packed = pack_bits(nums, bits_needed)
                output.extend(struct.pack('<I', len(packed)))
                output.extend(packed)
                encodings.append(f'bitpack{bits_needed}b')
            elif max_val <= 0xFFFF:
                output.append(2)  # type=binary 2-byte
                binary = b''.join(struct.pack('<H', n) for n in nums)
                output.extend(struct.pack('<I', len(binary)))
                output.extend(binary)
                encodings.append('bin')
            else:
                output.append(1)  # type=binary 4-byte
                binary = b''.join(struct.pack('<I', n) for n in nums)
                output.extend(struct.pack('<I', len(binary)))
                output.extend(binary)
                encodings.append('bin')
        elif 2 <= len(unique) <= 16:
            # Bit-packed dictionary for very low cardinality
            output.append(4)  # type=bitpack
            freq = Counter(seg_values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            # Determine bits per index
            if len(sorted_vals) <= 2:
                bits_per = 1
            elif len(sorted_vals) <= 4:
                bits_per = 2
            elif len(sorted_vals) <= 8:
                bits_per = 3
            else:
                bits_per = 4

            # Write dictionary
            output.append(len(sorted_vals))
            for v in sorted_vals:
                vb = v.encode('utf-8')
                output.append(len(vb))
                output.extend(vb)

            # Write bits per value
            output.append(bits_per)

            # Pack indices into bytes
            indices = [val_to_id[v] for v in seg_values]
            packed = bytearray()
            current_byte = 0
            bits_used = 0

            for idx in indices:
                current_byte |= (idx << bits_used)
                bits_used += bits_per
                while bits_used >= 8:
                    packed.append(current_byte & 0xFF)
                    current_byte >>= 8
                    bits_used -= 8

            if bits_used > 0:
                packed.append(current_byte & 0xFF)

            output.extend(struct.pack('<I', len(packed)))
            output.extend(packed)
            encodings.append(f'bitpack({len(unique)}@{bits_per}b)')
        else:
            # Dictionary encoding
            output.append(0)  # type=dict
            freq = Counter(seg_values)
            sorted_vals = [v for v, _ in freq.most_common()]
            val_to_id = {v: i for i, v in enumerate(sorted_vals)}

            output.extend(struct.pack('<H', len(sorted_vals)))
            for v in sorted_vals:
                vb = v.encode('utf-8')
                output.append(len(vb))
                output.extend(vb)

            if len(sorted_vals) <= 256:
                output.append(1)  # byte indices
                output.extend(bytes(val_to_id[v] for v in seg_values))
            else:
                output.append(0)  # text indices
                indices = '\n'.join(str(val_to_id[v]) for v in seg_values)
                output.extend(struct.pack('<I', len(indices.encode('utf-8'))))
                output.extend(indices.encode('utf-8'))
            encodings.append(f'dict({len(unique)})')

    return f'path({max_segments}:{",".join(encodings)})'


def encode_variable_column(output, var_values, n_lines, depth=0):
    """Encode a variable column with optimal strategy (dict, binary, or recursive Drain)"""
    unique = set(var_values)
    unique_ratio = len(unique) / len(var_values) if var_values else 1

    # Check if all values are numeric
    all_numeric = all(v.isdigit() or (v.startswith('-') and v[1:].isdigit()) for v in var_values if v)

    if all_numeric and len(unique) > 256:
        # Use binary for high-cardinality numbers
        output.append(ENC_PREFIX_BINARY)

        nums = []
        for v in var_values:
            try:
                nums.append(int(v))
            except (ValueError, TypeError):
                nums.append(0)

        max_val = max(abs(n) for n in nums) if nums else 0
        if max_val > 0x7FFFFFFF:
            byte_width = 8
            output.append(8)
        else:
            byte_width = 4
            output.append(4)

        if byte_width == 4:
            binary = b''.join(struct.pack('<i', n) for n in nums)
        else:
            binary = b''.join(struct.pack('<q', n) for n in nums)

        output.extend(struct.pack('<I', len(binary)))
        output.extend(binary)

        return 'binary'

    # For high-cardinality strings with paths, use columnar path encoding
    if depth < 2 and unique_ratio > 0.3 and len(unique) > 100:
        # Check if these look like paths (contain / delimiter)
        path_like = sum(1 for v in var_values[:100] if '/' in v) > 80

        if path_like:
            # Use delimiter-based columnar encoding for paths
            return encode_path_column(output, var_values, n_lines)

        # NOTE: Drain template encoding is disabled for byte-accurate reconstruction.
        # Drain normalizes whitespace internally, which corrupts multi-space sequences.

    # Check if all values are UUIDs (8-4-4-4-12 hex format)
    uuid_pattern = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    all_uuid = all(uuid_pattern.match(v) for v in var_values if v)
    if all_uuid and len(unique) > 100:
        # UUID binary encoding: 36 chars -> 16 bytes (55% smaller)
        output.append(ENC_UUID_BINARY)
        output.extend(struct.pack('<I', len(var_values)))
        for v in var_values:
            # Remove dashes and convert to bytes
            hex_str = v.replace('-', '')
            output.extend(bytes.fromhex(hex_str))
        return 'uuid-binary'

    # Check if all values are hex strings (even length, all hex chars)
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    all_hex = all(hex_pattern.match(v) and len(v) % 2 == 0 for v in var_values if v)
    if all_hex and len(unique) > 100:
        # Hex binary encoding: 2 chars -> 1 byte (50% smaller)
        output.append(ENC_HEX_BINARY)
        output.extend(struct.pack('<I', len(var_values)))
        # Store hex length for first value (assuming all same length)
        hex_len = len(var_values[0]) if var_values else 0
        output.append(hex_len)
        for v in var_values:
            output.extend(bytes.fromhex(v))
        return 'hex-binary'

    # Check if values are UUID-like (hex chars with dashes, variable length)
    # This handles cloudtrail-style IDs like "3038ebd2-c98a-4c65-9b6e-e22506292313"
    uuid_like_pattern = re.compile(r'^[0-9a-fA-F-]+$')
    all_uuid_like = all(uuid_like_pattern.match(v) and '-' in v for v in var_values if v)
    if all_uuid_like and len(unique) > 100:
        # UUID-like binary encoding:
        # - Store dash positions as a template, then hex bytes
        # - Group values by their dash pattern for better compression
        output.append(ENC_UUID_LIKE)
        output.extend(struct.pack('<I', len(var_values)))

        # Extract dash positions for each value
        def get_dash_pattern(s):
            return tuple(i for i, c in enumerate(s) if c == '-')

        # Group by pattern
        patterns = {}
        for i, v in enumerate(var_values):
            pattern = get_dash_pattern(v)
            if pattern not in patterns:
                patterns[pattern] = []
            patterns[pattern].append((i, v))

        # Write number of patterns
        output.extend(struct.pack('<H', len(patterns)))

        # For each pattern: [pattern length] [dash positions] [count] [indices + hex data]
        for pattern, items in patterns.items():
            # Write pattern
            output.append(len(pattern))
            for pos in pattern:
                output.append(pos)

            # Write count
            output.extend(struct.pack('<I', len(items)))

            # Write indices and hex data
            for idx, v in items:
                output.extend(struct.pack('<I', idx))
                hex_only = v.replace('-', '')
                orig_hex_len = len(hex_only)  # Store original length
                # Ensure even length for bytes.fromhex
                if len(hex_only) % 2 == 1:
                    hex_only = '0' + hex_only
                hex_bytes = bytes.fromhex(hex_only)
                output.append(len(hex_bytes))
                output.append(orig_hex_len)  # Store original hex length to know if padding was added
                output.extend(hex_bytes)

        return 'uuid-like-binary'

    # Default: dictionary encoding
    output.append(ENC_DICTIONARY)
    freq = Counter(var_values)
    sorted_vals = [v for v, _ in freq.most_common()]
    val_to_id = {v: i for i, v in enumerate(sorted_vals)}

    output.extend(struct.pack('<I', len(sorted_vals)))
    for v in sorted_vals:
        vb = v.encode('utf-8')
        output.extend(struct.pack('<I', len(vb)))  # 4 bytes for consistency with main encoder
        output.extend(vb)

    if len(sorted_vals) <= 256:
        output.append(1)
        output.extend(bytes(val_to_id[v] for v in var_values))
    else:
        output.append(0)
        indices = '\n'.join(str(val_to_id[v]) for v in var_values)
        output.extend(struct.pack('<I', len(indices.encode('utf-8'))))
        output.extend(indices.encode('utf-8'))

    return 'dict'


def encode_json_logs(lines):
    """Parse JSON lines and extract columnar data"""
    parsed = []
    all_keys = []
    key_orders = []  # Per-line key order tuples

    # Detect JSON separator style from first valid JSON line
    # Style 0: compact (no spaces): {"a":"b","c":"d"}
    # Style 1: space after colon: {"a": "b", "c": "d"}
    # Style 2: space after colon and comma: {"a": "b", "c": "d"} (same as 1 for json.dumps)
    separator_style = 0  # default compact
    for line in lines:
        line_stripped = line.strip()
        if line_stripped and line_stripped.startswith('{'):
            # Check if there's a space after first colon
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
                parsed.append(obj)
                key_orders.append(tuple(obj.keys()))  # Preserve exact key order
                for k in obj.keys():
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

    columns = {}
    for key in all_keys:
        # Use '_ABSENT_' marker for truly absent keys (vs null values)
        col_values = []
        for obj in parsed:
            if key in obj:
                col_values.append(obj[key])  # Could be None (null in JSON)
            else:
                col_values.append('_ABSENT_')  # Key not present
        columns[key] = col_values

    # Store separator style in special column
    columns['_sep_style'] = separator_style
    # Store key orders (will be encoded as dictionary)
    columns['_key_orders'] = key_orders

    return all_keys, columns, parsed


def encode_to_bytes(keys, columns, n_lines):
    """Encode columnar data to bytes"""
    output = bytearray()
    output.extend(b'JSN3')  # Magic v3

    # Write separator style (compact=0 or spaced=1)
    sep_style = columns.get('_sep_style', 0)
    output.append(sep_style)

    # Write schema
    output.extend(struct.pack('<H', len(keys)))
    for key in keys:
        kb = key.encode('utf-8')
        output.extend(struct.pack('<H', len(kb)))
        output.extend(kb)

    output.extend(struct.pack('<I', n_lines))

    # Encode key orders (for preserving per-line key order)
    key_orders = columns.get('_key_orders', None)
    if key_orders is not None:
        # Convert tuples to strings for dictionary encoding
        order_strs = [','.join(ko) for ko in key_orders]
        unique_orders = list(dict.fromkeys(order_strs))  # Preserve order, remove dups
        order_to_id = {o: i for i, o in enumerate(unique_orders)}

        output.extend(struct.pack('<H', len(unique_orders)))
        for o in unique_orders:
            ob = o.encode('utf-8')
            output.extend(struct.pack('<H', len(ob)))
            output.extend(ob)

        # Store indices
        if len(unique_orders) <= 256:
            output.append(1)
            output.extend(bytes(order_to_id[o] for o in order_strs))
        else:
            output.append(2)
            output.extend(b''.join(struct.pack('<H', order_to_id[o]) for o in order_strs))
    else:
        output.extend(struct.pack('<H', 0))  # No key orders

    col_info = []

    # Special marker for None values (distinct from empty string and absent)
    NONE_MARKER = '\x00__NULL__\x00'

    for key in keys:
        values = columns[key]

        col_type, extra = detect_column_type(values, key)

        # Handle nested objects - recursively encode as columnar data
        if col_type == 'nested_object':
            output.append(ENC_NESTED_OBJECT)

            sep_style = columns.get('_sep_style', 0)
            separators = (',', ':') if sep_style == 0 else (', ', ': ')

            # Build null mask: 0=has value, 1=null, 2=absent
            null_mask = []
            nested_lines = []
            for v in values:
                if isinstance(v, dict):
                    null_mask.append(0)  # Has value
                    nested_lines.append(json.dumps(v, separators=separators, ensure_ascii=False))
                elif v is None:
                    null_mask.append(1)  # Null
                    nested_lines.append('{}')  # placeholder
                elif v == '_ABSENT_':
                    null_mask.append(2)  # Absent
                    nested_lines.append('{}')  # placeholder
                else:
                    null_mask.append(0)  # Treat as value
                    nested_lines.append(json.dumps(v, separators=separators, ensure_ascii=False) if isinstance(v, (dict, list)) else '{}')

            # Write null mask
            packed_mask = pack_bits(null_mask, 2)
            output.extend(struct.pack('<I', len(packed_mask)))
            output.extend(packed_mask)

            # Recursively encode nested objects
            nested_keys, nested_columns, _ = encode_json_logs(nested_lines)
            nested_data, nested_info = encode_to_bytes(nested_keys, nested_columns, len(nested_lines))

            output.extend(struct.pack('<I', len(nested_data)))
            output.extend(nested_data)

            col_info.append(f'nested-recursive({",".join(nested_info)})')
            continue

        # Handle nested arrays - store as JSON strings
        if col_type == 'nested_array':
            output.append(ENC_NESTED_ARRAY)

            sep_style = columns.get('_sep_style', 0)
            separators = (',', ':') if sep_style == 0 else (', ', ': ')

            # Convert arrays to JSON strings
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

            # Dictionary encode the JSON strings
            unique = set(json_strs)
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

            col_info.append(f'nested-array({len(unique)})')
            continue

        # Handle booleans - bit-pack them with null mask
        if col_type == 'boolean':
            output.append(ENC_BOOLEAN)

            # Track null/absent with 2-bit mask: 0=value, 1=null, 2=absent
            null_mask = []
            bits = []
            for v in values:
                if isinstance(v, bool):
                    null_mask.append(0)  # Has value
                    bits.append(1 if v else 0)
                elif v is None:
                    null_mask.append(1)  # Null
                    bits.append(0)
                elif v == '_ABSENT_':
                    null_mask.append(2)  # Absent
                    bits.append(0)
                else:
                    null_mask.append(0)  # Treat as value
                    bits.append(1 if v else 0)

            # Write null mask
            packed_mask = pack_bits(null_mask, 2)
            output.extend(struct.pack('<I', len(packed_mask)))
            output.extend(packed_mask)

            # Bit-pack values
            packed = pack_bits(bits, 1)
            output.extend(struct.pack('<I', len(packed)))
            output.extend(packed)

            col_info.append('boolean')
            continue

        str_values = [NONE_MARKER if v is None else str(v) for v in values]

        if col_type == 'iso_timestamp':
            output.append(ENC_BINARY_TIMESTAMP)

            parsed = []
            format_set = set()
            raw_fallbacks = []
            ms_values = []

            for i, v in enumerate(str_values):
                ms_val, fmt = parse_iso_timestamp(v)
                if ms_val is not None:
                    fmt_key = (fmt['ms_digits'], fmt['tz'], fmt['separator'])
                    format_set.add(fmt_key)
                    parsed.append((ms_val, fmt_key))
                    ms_values.append(ms_val)
                else:
                    parsed.append((0, None))
                    ms_values.append(0)
                    raw_fallbacks.append((i, v))

            # Store format info
            format_list = sorted(format_set)
            fmt_to_id = {f: i for i, f in enumerate(format_list)}
            output.extend(struct.pack('<B', len(format_list)))
            for fmt in format_list:
                output.append(fmt[0])
                tz = fmt[1].encode('utf-8')
                output.append(len(tz))
                output.extend(tz)
                output.append(ord(fmt[2]))

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

            # Format indices - optimize for single format case
            if len(format_list) == 1:
                # Single format - no need to store per-value indices
                output.append(0xFF)  # Marker for single-format mode
            else:
                # Multiple formats - store per-value indices
                output.append(len(format_list))  # Number of formats (also signals multi-format mode)
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

        elif col_type == 'drain_template':
            output.append(ENC_DRAIN_TEMPLATE)
            templates_hint, n_vars_hint, use_masking = extra

            # Re-run Drain on full data with same masking setting
            templates, assignments, n_vars = extract_drain_templates(values, use_masking=use_masking)

            if not templates:
                # Fallback to raw
                output[-1] = ENC_RAW
                escaped = [v.replace('\\', '\\\\').replace('\n', '\\n') for v in str_values]
                all_text = '\n'.join(escaped)
                output.extend(struct.pack('<I', len(all_text.encode('utf-8'))))
                output.extend(all_text.encode('utf-8'))
                col_info.append('raw')
                continue

            # Write templates
            output.extend(struct.pack('<H', len(templates)))
            for cluster_id, template in sorted(templates.items()):
                output.extend(struct.pack('<I', cluster_id))
                tmpl_bytes = template.encode('utf-8')
                output.extend(struct.pack('<H', len(tmpl_bytes)))
                output.extend(tmpl_bytes)
                output.append(n_vars[cluster_id])

            # Write cluster assignments
            cluster_ids = [a[0] for a in assignments]
            unique_clusters = sorted(set(cluster_ids))
            cluster_to_idx = {c: i for i, c in enumerate(unique_clusters)}

            # Single-template optimization: skip cluster indices entirely
            if len(unique_clusters) == 1:
                output.extend(struct.pack('<H', 0xFFFF))  # Marker for single-template mode
                output.extend(struct.pack('<I', unique_clusters[0]))  # Just store the one cluster ID
            else:
                output.extend(struct.pack('<H', len(unique_clusters)))
                for c in unique_clusters:
                    output.extend(struct.pack('<I', c))

                if len(unique_clusters) <= 256:
                    output.append(1)
                    output.extend(bytes(cluster_to_idx[c] for c in cluster_ids))
                else:
                    output.append(0)
                    indices = '\n'.join(str(cluster_to_idx[c]) for c in cluster_ids)
                    output.extend(struct.pack('<I', len(indices.encode('utf-8'))))
                    output.extend(indices.encode('utf-8'))

            # Group variables by position across all templates
            max_vars = max(n_vars.values()) if n_vars else 0
            var_encodings = []

            for var_idx in range(max_vars):
                var_values = []
                for cluster_id, vars_list in assignments:
                    if var_idx < len(vars_list):
                        var_values.append(vars_list[var_idx])
                    else:
                        var_values.append('')

                enc = encode_variable_column(output, var_values, n_lines)
                var_encodings.append(enc)

            col_info.append(f'drain-template({len(templates)}t,{max_vars}v:{",".join(var_encodings)})')

        elif col_type == 'prefix_id':
            output.append(ENC_PREFIX_DELTA)

            parsed = []
            prefix_val = None
            width_set = set()
            for v in str_values:
                m = PREFIX_ID_RE.match(v)
                if m:
                    prefix, num_str = m.groups()
                    if prefix_val is None:
                        prefix_val = prefix
                    width_set.add(len(num_str))
                    parsed.append((int(num_str), len(num_str), None))
                else:
                    parsed.append((None, 0, v))

            prefix_bytes = prefix_val.encode('utf-8') if prefix_val else b''
            output.extend(struct.pack('<B', len(prefix_bytes)))
            output.extend(prefix_bytes)

            width_list = sorted(width_set)
            width_to_id = {w: i for i, w in enumerate(width_list)}
            output.extend(struct.pack('<B', len(width_list)))
            for w in width_list:
                output.append(w)

            deltas = []
            width_indices = []
            prev = 0
            for num, width, orig in parsed:
                if num is not None:
                    deltas.append(str(num - prev))
                    prev = num
                    width_indices.append(str(width_to_id[width]))
                else:
                    escaped = orig.replace('\\', '\\\\').replace('\n', '\\n')
                    deltas.append(f"R{escaped}")
                    width_indices.append("0")

            delta_text = '\n'.join(deltas)
            output.extend(struct.pack('<I', len(delta_text.encode('utf-8'))))
            output.extend(delta_text.encode('utf-8'))

            width_text = '\n'.join(width_indices)
            output.extend(struct.pack('<I', len(width_text.encode('utf-8'))))
            output.extend(width_text.encode('utf-8'))

            col_info.append('prefix-id-delta')

        elif col_type == 'prefix_binary':
            prefix_val = None
            nums = []
            widths = []
            raw_fallbacks = []

            for i, v in enumerate(str_values):
                m = PREFIX_ID_RE.match(v)
                if m:
                    prefix, num_str = m.groups()
                    if prefix_val is None:
                        prefix_val = prefix
                    nums.append(int(num_str))
                    widths.append(len(num_str))
                else:
                    nums.append(0)
                    widths.append(0)
                    raw_fallbacks.append((i, v))

            prefix_bytes = prefix_val.encode('utf-8') if prefix_val else b''

            max_val = max(nums) if nums else 0

            # Calculate costs for fixed-width vs bit-packed encoding
            if max_val <= 0xFFFF:
                byte_width = 2
            elif max_val <= 0xFFFFFF:
                byte_width = 3
            elif max_val <= 0xFFFFFFFF:
                byte_width = 4
            else:
                byte_width = 8

            bits_needed = max_val.bit_length() if max_val > 0 else 1
            fixed_cost = byte_width * n_lines
            bitpack_cost = (bits_needed * n_lines + 7) // 8 + 5

            # Use bit-packing if it saves bytes
            use_bitpack = (bits_needed < byte_width * 8) and (bitpack_cost < fixed_cost)

            if use_bitpack:
                output.append(ENC_BITPACK_PREFIX)
                output.extend(struct.pack('<B', len(prefix_bytes)))
                output.extend(prefix_bytes)
                output.append(bits_needed)

                packed = pack_bits(nums, bits_needed)
                output.extend(struct.pack('<I', len(packed)))
                output.extend(packed)
            else:
                output.append(ENC_PREFIX_BINARY)
                output.extend(struct.pack('<B', len(prefix_bytes)))
                output.extend(prefix_bytes)

                output.append(byte_width)
                if byte_width == 2:
                    binary_nums = b''.join(struct.pack('<H', n) for n in nums)
                elif byte_width == 3:
                    binary_nums = b''.join(struct.pack('<I', n)[:3] for n in nums)
                elif byte_width == 4:
                    binary_nums = b''.join(struct.pack('<I', n) for n in nums)
                else:
                    binary_nums = b''.join(struct.pack('<Q', n) for n in nums)
                output.extend(struct.pack('<I', len(binary_nums)))
                output.extend(binary_nums)

            # Width encoding - optimize for constant width case
            width_set = sorted(set(w for w in widths if w > 0))
            if len(width_set) == 1:
                # Constant width - just store the single width value
                output.extend(struct.pack('<B', 0x80 | width_set[0]))  # High bit = constant width mode
            else:
                # Variable widths - store width table and per-value indices
                width_to_id = {w: i for i, w in enumerate(width_set)}
                output.extend(struct.pack('<B', len(width_set)))
                for w in width_set:
                    output.append(w)
                output.extend(bytes(width_to_id.get(w, 0) for w in widths))

            output.extend(struct.pack('<H', len(raw_fallbacks)))
            for idx, val in raw_fallbacks:
                output.extend(struct.pack('<I', idx))
                val_bytes = val.encode('utf-8')
                output.extend(struct.pack('<H', len(val_bytes)))
                output.extend(val_bytes)

            if use_bitpack:
                col_info.append(f'prefix-bitpack{bits_needed}b')
            else:
                col_info.append('prefix-binary')

        elif col_type == 'integer':
            nums = []
            raw_fallbacks = []  # (index, value) for non-integer entries
            for i, v in enumerate(values):
                if isinstance(v, int):
                    nums.append(v)
                elif v is not None and SAFE_INT_RE.match(str(v)):
                    nums.append(int(v))
                else:
                    nums.append(0)  # placeholder
                    raw_fallbacks.append((i, '' if v is None else str(v)))

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
            bitpack_cost = (bits_needed * n_lines + 7) // 8 + 5  # +5 for metadata (bits_needed byte + length)

            # Dictionary cost: dict_overhead + index_width * n_lines
            dict_overhead = sum(len(str(v)) + 2 for v in unique)  # length-prefixed strings
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
                          and bits_needed < binary_width * 8)  # Only if we actually save bits

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

                # Determine byte width based on range (already calculated above)
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
                for v in values:
                    if isinstance(v, int):
                        deltas.append(str(v - prev))
                        prev = v
                    elif v is not None and SAFE_INT_RE.match(str(v)):
                        n = int(v)
                        deltas.append(str(n - prev))
                        prev = n
                    else:
                        s = '' if v is None else str(v)
                        escaped = s.replace('\\', '\\\\').replace('\n', '\\n')
                        deltas.append(f"R{escaped}")

                all_text = '\n'.join(deltas)
                output.extend(struct.pack('<I', len(all_text.encode('utf-8'))))
                output.extend(all_text.encode('utf-8'))
                col_info.append('integer-delta')
            else:
                # Low cardinality - use dictionary for integers
                output.append(ENC_DICTIONARY_INT)
                freq = Counter(str_values)
                sorted_vals = [v for v, _ in freq.most_common()]
                val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                output.extend(struct.pack('<I', len(sorted_vals)))
                for v in sorted_vals:
                    vb = v.encode('utf-8')
                    output.extend(struct.pack('<I', len(vb)))  # 4 bytes for consistency
                    output.extend(vb)

                if len(sorted_vals) <= 256:
                    output.append(1)  # 1-byte indices
                    output.extend(bytes(val_to_id[v] for v in str_values))
                elif len(sorted_vals) <= 65536:
                    output.append(2)  # 2-byte indices
                    output.extend(b''.join(struct.pack('<H', val_to_id[v]) for v in str_values))
                else:
                    output.append(4)  # 4-byte indices
                    output.extend(b''.join(struct.pack('<I', val_to_id[v]) for v in str_values))
                col_info.append('integer-dict')

        elif col_type == 'string_integer':
            # String values that look like integers - encode as integers but mark for string decode
            nums = []
            raw_fallbacks = []
            for i, v in enumerate(values):
                if v is not None and SAFE_INT_RE.match(str(v)):
                    nums.append(int(v))
                else:
                    nums.append(0)
                    raw_fallbacks.append((i, '' if v is None else str(v)))

            output.append(ENC_STRING_INT)

            # Use delta encoding (most efficient for these account-id style values)
            deltas = []
            prev = 0
            for n in nums:
                deltas.append(str(n - prev))
                prev = n

            all_text = '\n'.join(deltas)
            output.extend(struct.pack('<I', len(all_text.encode('utf-8'))))
            output.extend(all_text.encode('utf-8'))

            # Write fallbacks (use 4-byte count)
            output.extend(struct.pack('<I', len(raw_fallbacks)))
            for idx, val in raw_fallbacks:
                output.extend(struct.pack('<I', idx))
                val_bytes = val.encode('utf-8')
                output.extend(struct.pack('<H', len(val_bytes)))
                output.extend(val_bytes)

            col_info.append('string-int-delta')

        elif col_type == 'uuid_like':
            # UUID-like strings (hex with dashes) - encode as binary
            # Use encode_variable_column which handles UUID-like encoding
            enc = encode_variable_column(output, str_values, n_lines)
            col_info.append(enc)

        elif col_type == 'hex_binary':
            # Pure hex strings - encode as binary bytes
            enc = encode_variable_column(output, str_values, n_lines)
            col_info.append(enc)

        else:
            # String - dictionary or raw
            unique = set(str_values)
            if len(unique) < n_lines * 0.3:
                freq = Counter(str_values)
                sorted_vals = [v for v, _ in freq.most_common()]
                val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                # Use bit-packing for very low cardinality (2-16 values)
                if 2 <= len(sorted_vals) <= 16:
                    output.append(ENC_BITPACK_DICT)

                    # Determine bits per index
                    if len(sorted_vals) <= 2:
                        bits_per = 1
                    elif len(sorted_vals) <= 4:
                        bits_per = 2
                    elif len(sorted_vals) <= 8:
                        bits_per = 3
                    else:
                        bits_per = 4

                    # Write dictionary
                    output.append(len(sorted_vals))
                    for v in sorted_vals:
                        vb = v.encode('utf-8', errors='replace')
                        output.extend(struct.pack('<H', len(vb)))
                        output.extend(vb)

                    # Write bits per value
                    output.append(bits_per)

                    # Pack indices into bytes
                    indices = [val_to_id[v] for v in str_values]
                    packed = bytearray()
                    current_byte = 0
                    bits_used = 0

                    for idx in indices:
                        current_byte |= (idx << bits_used)
                        bits_used += bits_per
                        while bits_used >= 8:
                            packed.append(current_byte & 0xFF)
                            current_byte >>= 8
                            bits_used -= 8

                    if bits_used > 0:
                        packed.append(current_byte & 0xFF)

                    output.extend(struct.pack('<I', len(packed)))
                    output.extend(packed)
                    col_info.append(f'bitpack-dict({len(sorted_vals)}@{bits_per}b)')
                else:
                    output.append(ENC_DICTIONARY)
                    output.extend(struct.pack('<I', len(sorted_vals)))
                    for v in sorted_vals:
                        vb = v.encode('utf-8', errors='replace')
                        output.extend(struct.pack('<I', len(vb)))  # 4 bytes for large strings
                        output.extend(vb)

                    if len(sorted_vals) <= 256:
                        output.append(1)  # 1-byte indices
                        output.extend(bytes(val_to_id[v] for v in str_values))
                    elif len(sorted_vals) <= 65536:
                        output.append(2)  # 2-byte indices
                        output.extend(b''.join(struct.pack('<H', val_to_id[v]) for v in str_values))
                    else:
                        output.append(4)  # 4-byte indices
                        output.extend(b''.join(struct.pack('<I', val_to_id[v]) for v in str_values))
                    col_info.append('dictionary')
            else:
                output.append(ENC_RAW)
                escaped = [v.replace('\\', '\\\\').replace('\n', '\\n') for v in str_values]
                all_text = '\n'.join(escaped)
                output.extend(struct.pack('<I', len(all_text.encode('utf-8'))))
                output.extend(all_text.encode('utf-8'))
                col_info.append('raw')

    return bytes(output), col_info


def decode_variable_column(data, pos, n_lines):
    """Decode a variable column (supports nested Drain templates)"""
    enc_type = data[pos]
    pos += 1

    if enc_type == ENC_DICTIONARY:
        dict_len = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
        dictionary = []
        for _ in range(dict_len):
            val_len = struct.unpack('<I', data[pos:pos+4])[0]  # 4 bytes (matches encoder)
            pos += 4
            dictionary.append(data[pos:pos+val_len].decode('utf-8'))
            pos += val_len

        idx_mode = data[pos]
        pos += 1

        if idx_mode == 1:
            indices = list(data[pos:pos+n_lines])
            pos += n_lines
        else:
            idx_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            idx_text = data[pos:pos+idx_len].decode('utf-8')
            pos += idx_len
            indices = [int(x) for x in idx_text.split('\n')]

        return [dictionary[i] for i in indices], pos

    elif enc_type == ENC_PREFIX_BINARY:
        byte_width = data[pos]
        pos += 1

        binary_len = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
        binary_data = data[pos:pos+binary_len]
        pos += binary_len

        if byte_width == 4:
            nums = [struct.unpack('<i', binary_data[i:i+4])[0] for i in range(0, len(binary_data), 4)]
        else:
            nums = [struct.unpack('<q', binary_data[i:i+8])[0] for i in range(0, len(binary_data), 8)]

        return [str(n) for n in nums], pos

    elif enc_type == ENC_PATH_COLUMNAR:
        # Delimiter-based columnar encoding for path-like strings
        has_leading_slash = data[pos]
        pos += 1
        max_segments = data[pos]
        pos += 1

        # Read each segment column
        segment_columns = []
        for _ in range(max_segments):
            seg_type = data[pos]
            pos += 1

            if seg_type == 3:  # constant segment - single value for all rows
                val_len = data[pos]
                pos += 1
                const_val = data[pos:pos+val_len].decode('utf-8')
                pos += val_len
                segment_columns.append([const_val] * n_lines)
            elif seg_type == 1:  # binary 4-byte encoding
                binary_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                binary_data = data[pos:pos+binary_len]
                pos += binary_len
                nums = [struct.unpack('<I', binary_data[i:i+4])[0] for i in range(0, len(binary_data), 4)]
                segment_columns.append([str(n) for n in nums])
            elif seg_type == 2:  # binary 2-byte encoding
                binary_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                binary_data = data[pos:pos+binary_len]
                pos += binary_len
                nums = [struct.unpack('<H', binary_data[i:i+2])[0] for i in range(0, len(binary_data), 2)]
                segment_columns.append([str(n) for n in nums])
            elif seg_type == 5:  # bit-packed numeric
                bits_per = data[pos]
                pos += 1

                packed_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                packed = data[pos:pos+packed_len]
                pos += packed_len

                nums = unpack_bits(packed, n_lines, bits_per)
                segment_columns.append([str(n) for n in nums])
            elif seg_type == 4:  # bit-packed dictionary
                dict_len = data[pos]
                pos += 1
                dictionary = []
                for _ in range(dict_len):
                    val_len = data[pos]
                    pos += 1
                    dictionary.append(data[pos:pos+val_len].decode('utf-8'))
                    pos += val_len

                bits_per = data[pos]
                pos += 1

                packed_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                packed = data[pos:pos+packed_len]
                pos += packed_len

                # Unpack indices
                indices = []
                mask = (1 << bits_per) - 1
                bit_pos = 0
                byte_idx = 0
                current_bits = packed[0] if packed else 0

                for _ in range(n_lines):
                    if bit_pos + bits_per <= 8:
                        idx = (current_bits >> bit_pos) & mask
                        bit_pos += bits_per
                    else:
                        bits_from_current = 8 - bit_pos
                        idx = (current_bits >> bit_pos) & ((1 << bits_from_current) - 1)
                        byte_idx += 1
                        if byte_idx < len(packed):
                            current_bits = packed[byte_idx]
                            bits_needed = bits_per - bits_from_current
                            idx |= (current_bits & ((1 << bits_needed) - 1)) << bits_from_current
                            bit_pos = bits_needed
                        else:
                            bit_pos = 0

                    if bit_pos >= 8:
                        bit_pos -= 8
                        byte_idx += 1
                        if byte_idx < len(packed):
                            current_bits = packed[byte_idx]

                    indices.append(idx)

                segment_columns.append([dictionary[i] for i in indices])
            else:  # dict encoding (seg_type == 0)
                dict_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                dictionary = []
                for _ in range(dict_len):
                    val_len = data[pos]
                    pos += 1
                    dictionary.append(data[pos:pos+val_len].decode('utf-8'))
                    pos += val_len

                idx_mode = data[pos]
                pos += 1

                if idx_mode == 1:  # byte indices
                    indices = list(data[pos:pos+n_lines])
                    pos += n_lines
                else:  # text indices
                    idx_len = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4
                    idx_text = data[pos:pos+idx_len].decode('utf-8')
                    pos += idx_len
                    indices = [int(x) for x in idx_text.split('\n')]

                segment_columns.append([dictionary[i] for i in indices])

        # Reconstruct paths
        values = []
        for i in range(n_lines):
            segments = [seg_col[i] for seg_col in segment_columns]
            # Remove trailing empty segments
            while segments and segments[-1] == '':
                segments.pop()
            # Join with / and optionally add leading /
            if segments:
                path = '/'.join(segments)
                if has_leading_slash:
                    path = '/' + path
                values.append(path)
            else:
                values.append('')

        return values, pos

    elif enc_type == ENC_DRAIN_TEMPLATE:
        # Nested Drain template (recursive)
        n_templates = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2

        templates = {}
        n_vars = {}
        for _ in range(n_templates):
            cluster_id = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            tmpl_len = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            template = data[pos:pos+tmpl_len].decode('utf-8')
            pos += tmpl_len
            nv = data[pos]
            pos += 1
            templates[cluster_id] = template
            n_vars[cluster_id] = nv

        # Read cluster assignments
        n_unique_clusters = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2
        cluster_list = []
        for _ in range(n_unique_clusters):
            cluster_list.append(struct.unpack('<I', data[pos:pos+4])[0])
            pos += 4

        idx_mode = data[pos]
        pos += 1

        if idx_mode == 1:
            cluster_indices = list(data[pos:pos+n_lines])
            pos += n_lines
        else:
            idx_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            idx_text = data[pos:pos+idx_len].decode('utf-8')
            pos += idx_len
            cluster_indices = [int(x) for x in idx_text.split('\n')]

        cluster_ids = [cluster_list[i] for i in cluster_indices]

        # Read sub-variable columns recursively
        max_vars = max(n_vars.values()) if n_vars else 0
        var_columns = []
        for _ in range(max_vars):
            var_values, pos = decode_variable_column(data, pos, n_lines)
            var_columns.append(var_values)

        # Reconstruct values
        values = []
        for i in range(n_lines):
            cluster_id = cluster_ids[i]
            template = templates.get(cluster_id, '')
            nv = n_vars.get(cluster_id, 0)

            result = template
            for var_idx in range(nv):
                if var_idx < len(var_columns):
                    result = result.replace('<*>', var_columns[var_idx][i], 1)

            values.append(result)

        return values, pos

    elif enc_type == ENC_UUID_BINARY:
        # UUID binary encoding: 16 bytes -> 36 char UUID string
        n_values = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
        values = []
        for _ in range(n_values):
            uuid_bytes = data[pos:pos+16]
            pos += 16
            hex_str = uuid_bytes.hex()
            # Format as UUID: 8-4-4-4-12
            uuid_str = f'{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}'
            values.append(uuid_str)
        return values, pos

    elif enc_type == ENC_HEX_BINARY:
        # Hex binary encoding: n bytes -> 2n char hex string
        n_values = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
        hex_len = data[pos]  # Original hex string length
        pos += 1
        byte_len = hex_len // 2
        values = []
        for _ in range(n_values):
            hex_bytes = data[pos:pos+byte_len]
            pos += byte_len
            values.append(hex_bytes.hex().upper())  # Preserve uppercase
        return values, pos

    elif enc_type == ENC_UUID_LIKE:
        # UUID-like binary encoding: variable length hex with dashes
        n_values = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4

        # Read number of patterns
        n_patterns = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2

        # Initialize result array
        values = [None] * n_values

        # Read each pattern group
        for _ in range(n_patterns):
            # Read dash pattern
            pattern_len = data[pos]
            pos += 1
            dash_positions = list(data[pos:pos+pattern_len])
            pos += pattern_len

            # Read count
            count = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4

            # Read items
            for _ in range(count):
                idx = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                hex_byte_len = data[pos]
                pos += 1
                orig_hex_len = data[pos]  # Original hex length (before padding)
                pos += 1
                hex_bytes = data[pos:pos+hex_byte_len]
                pos += hex_byte_len

                # Convert to hex string
                hex_str = hex_bytes.hex()

                # Remove leading zero if we padded it (odd length original)
                if len(hex_str) > orig_hex_len:
                    hex_str = hex_str[1:]  # Remove the leading '0' we added

                # Insert dashes at stored positions
                result = list(hex_str)
                for dp in sorted(dash_positions, reverse=True):
                    # Adjust position for hex-only string
                    # dp is the original position in the string with dashes
                    # Count how many dashes come before this position
                    dashes_before = sum(1 for d in dash_positions if d < dp)
                    hex_pos = dp - dashes_before
                    if hex_pos <= len(result):
                        result.insert(hex_pos, '-')

                values[idx] = ''.join(result)

        return values, pos

    else:  # ENC_RAW
        text_len = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
        text = data[pos:pos+text_len].decode('utf-8')
        pos += text_len
        values = text.split('\n')
        return [v.replace('\\n', '\n').replace('\\\\', '\\') for v in values], pos


def decode_from_bytes(data):
    """Decode bytes back to JSON lines"""
    pos = 0

    magic = data[pos:pos+4]
    pos += 4
    if magic != b'JSN3':
        raise ValueError(f"Invalid magic: {magic}, expected JSN3")

    # Read separator style
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

    # Read key orders (for preserving per-line key order)
    n_unique_orders = struct.unpack('<H', data[pos:pos+2])[0]
    pos += 2

    key_orders = None
    if n_unique_orders > 0:
        unique_orders = []
        for _ in range(n_unique_orders):
            order_len = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
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

    columns = {}
    for key in keys:
        enc_type = data[pos]
        pos += 1

        if enc_type == ENC_BINARY_TIMESTAMP:
            # Read format info
            n_fmt = data[pos]
            pos += 1
            format_list = []
            for _ in range(n_fmt):
                ms_digits = data[pos]
                pos += 1
                tz_len = data[pos]
                pos += 1
                tz = data[pos:pos+tz_len].decode('utf-8')
                pos += tz_len
                sep = chr(data[pos])
                pos += 1
                format_list.append({'ms_digits': ms_digits, 'tz': tz, 'separator': sep})

            # Read min timestamp (frame of reference)
            min_ms = struct.unpack('<Q', data[pos:pos+8])[0]
            pos += 8

            # Read byte width and binary data
            byte_width = data[pos]
            pos += 1

            binary_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            binary_data = data[pos:pos+binary_len]
            pos += binary_len

            if byte_width == 2:
                relative_values = [struct.unpack('<H', binary_data[i:i+2])[0] for i in range(0, len(binary_data), 2)]
            elif byte_width == 4:
                relative_values = [struct.unpack('<I', binary_data[i:i+4])[0] for i in range(0, len(binary_data), 4)]
            else:
                relative_values = [struct.unpack('<Q', binary_data[i:i+8])[0] for i in range(0, len(binary_data), 8)]

            # Read format indices - check for single-format mode
            fmt_mode = data[pos]
            pos += 1

            if fmt_mode == 0xFF:
                # Single format mode - all entries use format 0
                fmt_indices = [0] * len(relative_values)
            else:
                # Multi-format mode - read per-value indices
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
                    values.append(fallbacks[i])
                else:
                    ms_val = min_ms + relative
                    fmt = format_list[fmt_indices[i]] if fmt_indices[i] < len(format_list) else {}
                    values.append(reconstruct_iso_timestamp(ms_val, fmt))
            columns[key] = values

        elif enc_type == ENC_DELTA_TIMESTAMP:
            n_fmt = data[pos]
            pos += 1
            format_list = []
            for _ in range(n_fmt):
                ms_digits = data[pos]
                pos += 1
                tz_len = data[pos]
                pos += 1
                tz = data[pos:pos+tz_len].decode('utf-8')
                pos += tz_len
                sep = chr(data[pos])
                pos += 1
                format_list.append({'ms_digits': ms_digits, 'tz': tz, 'separator': sep})

            delta_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            delta_text = data[pos:pos+delta_len].decode('utf-8')
            pos += delta_len
            deltas = delta_text.split('\n')

            fmt_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            fmt_text = data[pos:pos+fmt_len].decode('utf-8')
            pos += fmt_len
            fmt_indices = [int(x) for x in fmt_text.split('\n')]

            values = []
            current = 0
            for i, d in enumerate(deltas):
                if d.startswith('R'):
                    raw = d[1:].replace('\\n', '\n').replace('\\\\', '\\')
                    values.append(raw)
                else:
                    current += int(d)
                    fmt = format_list[fmt_indices[i]] if fmt_indices[i] < len(format_list) else {}
                    values.append(reconstruct_iso_timestamp(current, fmt))
            columns[key] = values

        elif enc_type == ENC_DRAIN_TEMPLATE:
            # Read templates
            n_templates = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2

            templates = {}
            n_vars = {}
            for _ in range(n_templates):
                cluster_id = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                tmpl_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                template = data[pos:pos+tmpl_len].decode('utf-8')
                pos += tmpl_len
                nv = data[pos]
                pos += 1
                templates[cluster_id] = template
                n_vars[cluster_id] = nv

            # Read cluster assignments
            n_unique_clusters = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2

            # Check for single-template mode (0xFFFF marker)
            if n_unique_clusters == 0xFFFF:
                # Single-template mode - all rows use the same cluster
                single_cluster_id = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                cluster_ids = [single_cluster_id] * n_lines
            else:
                cluster_list = []
                for _ in range(n_unique_clusters):
                    cluster_list.append(struct.unpack('<I', data[pos:pos+4])[0])
                    pos += 4

                idx_mode = data[pos]
                pos += 1

                if idx_mode == 1:
                    cluster_indices = list(data[pos:pos+n_lines])
                    pos += n_lines
                else:
                    idx_len = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4
                    idx_text = data[pos:pos+idx_len].decode('utf-8')
                    pos += idx_len
                    cluster_indices = [int(x) for x in idx_text.split('\n')]

                cluster_ids = [cluster_list[i] for i in cluster_indices]

            # Read variable columns
            max_vars = max(n_vars.values()) if n_vars else 0
            var_columns = []
            for _ in range(max_vars):
                var_values, pos = decode_variable_column(data, pos, n_lines)
                var_columns.append(var_values)

            # Reconstruct values
            values = []
            for i in range(n_lines):
                cluster_id = cluster_ids[i]
                template = templates.get(cluster_id, '')
                nv = n_vars.get(cluster_id, 0)

                # Replace <*> placeholders with variables
                result = template
                for var_idx in range(nv):
                    if var_idx < len(var_columns):
                        result = result.replace('<*>', var_columns[var_idx][i], 1)

                values.append(result)

            columns[key] = values

        elif enc_type == ENC_PREFIX_DELTA:
            prefix_len = data[pos]
            pos += 1
            prefix = data[pos:pos+prefix_len].decode('utf-8')
            pos += prefix_len

            n_widths = data[pos]
            pos += 1
            width_list = []
            for _ in range(n_widths):
                width_list.append(data[pos])
                pos += 1

            delta_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            delta_text = data[pos:pos+delta_len].decode('utf-8')
            pos += delta_len
            deltas = delta_text.split('\n')

            width_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            width_text = data[pos:pos+width_len].decode('utf-8')
            pos += width_len
            width_indices = [int(x) for x in width_text.split('\n')]

            values = []
            current = 0
            for i, d in enumerate(deltas):
                if d.startswith('R'):
                    raw = d[1:].replace('\\n', '\n').replace('\\\\', '\\')
                    values.append(raw)
                else:
                    current += int(d)
                    width = width_list[width_indices[i]] if width_indices[i] < len(width_list) else 0
                    if width > 0:
                        values.append(f"{prefix}-{current:0{width}d}")
                    else:
                        values.append(f"{prefix}-{current}")
            columns[key] = values

        elif enc_type == ENC_PREFIX_BINARY:
            prefix_len = data[pos]
            pos += 1
            prefix = data[pos:pos+prefix_len].decode('utf-8')
            pos += prefix_len

            byte_width = data[pos]
            pos += 1

            binary_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            binary_nums = data[pos:pos+binary_len]
            pos += binary_len

            if byte_width == 2:
                nums = [struct.unpack('<H', binary_nums[i:i+2])[0] for i in range(0, len(binary_nums), 2)]
            elif byte_width == 3:
                # 3-byte encoding: pad with 0 to make 4 bytes, then unpack as uint32
                nums = [struct.unpack('<I', binary_nums[i:i+3] + b'\x00')[0] for i in range(0, len(binary_nums), 3)]
            elif byte_width == 4:
                nums = [struct.unpack('<I', binary_nums[i:i+4])[0] for i in range(0, len(binary_nums), 4)]
            else:
                nums = [struct.unpack('<Q', binary_nums[i:i+8])[0] for i in range(0, len(binary_nums), 8)]

            # Width decoding - check for constant width mode (high bit set)
            width_byte = data[pos]
            pos += 1

            if width_byte & 0x80:
                # Constant width mode
                constant_width = width_byte & 0x7F
                width_list = [constant_width]
                width_indices = [0] * len(nums)
            else:
                # Variable width mode
                n_widths = width_byte
                width_list = []
                for _ in range(n_widths):
                    width_list.append(data[pos])
                    pos += 1
                width_indices = list(data[pos:pos+len(nums)])
                pos += len(nums)

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
                    values.append(fallbacks[i])
                else:
                    width = width_list[width_indices[i]] if width_indices[i] < len(width_list) else 0
                    if width > 0:
                        values.append(f"{prefix}-{num:0{width}d}")
                    else:
                        values.append(f"{prefix}-{num}")
            columns[key] = values

        elif enc_type == ENC_BITPACK_PREFIX:
            prefix_len = data[pos]
            pos += 1
            prefix = data[pos:pos+prefix_len].decode('utf-8')
            pos += prefix_len

            bits_per_value = data[pos]
            pos += 1

            packed_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            packed_data = data[pos:pos+packed_len]
            pos += packed_len

            nums = unpack_bits(packed_data, n_lines, bits_per_value)

            # Width decoding - check for constant width mode (high bit set)
            width_byte = data[pos]
            pos += 1

            if width_byte & 0x80:
                # Constant width mode
                constant_width = width_byte & 0x7F
                width_list = [constant_width]
                width_indices = [0] * len(nums)
            else:
                # Variable width mode
                n_widths = width_byte
                width_list = []
                for _ in range(n_widths):
                    width_list.append(data[pos])
                    pos += 1
                width_indices = list(data[pos:pos+len(nums)])
                pos += len(nums)

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
                    values.append(fallbacks[i])
                else:
                    width = width_list[width_indices[i]] if width_indices[i] < len(width_list) else 0
                    if width > 0:
                        values.append(f"{prefix}-{num:0{width}d}")
                    else:
                        values.append(f"{prefix}-{num}")
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
                    values.append(fallbacks[i])
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
                    values.append(fallbacks[i])
                else:
                    values.append(num)
            columns[key] = values

        elif enc_type == ENC_DELTA_INTEGER:
            text_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            text = data[pos:pos+text_len].decode('utf-8')
            pos += text_len

            entries = text.split('\n')
            values = []
            current = 0
            for e in entries:
                if e.startswith('R'):
                    raw = e[1:].replace('\\n', '\n').replace('\\\\', '\\')
                    values.append(raw if raw else None)
                elif e == '':
                    values.append(None)
                else:
                    current += int(e)
                    values.append(current)
            columns[key] = values

        elif enc_type == ENC_STRING_INT:
            # String integers - decode as integers but convert to strings
            text_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            text = data[pos:pos+text_len].decode('utf-8')
            pos += text_len

            entries = text.split('\n')
            values = []
            current = 0
            for e in entries:
                current += int(e)
                values.append(str(current))  # Convert to string!

            # Read fallbacks (4-byte count)
            n_fallbacks = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            for _ in range(n_fallbacks):
                idx = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                val_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                val = data[pos:pos+val_len].decode('utf-8')
                pos += val_len
                values[idx] = val if val else None

            columns[key] = values

        elif enc_type == ENC_BITPACK_DICT:
            # Bit-packed dictionary indices for very low cardinality
            dict_len = data[pos]
            pos += 1
            dictionary = []
            for _ in range(dict_len):
                val_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                dictionary.append(data[pos:pos+val_len].decode('utf-8', errors='replace'))
                pos += val_len

            bits_per = data[pos]
            pos += 1

            packed_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            packed = data[pos:pos+packed_len]
            pos += packed_len

            # Unpack indices
            indices = []
            mask = (1 << bits_per) - 1
            bit_pos = 0
            byte_idx = 0
            current_bits = packed[0] if packed else 0

            for _ in range(n_lines):
                # Extract bits_per bits starting at bit_pos
                if bit_pos + bits_per <= 8:
                    idx = (current_bits >> bit_pos) & mask
                    bit_pos += bits_per
                else:
                    # Need bits from current and next byte
                    bits_from_current = 8 - bit_pos
                    idx = (current_bits >> bit_pos) & ((1 << bits_from_current) - 1)
                    byte_idx += 1
                    if byte_idx < len(packed):
                        current_bits = packed[byte_idx]
                        bits_needed = bits_per - bits_from_current
                        idx |= (current_bits & ((1 << bits_needed) - 1)) << bits_from_current
                        bit_pos = bits_needed
                    else:
                        bit_pos = 0

                if bit_pos >= 8:
                    bit_pos -= 8
                    byte_idx += 1
                    if byte_idx < len(packed):
                        current_bits = packed[byte_idx]

                indices.append(idx)

            values = [dictionary[i] for i in indices]
            columns[key] = values

        elif enc_type == ENC_DICTIONARY or enc_type == ENC_DICTIONARY_INT:
            dict_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            dictionary = []
            for _ in range(dict_len):
                val_len = struct.unpack('<I', data[pos:pos+4])[0]  # 4 bytes for large strings
                pos += 4
                val_str = data[pos:pos+val_len].decode('utf-8', errors='replace')
                # Convert to int if this is an integer dictionary
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
                # 1-byte indices
                indices = list(data[pos:pos+n_lines])
                pos += n_lines
            elif idx_mode == 2:
                # 2-byte indices
                idx_data = data[pos:pos+n_lines*2]
                indices = [struct.unpack('<H', idx_data[i:i+2])[0] for i in range(0, len(idx_data), 2)]
                pos += n_lines * 2
            elif idx_mode == 4:
                # 4-byte indices
                idx_data = data[pos:pos+n_lines*4]
                indices = [struct.unpack('<I', idx_data[i:i+4])[0] for i in range(0, len(idx_data), 4)]
                pos += n_lines * 4
            else:
                # Legacy text mode (idx_mode == 0)
                idx_len = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
                idx_text = data[pos:pos+idx_len].decode('utf-8')
                pos += idx_len
                indices = [int(x) for x in idx_text.split('\n')]

            values = [dictionary[i] for i in indices]
            columns[key] = values

        elif enc_type == ENC_BOOLEAN:
            # Read null mask
            mask_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            packed_mask = data[pos:pos+mask_len]
            pos += mask_len
            null_mask = unpack_bits(packed_mask, n_lines, 2)

            # Bit-packed booleans
            packed_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            packed = data[pos:pos+packed_len]
            pos += packed_len

            bits = unpack_bits(packed, n_lines, 1)
            values = []
            for i, b in enumerate(bits):
                mask_val = null_mask[i] if i < len(null_mask) else 0
                if mask_val == 1:  # Null
                    values.append(None)
                elif mask_val == 2:  # Absent
                    values.append('_ABSENT_')
                else:  # Has value
                    values.append(bool(b))
            columns[key] = values

        elif enc_type == ENC_NESTED_OBJECT:
            # Read null mask
            mask_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            packed_mask = data[pos:pos+mask_len]
            pos += mask_len
            null_mask = unpack_bits(packed_mask, n_lines, 2)

            # Recursively decode nested object
            nested_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            nested_data = data[pos:pos+nested_len]
            pos += nested_len

            # Recursively decode - this returns JSON lines, but we need objects
            nested_lines = decode_from_bytes(nested_data)

            # Parse each line back to dict, applying null mask
            nested_objs = []
            for i, line in enumerate(nested_lines):
                mask_val = null_mask[i] if i < len(null_mask) else 0
                if mask_val == 1:  # Null
                    nested_objs.append(None)
                elif mask_val == 2:  # Absent
                    nested_objs.append('_ABSENT_')
                else:  # Actual dict
                    try:
                        nested_objs.append(json.loads(line))
                    except json.JSONDecodeError:
                        nested_objs.append({})

            columns[key] = nested_objs

        elif enc_type == ENC_NESTED_ARRAY:
            # Decode array stored as JSON strings in dictionary
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
                idx_data = data[pos:pos+n_lines*2]
                indices = [struct.unpack('<H', idx_data[i:i+2])[0] for i in range(0, len(idx_data), 2)]
                pos += n_lines * 2
            else:
                idx_data = data[pos:pos+n_lines*4]
                indices = [struct.unpack('<I', idx_data[i:i+4])[0] for i in range(0, len(idx_data), 4)]
                pos += n_lines * 4

            # Parse JSON strings back to arrays
            NONE_MARKER = '\x00__NULL__\x00'
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

        elif enc_type in (ENC_UUID_BINARY, ENC_HEX_BINARY, ENC_UUID_LIKE):
            # Use decode_variable_column for UUID-related encodings
            values, pos = decode_variable_column(data, pos - 1, n_lines)  # pos-1 because we already read enc_type
            columns[key] = values

        else:  # ENC_RAW
            text_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            text = data[pos:pos+text_len].decode('utf-8')
            pos += text_len

            raw_values = text.split('\n')
            values = [v.replace('\\n', '\n').replace('\\\\', '\\') for v in raw_values]
            columns[key] = values

    # Special marker for None values (must match encoding)
    NONE_MARKER = '\x00__NULL__\x00'

    # Reconstruct JSON lines with correct separator style and key order
    if sep_style == 0:
        separators = (',', ':')  # compact
    else:
        separators = (', ', ': ')  # spaced

    lines = []
    for i in range(n_lines):
        # Use original key order if available, otherwise use schema order
        if key_orders is not None:
            line_keys = key_orders[i]
        else:
            line_keys = keys

        obj = {}
        for key in line_keys:
            if key not in columns:
                continue
            val = columns[key][i]
            # Handle special markers
            if val == '_ABSENT_':
                continue  # Skip absent fields
            elif val == NONE_MARKER:
                obj[key] = None  # Becomes null in JSON
            else:
                obj[key] = val

        if '_raw' in obj:
            lines.append(obj['_raw'])
        else:
            lines.append(json.dumps(obj, separators=separators, ensure_ascii=False))

    return lines


def verify_file(input_file, relaxed=False):
    with open(input_file, 'r', errors='replace') as f:
        original_lines = [l.rstrip('\n') for l in f]

    print(f"Verifying {len(original_lines)} lines...")

    start = time.time()
    keys, columns, parsed = encode_json_logs(original_lines)
    binary_data, col_info = encode_to_bytes(keys, columns, len(original_lines))
    encode_time = time.time() - start

    print(f"  Schema: {keys}")
    print(f"  Column encoding: {col_info}")

    start = time.time()
    decoded_lines = decode_from_bytes(binary_data)
    decode_time = time.time() - start

    if len(decoded_lines) != len(original_lines):
        print(f"✗ Line count mismatch: {len(decoded_lines)} vs {len(original_lines)}")
        return False, None

    errors = 0
    for i, (orig, dec) in enumerate(zip(original_lines, decoded_lines)):
        try:
            orig_obj = json.loads(orig)
            dec_obj = json.loads(dec)
            if orig_obj != dec_obj:
                errors += 1
                if errors <= 5:
                    print(f"✗ Line {i} semantic mismatch")
                    for k in orig_obj:
                        if orig_obj.get(k) != dec_obj.get(k):
                            print(f"  diff {k}: {repr(orig_obj.get(k))} vs {repr(dec_obj.get(k))}")
        except json.JSONDecodeError:
            if orig != dec:
                errors += 1

    orig_size = sum(len(l.encode('utf-8')) + 1 for l in original_lines)

    if errors == 0:
        print(f"✓ All {len(original_lines)} lines verified!")
        print(f"  Encode: {encode_time:.2f}s ({len(original_lines)/encode_time:.0f} lines/sec)")
        print(f"  Decode: {decode_time:.2f}s ({len(original_lines)/decode_time:.0f} lines/sec)")
        print(f"  Size: {len(binary_data):,} bytes ({len(binary_data)*100/orig_size:.1f}% of original)")
        return True, binary_data
    else:
        print(f"✗ {errors} lines with mismatches")
        if relaxed:
            print(f"  (relaxed mode: returning data anyway)")
            return True, binary_data
        return False, None


if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[1] != 'verify':
        print("Usage: json_codec_v3.py verify <input_file>")
        sys.exit(1)
    result = verify_file(sys.argv[2])
    sys.exit(0 if result[0] else 1)

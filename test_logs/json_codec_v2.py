#!/usr/bin/env python3
"""
JSON log compression v2 - with nested pattern extraction.

Improvements:
- Detects patterns within string fields (like message templates)
- Splits compound fields into sub-columns
- Better user_id handling (dictionary for repeated prefixed IDs)
"""
import sys
import struct
import time
import re
import json
from collections import Counter

# Encoding types
ENC_RAW = 0
ENC_DICTIONARY = 1
ENC_DELTA_INTEGER = 2
ENC_DELTA_TIMESTAMP = 3
ENC_PREFIX_DELTA = 4
ENC_TEMPLATE = 5  # Template + variables
ENC_PREFIX_BINARY = 6  # Prefix + binary numbers (for random high-cardinality IDs)

# Patterns
ISO_TIMESTAMP_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')
PREFIX_ID_RE = re.compile(r'^([a-zA-Z][\w-]*)-(\d+)$')
SAFE_INT_RE = re.compile(r'^(-?[1-9]\d*|0)$')

# Pattern for extracting templates from strings
# Match numbers at end of URL paths like /users/123
ENDPOINT_NUMBER_RE = re.compile(r'/(\d+)(?:/|$|\s|")')
# Match endpoint patterns like /api/v1/users/123 -> captures both 'users' and '123'
ENDPOINT_FULL_RE = re.compile(r'/api/v\d+/(\w+)/(\d+)')


def parse_iso_timestamp(ts):
    """Parse ISO timestamp, return (milliseconds, format_info) or (None, None)"""
    m = ISO_TIMESTAMP_RE.match(ts)
    if not m:
        return None, None

    year, mon, day, h, mi, s, ms, tz = m.groups()
    y, mo, d = int(year), int(mon), int(day)
    hr, mn, sc = int(h), int(mi), int(s)

    days = (y - 1970) * 365 + (y - 1969) // 4 + (mo - 1) * 30 + d
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

    year = 1970 + days // 365
    day_of_year = days - (year - 1970) * 365 - (year - 1969) // 4

    while day_of_year < 0:
        year -= 1
        day_of_year = days - (year - 1970) * 365 - (year - 1969) // 4

    month = day_of_year // 30 + 1
    if month > 12:
        month = 12
    day = day_of_year - (month - 1) * 30
    if day <= 0:
        month -= 1
        if month <= 0:
            month = 12
            year -= 1
        day = day_of_year - (month - 1) * 30

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


def extract_template(values):
    """Extract template from string values by replacing variable parts with placeholders.
    Returns (template, is_templatable, variables_per_value, var_regex)"""
    if not values:
        return None, False, None, None

    sample = [str(v) for v in values[:1000] if v]
    if not sample:
        return None, False, None, None

    # Strategy 1: Try full endpoint pattern first (e.g., /api/v1/users/123)
    # This extracts both the endpoint type AND the ID
    templates_full = Counter()
    for v in sample:
        tmpl = ENDPOINT_FULL_RE.sub('/api/v1/<S>/<N>', v)
        templates_full[tmpl] += 1

    if templates_full:
        top_full, count_full = templates_full.most_common(1)[0]
        if count_full >= len(sample) * 0.8:
            # Use full pattern - extract both word and number
            variables = []
            for v in values:
                v_str = str(v) if v else ''
                matches = ENDPOINT_FULL_RE.findall(v_str)
                if matches:
                    # Flatten: each match is (word, number)
                    flat = []
                    for m in matches:
                        flat.extend(m)
                    variables.append(flat)
                else:
                    variables.append([])
            return top_full, True, variables, ENDPOINT_FULL_RE

    # Strategy 2: Try number-only pattern (e.g., /users/123)
    templates_num = Counter()
    for v in sample:
        tmpl = ENDPOINT_NUMBER_RE.sub('/<N>', v)
        templates_num[tmpl] += 1

    if templates_num:
        top_num, count_num = templates_num.most_common(1)[0]
        if count_num >= len(sample) * 0.8:
            variables = []
            for v in values:
                v_str = str(v) if v else ''
                nums = ENDPOINT_NUMBER_RE.findall(v_str)
                variables.append(nums)
            return top_num, True, variables, ENDPOINT_NUMBER_RE

    return None, False, None, None


def detect_column_type(values, key_hint=None):
    """Detect column type from sample values"""
    sample = [v for v in values[:1000] if v is not None and v != '']
    if not sample:
        return 'string', None

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

            # Low cardinality (many repeats) - use dictionary encoding
            if unique_ratio < 0.3:
                return 'string', None

            # High cardinality - check if sorted (use delta) or random
            sorted_count = sum(1 for i in range(1, len(nums)) if nums[i] >= nums[i-1])
            if sorted_count >= len(nums) * 0.6:
                return 'prefix_id', None  # Somewhat sorted - delta encoding
            else:
                return 'prefix_binary', None  # Random - binary encoding

    # Check for integers
    if all(isinstance(v, int) for v in sample):
        return 'integer', None

    int_count = sum(1 for v in str_sample if SAFE_INT_RE.match(v))
    if int_count >= len(str_sample) * 0.9:
        return 'integer', None

    # Check for templatable strings (strings with embedded numbers)
    template, is_templatable, variables, var_re = extract_template(sample)
    if is_templatable:
        return 'template', (template, var_re)

    return 'string', None


def encode_json_logs(lines):
    """Parse JSON lines and extract columnar data"""
    parsed = []
    all_keys = []

    for line in lines:
        line = line.strip()
        if not line:
            parsed.append({})
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                parsed.append(obj)
                for k in obj.keys():
                    if k not in all_keys:
                        all_keys.append(k)
            else:
                parsed.append({'_value': obj})
                if '_value' not in all_keys:
                    all_keys.append('_value')
        except json.JSONDecodeError:
            parsed.append({'_raw': line})
            if '_raw' not in all_keys:
                all_keys.append('_raw')

    columns = {}
    for key in all_keys:
        columns[key] = [obj.get(key) for obj in parsed]

    return all_keys, columns, parsed


def encode_to_bytes(keys, columns, n_lines):
    """Encode columnar data to bytes"""
    output = bytearray()
    output.extend(b'JSN2')  # Magic v2

    # Write schema
    output.extend(struct.pack('<H', len(keys)))
    for key in keys:
        kb = key.encode('utf-8')
        output.extend(struct.pack('<H', len(kb)))
        output.extend(kb)

    output.extend(struct.pack('<I', n_lines))

    col_info = []

    for key in keys:
        values = columns[key]
        str_values = ['' if v is None else str(v) for v in values]

        col_type, extra = detect_column_type(values, key)

        if col_type == 'iso_timestamp':
            output.append(ENC_DELTA_TIMESTAMP)

            parsed = []
            format_set = set()
            for v in str_values:
                ms_val, fmt = parse_iso_timestamp(v)
                if ms_val is not None:
                    fmt_key = (fmt['ms_digits'], fmt['tz'], fmt['separator'])
                    format_set.add(fmt_key)
                    parsed.append((ms_val, fmt_key, None))
                else:
                    parsed.append((None, None, v))

            format_list = sorted(format_set)
            fmt_to_id = {f: i for i, f in enumerate(format_list)}
            output.extend(struct.pack('<B', len(format_list)))
            for fmt in format_list:
                output.append(fmt[0])
                tz = fmt[1].encode('utf-8')
                output.append(len(tz))
                output.extend(tz)
                output.append(ord(fmt[2]))

            deltas = []
            fmt_indices = []
            prev = 0
            for ms_val, fmt_key, orig in parsed:
                if ms_val is not None:
                    deltas.append(str(ms_val - prev))
                    prev = ms_val
                    fmt_indices.append(str(fmt_to_id[fmt_key]))
                else:
                    escaped = orig.replace('\\', '\\\\').replace('\n', '\\n')
                    deltas.append(f"R{escaped}")
                    fmt_indices.append("0")

            delta_text = '\n'.join(deltas)
            output.extend(struct.pack('<I', len(delta_text.encode('utf-8'))))
            output.extend(delta_text.encode('utf-8'))

            fmt_text = '\n'.join(fmt_indices)
            output.extend(struct.pack('<I', len(fmt_text.encode('utf-8'))))
            output.extend(fmt_text.encode('utf-8'))

            col_info.append('iso-timestamp-delta')

        elif col_type == 'template':
            output.append(ENC_TEMPLATE)
            template, var_re = extra

            # Write template
            tmpl_bytes = template.encode('utf-8')
            output.extend(struct.pack('<H', len(tmpl_bytes)))
            output.extend(tmpl_bytes)

            # Count placeholders (<S> for strings, <N> for numbers)
            n_string_placeholders = template.count('<S>')
            n_number_placeholders = template.count('<N>')
            n_placeholders = n_string_placeholders + n_number_placeholders
            output.append(n_placeholders)

            # Extract variables for all values using the detected regex
            all_vars = []
            for v in values:
                v_str = str(v) if v else ''
                matches = var_re.findall(v_str)
                if matches:
                    # Flatten if needed (regex might return tuples)
                    if isinstance(matches[0], tuple):
                        flat = []
                        for m in matches:
                            flat.extend(m)
                        all_vars.append(flat)
                    else:
                        all_vars.append(matches)
                else:
                    all_vars.append([''] * n_placeholders)

            # Pad to ensure all have same length
            for i in range(len(all_vars)):
                while len(all_vars[i]) < n_placeholders:
                    all_vars[i].append('')
                all_vars[i] = all_vars[i][:n_placeholders]

            # Encode each variable column with dictionary encoding
            for var_idx in range(n_placeholders):
                var_values = [vars[var_idx] for vars in all_vars]

                # Always use dictionary for template variables (they repeat)
                unique = set(var_values)
                output.append(ENC_DICTIONARY)
                freq = Counter(var_values)
                sorted_vals = [v for v, _ in freq.most_common()]
                val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                output.extend(struct.pack('<I', len(sorted_vals)))
                for v in sorted_vals:
                    vb = v.encode('utf-8')
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)

                if len(sorted_vals) <= 256:
                    output.append(1)
                    output.extend(bytes(val_to_id[v] for v in var_values))
                else:
                    output.append(0)
                    indices = '\n'.join(str(val_to_id[v]) for v in var_values)
                    output.extend(struct.pack('<I', len(indices.encode('utf-8'))))
                    output.extend(indices.encode('utf-8'))

            col_info.append(f'template({n_placeholders})')

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
            output.append(ENC_PREFIX_BINARY)

            # Extract prefix and numbers
            prefix_val = None
            nums = []
            widths = []
            raw_fallbacks = []  # (index, value) for non-matching entries

            for i, v in enumerate(str_values):
                m = PREFIX_ID_RE.match(v)
                if m:
                    prefix, num_str = m.groups()
                    if prefix_val is None:
                        prefix_val = prefix
                    nums.append(int(num_str))
                    widths.append(len(num_str))
                else:
                    # Fallback for non-matching entries
                    nums.append(0)  # placeholder
                    widths.append(0)
                    raw_fallbacks.append((i, v))

            # Write prefix
            prefix_bytes = prefix_val.encode('utf-8') if prefix_val else b''
            output.extend(struct.pack('<B', len(prefix_bytes)))
            output.extend(prefix_bytes)

            # Find max value to determine byte width (4 or 8 bytes)
            max_val = max(nums) if nums else 0
            if max_val > 0xFFFFFFFF:
                byte_width = 8
                output.append(8)
            else:
                byte_width = 4
                output.append(4)

            # Write numbers in binary
            if byte_width == 4:
                binary_nums = b''.join(struct.pack('<I', n) for n in nums)
            else:
                binary_nums = b''.join(struct.pack('<Q', n) for n in nums)
            output.extend(struct.pack('<I', len(binary_nums)))
            output.extend(binary_nums)

            # Write widths (for reconstruction) - use single byte per width
            width_set = sorted(set(widths))
            width_to_id = {w: i for i, w in enumerate(width_set)}
            output.extend(struct.pack('<B', len(width_set)))
            for w in width_set:
                output.append(w)
            output.extend(bytes(width_to_id[w] for w in widths))

            # Write fallbacks
            output.extend(struct.pack('<H', len(raw_fallbacks)))
            for idx, val in raw_fallbacks:
                output.extend(struct.pack('<I', idx))
                val_bytes = val.encode('utf-8')
                output.extend(struct.pack('<H', len(val_bytes)))
                output.extend(val_bytes)

            col_info.append('prefix-binary')

        elif col_type == 'integer':
            # Check sortedness
            nums = []
            for v in values:
                if isinstance(v, int):
                    nums.append(v)
                elif v is not None and SAFE_INT_RE.match(str(v)):
                    nums.append(int(v))

            sorted_count = sum(1 for i in range(1, len(nums)) if nums[i] >= nums[i-1]) if len(nums) > 1 else 0
            use_delta = sorted_count >= len(nums) * 0.7 if nums else False

            if use_delta:
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
                # Dictionary for unsorted integers
                unique = set(str_values)
                if len(unique) < n_lines * 0.3:
                    output.append(ENC_DICTIONARY)
                    freq = Counter(str_values)
                    sorted_vals = [v for v, _ in freq.most_common()]
                    val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                    output.extend(struct.pack('<I', len(sorted_vals)))
                    for v in sorted_vals:
                        vb = v.encode('utf-8')
                        output.extend(struct.pack('<H', len(vb)))
                        output.extend(vb)

                    if len(sorted_vals) <= 256:
                        output.append(1)
                        output.extend(bytes(val_to_id[v] for v in str_values))
                    else:
                        output.append(0)
                        indices = '\n'.join(str(val_to_id[v]) for v in str_values)
                        output.extend(struct.pack('<I', len(indices.encode('utf-8'))))
                        output.extend(indices.encode('utf-8'))
                    col_info.append('integer-dict')
                else:
                    output.append(ENC_RAW)
                    all_text = '\n'.join(str_values)
                    output.extend(struct.pack('<I', len(all_text.encode('utf-8'))))
                    output.extend(all_text.encode('utf-8'))
                    col_info.append('integer-raw')

        else:
            # String - dictionary or raw
            unique = set(str_values)
            if len(unique) < n_lines * 0.3:
                output.append(ENC_DICTIONARY)
                freq = Counter(str_values)
                sorted_vals = [v for v, _ in freq.most_common()]
                val_to_id = {v: i for i, v in enumerate(sorted_vals)}

                output.extend(struct.pack('<I', len(sorted_vals)))
                for v in sorted_vals:
                    vb = v.encode('utf-8', errors='replace')
                    output.extend(struct.pack('<H', len(vb)))
                    output.extend(vb)

                if len(sorted_vals) <= 256:
                    output.append(1)
                    output.extend(bytes(val_to_id[v] for v in str_values))
                else:
                    output.append(0)
                    indices = '\n'.join(str(val_to_id[v]) for v in str_values)
                    output.extend(struct.pack('<I', len(indices.encode('utf-8'))))
                    output.extend(indices.encode('utf-8'))
                col_info.append('dictionary')
            else:
                output.append(ENC_RAW)
                escaped = [v.replace('\\', '\\\\').replace('\n', '\\n') for v in str_values]
                all_text = '\n'.join(escaped)
                output.extend(struct.pack('<I', len(all_text.encode('utf-8'))))
                output.extend(all_text.encode('utf-8'))
                col_info.append('raw')

    return bytes(output), col_info


def decode_from_bytes(data):
    """Decode bytes back to JSON lines"""
    pos = 0

    magic = data[pos:pos+4]
    pos += 4
    if magic != b'JSN2':
        raise ValueError(f"Invalid magic: {magic}, expected JSN2")

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

    columns = {}
    for key in keys:
        enc_type = data[pos]
        pos += 1

        if enc_type == ENC_DELTA_TIMESTAMP:
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

        elif enc_type == ENC_TEMPLATE:
            tmpl_len = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            template = data[pos:pos+tmpl_len].decode('utf-8')
            pos += tmpl_len

            n_placeholders = data[pos]
            pos += 1

            # Read variable columns
            var_columns = []
            for _ in range(n_placeholders):
                var_enc = data[pos]
                pos += 1

                if var_enc == ENC_DICTIONARY:
                    dict_len = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4
                    dictionary = []
                    for _ in range(dict_len):
                        val_len = struct.unpack('<H', data[pos:pos+2])[0]
                        pos += 2
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

                    var_columns.append([dictionary[i] for i in indices])

                else:  # ENC_RAW
                    text_len = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4
                    text = data[pos:pos+text_len].decode('utf-8')
                    pos += text_len
                    raw_values = text.split('\n')
                    var_columns.append([v.replace('\\n', '\n').replace('\\\\', '\\') for v in raw_values])

            # Reconstruct strings - handle both <S> and <N> placeholders
            values = []
            # Use regex to split template while preserving placeholder order
            import re
            placeholder_re = re.compile(r'(<[SN]>)')
            parts = placeholder_re.split(template)

            for i in range(n_lines):
                result = []
                var_idx = 0
                for part in parts:
                    if part == '<S>' or part == '<N>':
                        if var_idx < len(var_columns):
                            result.append(var_columns[var_idx][i])
                        var_idx += 1
                    else:
                        result.append(part)
                values.append(''.join(result))
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

            # Unpack numbers
            if byte_width == 4:
                nums = [struct.unpack('<I', binary_nums[i:i+4])[0] for i in range(0, len(binary_nums), 4)]
            else:
                nums = [struct.unpack('<Q', binary_nums[i:i+8])[0] for i in range(0, len(binary_nums), 8)]

            # Read widths
            n_widths = data[pos]
            pos += 1
            width_list = []
            for _ in range(n_widths):
                width_list.append(data[pos])
                pos += 1

            # Width indices - one per value
            width_indices = list(data[pos:pos+len(nums)])
            pos += len(nums)

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

            # Reconstruct values
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

        elif enc_type == ENC_DICTIONARY:
            dict_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            dictionary = []
            for _ in range(dict_len):
                val_len = struct.unpack('<H', data[pos:pos+2])[0]
                pos += 2
                dictionary.append(data[pos:pos+val_len].decode('utf-8', errors='replace'))
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

            values = [dictionary[i] for i in indices]
            columns[key] = values

        else:  # ENC_RAW
            text_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            text = data[pos:pos+text_len].decode('utf-8')
            pos += text_len

            raw_values = text.split('\n')
            values = [v.replace('\\n', '\n').replace('\\\\', '\\') for v in raw_values]
            columns[key] = values

    # Reconstruct JSON lines
    lines = []
    for i in range(n_lines):
        obj = {}
        for key in keys:
            val = columns[key][i]
            if val is not None and val != '':
                if isinstance(val, int):
                    obj[key] = val
                else:
                    try:
                        obj[key] = int(val)
                    except (ValueError, TypeError):
                        obj[key] = val

        if '_raw' in obj:
            lines.append(obj['_raw'])
        else:
            lines.append(json.dumps(obj, separators=(',', ': ')))

    return lines


def verify_file(input_file):
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
        return False, None


if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[1] != 'verify':
        print("Usage: json_codec_v2.py verify <input_file>")
        sys.exit(1)
    result = verify_file(sys.argv[2])
    sys.exit(0 if result[0] else 1)

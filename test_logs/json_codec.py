#!/usr/bin/env python3
"""
Direct JSON log compression - no Drain needed.

For structured logs (JSON, key=value), we can:
1. Extract schema (keys) as template
2. Store values in columns directly
3. Apply type-specific encoding per column

This avoids Drain's overhead and gives us perfect column alignment.
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

# ISO timestamp pattern
ISO_TIMESTAMP_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')
PREFIX_ID_RE = re.compile(r'^([a-zA-Z][\w-]*)-(\d+)$')
SAFE_INT_RE = re.compile(r'^(-?[1-9]\d*|0)$')


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


def parse_prefix_id(val):
    """Parse prefixed ID like req-12345"""
    m = PREFIX_ID_RE.match(val)
    if not m:
        return None, None, None
    prefix, num_str = m.groups()
    return prefix, int(num_str), len(num_str)


def reconstruct_prefix_id(prefix, num, width):
    """Reconstruct prefixed ID"""
    if width > 0:
        return f"{prefix}-{num:0{width}d}"
    return f"{prefix}-{num}"


def detect_column_type(values):
    """Detect column type from sample values"""
    sample = [v for v in values[:1000] if v is not None and v != '']
    if not sample:
        return 'string'

    # Convert to strings for pattern matching
    str_sample = [str(v) for v in sample]

    # Check for ISO timestamps
    iso_count = sum(1 for v in str_sample if ISO_TIMESTAMP_RE.match(v))
    if iso_count >= len(str_sample) * 0.9:
        return 'iso_timestamp'

    # Check for prefixed IDs
    prefix_count = sum(1 for v in str_sample if PREFIX_ID_RE.match(v))
    if prefix_count >= len(str_sample) * 0.9:
        prefixes = set()
        for v in str_sample:
            m = PREFIX_ID_RE.match(v)
            if m:
                prefixes.add(m.group(1))
        if len(prefixes) == 1:
            return 'prefix_id'

    # Check for integers
    if all(isinstance(v, int) for v in sample):
        return 'integer'

    int_count = sum(1 for v in str_sample if SAFE_INT_RE.match(v))
    if int_count >= len(str_sample) * 0.9:
        return 'integer'

    return 'string'


def encode_json_logs(lines):
    """Parse JSON lines and extract columnar data"""
    # Parse all JSON objects
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
            # Store as raw line
            parsed.append({'_raw': line})
            if '_raw' not in all_keys:
                all_keys.append('_raw')

    # Extract columns
    columns = {}
    for key in all_keys:
        columns[key] = [obj.get(key) for obj in parsed]

    return all_keys, columns, parsed


def encode_to_bytes(keys, columns, n_lines):
    """Encode columnar data to bytes"""
    output = bytearray()
    output.extend(b'JSON')  # Magic

    # Write schema (keys)
    output.extend(struct.pack('<H', len(keys)))
    for key in keys:
        kb = key.encode('utf-8')
        output.extend(struct.pack('<H', len(kb)))
        output.extend(kb)

    output.extend(struct.pack('<I', n_lines))

    col_info = []

    for key in keys:
        values = columns[key]

        # Convert None to empty string for encoding
        str_values = ['' if v is None else str(v) for v in values]

        col_type = detect_column_type(values)

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

            # Write format dictionary
            format_list = sorted(format_set)
            fmt_to_id = {f: i for i, f in enumerate(format_list)}
            output.extend(struct.pack('<B', len(format_list)))
            for fmt in format_list:
                output.append(fmt[0])  # ms_digits
                tz = fmt[1].encode('utf-8')
                output.append(len(tz))
                output.extend(tz)
                output.append(ord(fmt[2]))  # separator

            # Write deltas
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

        elif col_type == 'prefix_id':
            output.append(ENC_PREFIX_DELTA)

            parsed = []
            prefix_val = None
            width_set = set()
            for v in str_values:
                prefix, num, width = parse_prefix_id(v)
                if prefix is not None:
                    if prefix_val is None:
                        prefix_val = prefix
                    width_set.add(width)
                    parsed.append((num, width, None))
                else:
                    parsed.append((None, 0, v))

            # Write prefix
            prefix_bytes = prefix_val.encode('utf-8') if prefix_val else b''
            output.extend(struct.pack('<B', len(prefix_bytes)))
            output.extend(prefix_bytes)

            # Write width options
            width_list = sorted(width_set)
            width_to_id = {w: i for i, w in enumerate(width_list)}
            output.extend(struct.pack('<B', len(width_list)))
            for w in width_list:
                output.append(w)

            # Write deltas
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

        elif col_type == 'integer':
            # Check if sorted for delta encoding
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
                text_bytes = all_text.encode('utf-8')
                output.extend(struct.pack('<I', len(text_bytes)))
                output.extend(text_bytes)
                col_info.append('integer-delta')
            else:
                # Store as raw - use dictionary if beneficial
                str_values = ['' if v is None else str(v) for v in values]
                unique = set(str_values)
                if len(unique) < 0.3 * n_lines:
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
                    text_bytes = all_text.encode('utf-8')
                    output.extend(struct.pack('<I', len(text_bytes)))
                    output.extend(text_bytes)
                    col_info.append('integer-raw')

        else:
            # String - dictionary or raw
            unique = set(str_values)
            if len(unique) < 0.3 * n_lines:
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
    if magic != b'JSON':
        raise ValueError(f"Invalid magic: {magic}, expected JSON")

    # Read schema
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
            # Read format dictionary
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

            # Read deltas
            delta_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            delta_text = data[pos:pos+delta_len].decode('utf-8')
            pos += delta_len
            deltas = delta_text.split('\n')

            # Read format indices
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

        elif enc_type == ENC_PREFIX_DELTA:
            # Read prefix
            prefix_len = data[pos]
            pos += 1
            prefix = data[pos:pos+prefix_len].decode('utf-8')
            pos += prefix_len

            # Read width options
            n_widths = data[pos]
            pos += 1
            width_list = []
            for _ in range(n_widths):
                width_list.append(data[pos])
                pos += 1

            # Read deltas
            delta_len = struct.unpack('<I', data[pos:pos+4])[0]
            pos += 4
            delta_text = data[pos:pos+delta_len].decode('utf-8')
            pos += delta_len
            deltas = delta_text.split('\n')

            # Read width indices
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
                    values.append(reconstruct_prefix_id(prefix, current, width))
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
                    try:
                        # Check if it's a delta or raw value
                        n = int(e)
                        current += n
                        values.append(current)
                    except ValueError:
                        values.append(e)
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
                # Try to preserve types
                if isinstance(val, int):
                    obj[key] = val
                else:
                    # Try parsing as int
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

    # For JSON, we need semantic comparison not string comparison
    errors = 0
    for i, (orig, dec) in enumerate(zip(original_lines, decoded_lines)):
        try:
            orig_obj = json.loads(orig)
            dec_obj = json.loads(dec)
            if orig_obj != dec_obj:
                errors += 1
                if errors <= 5:
                    print(f"✗ Line {i} semantic mismatch")
                    print(f"  orig keys: {sorted(orig_obj.keys())}")
                    print(f"  dec keys:  {sorted(dec_obj.keys())}")
                    for k in orig_obj:
                        if orig_obj.get(k) != dec_obj.get(k):
                            print(f"  diff {k}: {repr(orig_obj.get(k))} vs {repr(dec_obj.get(k))}")
        except json.JSONDecodeError:
            if orig != dec:
                errors += 1
                if errors <= 5:
                    print(f"✗ Line {i} mismatch (non-JSON)")

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


def main():
    if len(sys.argv) < 2:
        print("Usage: json_codec.py verify <input_file>")
        sys.exit(1)

    if sys.argv[1] == 'verify':
        result = verify_file(sys.argv[2])
        success = result[0] if isinstance(result, tuple) else result
        sys.exit(0 if success else 1)
    else:
        print(f"Unknown command: {sys.argv[1]}")
        sys.exit(1)


if __name__ == '__main__':
    main()

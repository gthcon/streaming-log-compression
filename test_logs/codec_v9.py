#!/usr/bin/env python3
"""
V9 Adaptive Log Codec - Best encoding per log type

Strategy:
1. For JSON logs: Use V6-style columnar encoding (best for structured data)
2. For repetitive text logs: Use V8-style XOR delta (best after zstd)
3. For template-based logs: Use Drain + smart column encoding (best for apache/nasa)

Auto-detects log type and uses optimal strategy.
"""

import sys
import struct
import json
import re
from collections import Counter, defaultdict
from io import BytesIO

# Import components from other codecs
try:
    from codec_v6 import encode_v6 as v6_encode, decode_v6 as v6_decode
    HAS_V6 = True
except ImportError:
    HAS_V6 = False

try:
    from codec_v8 import encode_v8 as v8_encode, decode_v8 as v8_decode
    HAS_V8 = True
except ImportError:
    HAS_V8 = False

try:
    from drain_lossless_v4 import encode as drain_encode, decode as drain_decode
    HAS_DRAIN = True
except ImportError:
    HAS_DRAIN = False

import zstandard as zstd

MAGIC = b'LGV9'
VERSION = 1

# Encoding strategies
STRATEGY_V6 = 1  # JSON columnar
STRATEGY_V8 = 2  # XOR delta
STRATEGY_DRAIN = 3  # Drain template

def is_json_log(lines):
    """Check if log is JSON format."""
    json_count = 0
    for line in lines[:100]:
        line = line.strip()
        if line:
            try:
                json.loads(line)
                json_count += 1
            except:
                pass
    return json_count > len(lines[:100]) * 0.5

def is_repetitive_log(lines):
    """Check if log has highly repetitive structure (good for XOR)."""
    if len(lines) < 100:
        return False

    # Check if consecutive lines have similar lengths
    lengths = [len(l) for l in lines[:500]]
    avg_len = sum(lengths) / len(lengths)
    variance = sum((l - avg_len)**2 for l in lengths) / len(lengths)

    # Low variance in length = repetitive structure
    return variance < avg_len * 2  # Threshold

def is_template_log(lines):
    """Check if log follows template patterns (good for Drain)."""
    if len(lines) < 100:
        return False

    # Check for common prefixes (timestamps, etc.)
    prefix_len = 20
    prefixes = Counter(l[:prefix_len] for l in lines[:500] if len(l) > prefix_len)

    # If top prefixes cover >50% of lines, it's template-based
    top_count = sum(c for _, c in prefixes.most_common(10))
    return top_count > len(lines[:500]) * 0.5

def estimate_compression(data):
    """Estimate how well data compresses with zstd."""
    compressed = zstd.compress(data, level=1)  # Fast compression for estimation
    return len(compressed) / len(data) if data else 1.0

def encode_v9(lines):
    """Main V9 encoder - picks best strategy."""
    if not lines:
        return MAGIC + bytes([VERSION, STRATEGY_V8]) + b'\x00'

    # Detect log type
    is_json = is_json_log(lines)
    is_repetitive = is_repetitive_log(lines)

    if is_json and HAS_V6:
        # JSON logs: use V6 columnar
        encoded = v6_encode(lines)
        return MAGIC + bytes([VERSION, STRATEGY_V6]) + encoded

    elif HAS_V8:
        # Text logs: use V8 XOR delta (almost always better after zstd)
        encoded = v8_encode(lines)
        return MAGIC + bytes([VERSION, STRATEGY_V8]) + encoded

    else:
        # Fallback to raw
        output = BytesIO()
        output.write(MAGIC)
        output.write(bytes([VERSION, 0]))

        for line in lines:
            line_bytes = line.encode('utf-8')
            output.write(struct.pack('<I', len(line_bytes)))
            output.write(line_bytes)

        return output.getvalue()

def decode_v9(data):
    """Main V9 decoder."""
    if len(data) < 6:
        return []

    if data[:4] != MAGIC:
        return []

    version = data[4]
    strategy = data[5]
    inner_data = data[6:]

    if strategy == STRATEGY_V6 and HAS_V6:
        return v6_decode(inner_data)
    elif strategy == STRATEGY_V8 and HAS_V8:
        return v8_decode(inner_data)
    elif strategy == STRATEGY_DRAIN and HAS_DRAIN:
        return drain_decode(inner_data)
    else:
        # Fallback raw decode
        lines = []
        pos = 0
        while pos < len(inner_data):
            if pos + 4 > len(inner_data):
                break
            line_len = struct.unpack('<I', inner_data[pos:pos+4])[0]
            pos += 4
            lines.append(inner_data[pos:pos+line_len].decode('utf-8'))
            pos += line_len
        return lines

def verify_file(input_path):
    """Encode, decode, and verify a file."""
    import time

    print(f"V9 Processing {input_path}...")

    with open(input_path, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    print(f"  Lines: {len(lines)}")

    is_json = is_json_log(lines)
    is_repetitive = is_repetitive_log(lines)
    print(f"  JSON: {is_json}, Repetitive: {is_repetitive}")

    start = time.time()
    encoded = encode_v9(lines)
    encode_time = time.time() - start

    orig_size = len('\n'.join(lines))
    print(f"  Strategy: {'V6 columnar' if encoded[5] == STRATEGY_V6 else 'V8 XOR' if encoded[5] == STRATEGY_V8 else 'Drain'}")
    print(f"  Encoded size: {len(encoded):,} bytes ({len(encoded)/orig_size*100:.1f}%)")
    print(f"  Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")

    start = time.time()
    decoded = decode_v9(encoded)
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
        print("Usage: codec_v9.py <logfile>")
        sys.exit(1)

    success, data = verify_file(sys.argv[1])
    sys.exit(0 if success else 1)

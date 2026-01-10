#!/usr/bin/env python3
"""
Unified log compression codec - auto-detects format and uses optimal strategy.

Supported formats:
- JSON lines (structured)
- CLF/Apache access logs (semi-structured with timestamps)
- Generic text logs (uses Drain for template discovery)

The codec automatically selects the best compression strategy.
"""
import sys
import struct
import time
import json
import pyzstd

# Import the specialized codecs
from json_codec_v2 import encode_json_logs, encode_to_bytes as json_encode_to_bytes, decode_from_bytes as json_decode
from drain_lossless_v4 import encode_lossless as drain_encode, encode_to_bytes as drain_encode_to_bytes, decode_from_bytes as drain_decode


def detect_format(lines, sample_size=100):
    """Detect log format from sample lines"""
    sample = lines[:min(sample_size, len(lines))]

    # Check for JSON
    json_count = 0
    for line in sample:
        line = line.strip()
        if line.startswith('{') and line.endswith('}'):
            try:
                json.loads(line)
                json_count += 1
            except json.JSONDecodeError:
                pass

    if json_count >= len(sample) * 0.9:
        return 'json'

    # Default to drain-based compression
    return 'drain'


def compress(lines, level=19, adaptive=True):
    """Compress log lines using optimal strategy

    If adaptive=True, compares our codec with raw zstd and uses the smaller one.
    """
    fmt = detect_format(lines)

    if fmt == 'json':
        keys, columns, parsed = encode_json_logs(lines)
        raw_data, col_info = json_encode_to_bytes(keys, columns, len(lines))
        magic = b'LJS2'  # Log JSON v2
    else:
        templates, encoded = drain_encode(lines)
        raw_data, col_info = drain_encode_to_bytes(templates, encoded)
        magic = b'LDRN'  # Log Drain

    # Compress with zstd
    compressed = pyzstd.compress(raw_data, level)

    # Adaptive: compare with raw zstd and use smaller one
    if adaptive:
        raw_text = '\n'.join(lines).encode('utf-8')
        raw_zst = pyzstd.compress(raw_text, level)
        if len(raw_zst) < len(compressed):
            # Raw zstd is better - use it
            output = bytearray()
            output.extend(b'LOGC')
            output.extend(b'LRAW')  # Raw format
            output.extend(struct.pack('<I', len(raw_zst)))
            output.extend(raw_zst)
            return bytes(output), 'raw', []

    # Wrap with format header
    output = bytearray()
    output.extend(b'LOGC')  # Log Codec magic
    output.extend(magic)    # Format type
    output.extend(struct.pack('<I', len(compressed)))
    output.extend(compressed)

    return bytes(output), fmt, col_info


def decompress(data):
    """Decompress log data back to lines"""
    if data[:4] != b'LOGC':
        raise ValueError(f"Invalid magic: {data[:4]}, expected LOGC")

    fmt_magic = data[4:8]
    compressed_len = struct.unpack('<I', data[8:12])[0]
    compressed = data[12:12+compressed_len]

    raw_data = pyzstd.decompress(compressed)

    if fmt_magic == b'LJSN':
        lines = json_decode(raw_data)
    elif fmt_magic == b'LJS2':
        # JSON v2 format
        lines = json_decode(raw_data)
    elif fmt_magic == b'LDRN':
        lines = drain_decode(raw_data)
    elif fmt_magic == b'LRAW':
        lines = raw_data.decode('utf-8').split('\n')
    else:
        raise ValueError(f"Unknown format: {fmt_magic}")

    return lines


def verify_file(input_file):
    """Verify lossless compression of a file"""
    with open(input_file, 'r', errors='replace') as f:
        original_lines = [l.rstrip('\n') for l in f]

    print(f"Verifying {len(original_lines):,} lines from {input_file}...")

    # Compress
    start = time.time()
    compressed, fmt, col_info = compress(original_lines)
    compress_time = time.time() - start

    # Decompress
    start = time.time()
    decoded_lines = decompress(compressed)
    decompress_time = time.time() - start

    # Verify
    orig_size = sum(len(l.encode('utf-8')) + 1 for l in original_lines)

    if fmt == 'json':
        # Semantic comparison for JSON
        errors = 0
        for i, (orig, dec) in enumerate(zip(original_lines, decoded_lines)):
            try:
                if json.loads(orig) != json.loads(dec):
                    errors += 1
            except json.JSONDecodeError:
                if orig != dec:
                    errors += 1
    else:
        # Exact comparison for other formats
        errors = sum(1 for o, d in zip(original_lines, decoded_lines) if o != d)

    if len(decoded_lines) != len(original_lines):
        print(f"✗ Line count mismatch: {len(decoded_lines)} vs {len(original_lines)}")
        return False

    if errors == 0:
        print(f"✓ All {len(original_lines):,} lines verified!")
        print(f"  Format: {fmt}")
        print(f"  Columns: {col_info}")
        print(f"  Compress: {compress_time:.2f}s ({len(original_lines)/compress_time:.0f} lines/sec)")
        print(f"  Decompress: {decompress_time:.2f}s ({len(original_lines)/decompress_time:.0f} lines/sec)")
        print(f"  Original: {orig_size:,} bytes")
        print(f"  Compressed: {len(compressed):,} bytes ({len(compressed)*100/orig_size:.2f}%)")

        # Compare with raw zstd
        raw_zst = pyzstd.compress('\n'.join(original_lines).encode('utf-8'), 19)
        print(f"  Raw zstd: {len(raw_zst):,} bytes ({len(raw_zst)*100/orig_size:.2f}%)")
        improvement = (1 - len(compressed)/len(raw_zst)) * 100
        print(f"  Improvement over raw zstd: {improvement:.1f}%")

        return True
    else:
        print(f"✗ {errors} lines with mismatches")
        return False


def benchmark(input_file):
    """Benchmark compression performance"""
    with open(input_file, 'r', errors='replace') as f:
        original_lines = [l.rstrip('\n') for l in f]

    orig_size = sum(len(l.encode('utf-8')) + 1 for l in original_lines)

    print(f"Benchmarking {len(original_lines):,} lines ({orig_size:,} bytes)")
    print("-" * 60)

    # Our codec
    start = time.time()
    compressed, fmt, _ = compress(original_lines)
    our_time = time.time() - start

    # Raw zstd
    start = time.time()
    raw_zst = pyzstd.compress('\n'.join(original_lines).encode('utf-8'), 19)
    zstd_time = time.time() - start

    print(f"{'Method':<20} {'Size':>12} {'Ratio':>8} {'Time':>8} {'Speed':>12}")
    print("-" * 60)
    print(f"{'Raw zstd':<20} {len(raw_zst):>12,} {len(raw_zst)*100/orig_size:>7.2f}% {zstd_time:>7.2f}s {len(original_lines)/zstd_time:>10,.0f}/s")
    print(f"{'Log codec (' + fmt + ')':<20} {len(compressed):>12,} {len(compressed)*100/orig_size:>7.2f}% {our_time:>7.2f}s {len(original_lines)/our_time:>10,.0f}/s")

    improvement = (1 - len(compressed)/len(raw_zst)) * 100
    print("-" * 60)
    print(f"Improvement: {improvement:.1f}% smaller than raw zstd")


def main():
    if len(sys.argv) < 2:
        print("Usage: log_codec.py <command> <file>")
        print("Commands:")
        print("  verify    - Verify lossless compression")
        print("  benchmark - Compare compression performance")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'verify':
        success = verify_file(sys.argv[2])
        sys.exit(0 if success else 1)
    elif cmd == 'benchmark':
        benchmark(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == '__main__':
    main()

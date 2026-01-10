#!/usr/bin/env python3
"""Benchmark streaming V10 codec vs batch V10 codec."""

import os
import sys
import time
import tempfile

from codec_v10_streaming import encode_streaming, decode_streaming

TEST_FILES = [
    "linux_50mb.log",
    "windows_50mb.log",
    "thunderbird_50mb.log",
    "hdfs_50mb.log",
    "mac_50mb.log",
    "apache_combined_50mb.log",
    "nasa_50mb.log",
    "nginx_json_50mb.log",
    "cloudtrail_50mb.log",
    "gharchive_jan_50mb.log",
    "elastic_web_50mb.log",
]

# Batch V10 results (from previous benchmark)
BATCH_RESULTS = {
    "linux_50mb.log": 0.24,
    "windows_50mb.log": 0.40,
    "thunderbird_50mb.log": 4.46,
    "hdfs_50mb.log": 0.09,
    "mac_50mb.log": 3.63,
    "apache_combined_50mb.log": 6.44,
    "nasa_50mb.log": 6.44,
    "nginx_json_50mb.log": 1.08,
    "cloudtrail_50mb.log": 7.72,
    "gharchive_jan_50mb.log": 5.94,
    "elastic_web_50mb.log": 2.47,
}

def benchmark_streaming(filepath, block_size):
    """Benchmark streaming compression on a single file."""
    original_size = os.path.getsize(filepath)

    # Read original for verification
    with open(filepath, 'r', errors='replace') as f:
        original_lines = [l.rstrip('\n') for l in f]

    temp_encoded = tempfile.NamedTemporaryFile(delete=False)
    temp_encoded.close()

    try:
        # Encode
        start = time.time()
        block_count = encode_streaming(filepath, temp_encoded.name, block_size)
        encode_time = time.time() - start

        encoded_size = os.path.getsize(temp_encoded.name)
        ratio = encoded_size / original_size * 100

        # Decode
        start = time.time()
        decoded_lines = decode_streaming(temp_encoded.name)
        decode_time = time.time() - start

        # Verify (including JSON semantic equivalence)
        import json
        lossless = True
        if len(original_lines) != len(decoded_lines):
            lossless = False
        else:
            for orig, dec in zip(original_lines, decoded_lines):
                if orig != dec:
                    # Check JSON semantic equivalence
                    try:
                        if json.loads(orig) != json.loads(dec):
                            lossless = False
                            break
                    except:
                        lossless = False
                        break

        return {
            "ratio_pct": ratio,
            "blocks": block_count,
            "encode_time": encode_time,
            "decode_time": decode_time,
            "lossless": lossless,
            "lines": len(original_lines)
        }
    finally:
        os.unlink(temp_encoded.name)


def main():
    block_sizes = [5000, 10000, 50000]

    print("="*110)
    print("STREAMING V10 CODEC BENCHMARK")
    print("="*110)

    for block_size in block_sizes:
        print(f"\n--- Block Size: {block_size} lines ---")
        print(f"{'File':<28} {'Size':>8} {'Batch':>8} {'Stream':>10} {'Blocks':>8} {'Gap':>8} {'Lossless':>10}")
        print("-"*110)

        for filename in TEST_FILES:
            if not os.path.exists(filename):
                print(f"{filename:<28} NOT FOUND")
                continue

            orig_size = os.path.getsize(filename)
            batch_pct = BATCH_RESULTS.get(filename, 999)

            print(f"{filename:<28} {orig_size/1024/1024:>6.1f}MB {batch_pct:>7.2f}% ", end="", flush=True)

            try:
                r = benchmark_streaming(filename, block_size)
                gap = r["ratio_pct"] - batch_pct
                lossless_str = "✓" if r["lossless"] else "✗"

                print(f"{r['ratio_pct']:>9.2f}% {r['blocks']:>8} {gap:>+7.2f}% {lossless_str:>10}")

            except Exception as e:
                print(f"ERROR: {e}")

    print("\n" + "="*110)


if __name__ == "__main__":
    main()

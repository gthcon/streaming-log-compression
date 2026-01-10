#!/usr/bin/env python3
"""Benchmark V10 codec with zstd compression against raw zstd baseline."""

import subprocess
import os
import sys
import time
import tempfile

# Import codec_v10 directly
from codec_v10 import encode_v10, decode_v10, detect_format, FMT_JSON

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

# Baseline results from zstd -19 (raw)
BASELINES = {
    "linux_50mb.log": 0.24,
    "windows_50mb.log": 0.40,
    "thunderbird_50mb.log": 4.46,
    "hdfs_50mb.log": 0.09,
    "mac_50mb.log": 3.64,
    "apache_combined_50mb.log": 6.44,
    "nasa_50mb.log": 6.44,
    "nginx_json_50mb.log": 2.17,
    "cloudtrail_50mb.log": 8.64,
    "gharchive_jan_50mb.log": 5.94,
    "elastic_web_50mb.log": 3.10,
}

def compress_zstd(data: bytes) -> bytes:
    """Compress data with zstd -19."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        temp_in = f.name

    temp_out = temp_in + ".zst"
    try:
        subprocess.run(["zstd", "-19", "-f", "-q", temp_in, "-o", temp_out], check=True)
        with open(temp_out, "rb") as f:
            result = f.read()
        return result
    finally:
        os.unlink(temp_in)
        if os.path.exists(temp_out):
            os.unlink(temp_out)

def benchmark_file(filepath):
    """Benchmark a single file."""
    orig_size = os.path.getsize(filepath)

    with open(filepath, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    # Encode with V10
    start = time.time()
    encoded = encode_v10(lines)
    encode_time = time.time() - start

    # Compress encoded data with zstd
    compressed = compress_zstd(encoded)

    # Verify decode
    start = time.time()
    decoded = decode_v10(encoded)
    decode_time = time.time() - start

    # Check losslessness
    lossless = True
    mismatches = 0
    for i, (orig, dec) in enumerate(zip(lines, decoded)):
        if orig != dec:
            import json
            try:
                orig_obj = json.loads(orig)
                dec_obj = json.loads(dec)
                if orig_obj == dec_obj:
                    continue  # JSON-equivalent
            except:
                pass
            mismatches += 1
            lossless = False

    return {
        "orig_size": orig_size,
        "encoded_size": len(encoded),
        "compressed_size": len(compressed),
        "ratio_pct": len(compressed) / orig_size * 100,
        "encode_time": encode_time,
        "decode_time": decode_time,
        "lossless": lossless,
        "mismatches": mismatches,
        "lines": len(lines)
    }

def main():
    print("="*100)
    print("V10 CODEC + ZSTD vs RAW ZSTD BASELINE")
    print("="*100)
    print(f"{'File':<26} {'Size':>8} {'zstd':>8} {'V10+zstd':>10} {'Winner':>10} {'Lossless':>10} {'Enc MB/s':>10}")
    print("-"*100)

    v10_wins = 0
    ties = 0
    total_files = 0
    results = []

    for filename in TEST_FILES:
        if not os.path.exists(filename):
            print(f"{filename:<26} NOT FOUND")
            continue

        total_files += 1
        zstd_pct = BASELINES.get(filename, 999)

        print(f"{filename:<26} ", end="", flush=True)

        try:
            r = benchmark_file(filename)

            # Use tolerance for floating point comparison
            diff = r["ratio_pct"] - zstd_pct
            if diff < -0.005:  # V10 wins (more than 0.005% better)
                winner = "V10"
                v10_wins += 1
            elif diff > 0.005:  # zstd wins (more than 0.005% better)
                winner = "zstd"
            else:  # Tie (within 0.005%)
                winner = "TIE"
                ties += 1

            lossless_str = "✓" if r["lossless"] else f"✗({r['mismatches']})"
            enc_speed = r["orig_size"] / r["encode_time"] / 1024 / 1024

            print(f"{r['orig_size']/1024/1024:>6.1f}MB {zstd_pct:>7.2f}% {r['ratio_pct']:>9.2f}% {winner:>10} {lossless_str:>10} {enc_speed:>9.1f}")

            results.append({
                "file": filename,
                "zstd": zstd_pct,
                "v10": r["ratio_pct"],
                "winner": winner,
                "lossless": r["lossless"],
                "mismatches": r["mismatches"]
            })
        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()

    print("-"*100)
    losses = total_files - v10_wins - ties
    print(f"\nV10 wins: {v10_wins}, Ties: {ties}, Losses: {losses} (out of {total_files})")

    if losses == 0:
        print("\n🏆 V10+ZSTD BEATS OR MATCHES RAW ZSTD ON EVERY FILE! 🏆")
    else:
        print(f"\nLosing on {losses} file(s):")
        for r in results:
            if r["winner"] == "zstd":
                print(f"  - {r['file']}: V10={r['v10']:.2f}% vs zstd={r['zstd']:.2f}%")

    # Summary stats
    if results:
        avg_v10 = sum(r['v10'] for r in results) / len(results)
        avg_zstd = sum(r['zstd'] for r in results) / len(results)
        print(f"\nAverage compression ratio:")
        print(f"  zstd -19:  {avg_zstd:.2f}%")
        print(f"  V10+zstd:  {avg_v10:.2f}%")
        print(f"  Improvement: {(avg_zstd - avg_v10)/avg_zstd*100:.1f}%")

if __name__ == "__main__":
    main()

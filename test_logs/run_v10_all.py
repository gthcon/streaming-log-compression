#!/usr/bin/env python3
"""Run V10 codec on all 50MB logs and compare against baselines."""

import subprocess
import os
import sys
import json

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

# Baseline results from zstd -19
BASELINES = {
    "linux_50mb.log": {"zstd": 0.24},
    "windows_50mb.log": {"zstd": 0.40},
    "thunderbird_50mb.log": {"zstd": 4.46},
    "hdfs_50mb.log": {"zstd": 0.09},
    "mac_50mb.log": {"zstd": 3.64},
    "apache_combined_50mb.log": {"zstd": 6.44},
    "nasa_50mb.log": {"zstd": 6.44},
    "nginx_json_50mb.log": {"zstd": 2.17},
    "cloudtrail_50mb.log": {"zstd": 8.64},
    "gharchive_jan_50mb.log": {"zstd": 5.94},
    "elastic_web_50mb.log": {"zstd": 3.10},
}

def run_v10(filepath):
    """Run V10 codec and return compression ratio."""
    result = subprocess.run(
        ["python3", "codec_v10.py", filepath],
        capture_output=True, text=True, timeout=600
    )

    # Parse output - look for ratio line
    for line in result.stdout.split('\n'):
        if 'Ratio:' in line:
            # "Ratio: 0.31%"
            parts = line.split(':')
            if len(parts) >= 2:
                pct = parts[1].strip().replace('%', '')
                return float(pct)

    # Try alternate format
    for line in result.stdout.split('\n'):
        if '%' in line and 'compressed' in line.lower():
            import re
            m = re.search(r'(\d+\.?\d*)\s*%', line)
            if m:
                return float(m.group(1))

    return None

def main():
    results = []

    print("="*90)
    print("V10 CODEC vs BASELINES")
    print("="*90)
    print(f"{'File':<28} {'Size':>10} {'zstd':>10} {'V10':>10} {'Winner':>12} {'Lossless':>10}")
    print("-"*90)

    v10_wins = 0
    total_files = 0

    for filename in TEST_FILES:
        if not os.path.exists(filename):
            print(f"{filename:<28} NOT FOUND")
            continue

        total_files += 1
        orig_size = os.path.getsize(filename)

        # Get baseline
        zstd_pct = BASELINES.get(filename, {}).get("zstd", 999)

        # Run V10
        print(f"{filename:<28} {orig_size/1024/1024:>7.1f} MB {zstd_pct:>9.2f}% ", end="", flush=True)

        result = subprocess.run(
            ["python3", "codec_v10.py", filename],
            capture_output=True, text=True, timeout=600
        )

        # Parse output - look for "Encoded size: X bytes (Y%)"
        v10_pct = None
        lossless = "?"
        import re
        for line in result.stdout.split('\n'):
            # Match "Encoded size: 10,925,985 bytes (21.1%)"
            m = re.search(r'Encoded size:.*\((\d+\.?\d*)%\)', line)
            if m:
                v10_pct = float(m.group(1))
            if 'verified!' in line:
                lossless = "✓"
            elif 'MISMATCH' in line or 'mismatch' in line:
                lossless = "✗"

        if v10_pct is None:
            print(f"{'FAIL':>10} {'---':>12} {'---':>10}")
            print(f"  Error: {result.stderr[:100] if result.stderr else 'Unknown'}")
        else:
            winner = "V10" if v10_pct <= zstd_pct else "zstd"
            if v10_pct <= zstd_pct:
                v10_wins += 1
            print(f"{v10_pct:>9.2f}% {winner:>12} {lossless:>10}")
            results.append({
                "file": filename,
                "zstd": zstd_pct,
                "v10": v10_pct,
                "winner": winner,
                "lossless": lossless
            })

    print("-"*90)
    print(f"\nV10 wins: {v10_wins}/{total_files} files")

    if v10_wins == total_files:
        print("\n🏆 V10 BEATS ALL BASELINES ON EVERY FILE! 🏆")
    else:
        print(f"\nLosing on {total_files - v10_wins} file(s):")
        for r in results:
            if r["winner"] != "V10":
                print(f"  - {r['file']}: V10={r['v10']:.2f}% vs zstd={r['zstd']:.2f}%")

    return results

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run baseline benchmarks (zstd, loglite, clp) on all 50MB logs and cache results."""

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

CACHE_FILE = "baseline_results.json"

def get_file_size(path):
    return os.path.getsize(path)

def run_zstd(filepath):
    """Run raw zstd compression."""
    out_path = filepath + ".zst"
    subprocess.run(["zstd", "-19", "-f", "-q", filepath, "-o", out_path], check=True)
    size = get_file_size(out_path)
    os.remove(out_path)
    return size

def run_loglite(filepath):
    """Run LogLite compression."""
    out_path = filepath + ".loglite"
    try:
        result = subprocess.run(
            ["python3", "../LogLite/compress.py", filepath, out_path],
            capture_output=True, text=True, timeout=300
        )
        if os.path.exists(out_path):
            size = get_file_size(out_path)
            os.remove(out_path)
            return size
        return None
    except Exception as e:
        return None

def run_clp(filepath):
    """Run CLP compression."""
    out_dir = filepath + "_clp"
    try:
        result = subprocess.run(
            ["../clp_src/clp", "c", out_dir, filepath],
            capture_output=True, text=True, timeout=300
        )
        # CLP creates a directory with multiple files
        if os.path.exists(out_dir):
            total_size = 0
            for root, dirs, files in os.walk(out_dir):
                for f in files:
                    total_size += get_file_size(os.path.join(root, f))
            subprocess.run(["rm", "-rf", out_dir], check=True)
            return total_size
        return None
    except Exception as e:
        return None

def main():
    results = {}

    for filename in TEST_FILES:
        filepath = filename
        if not os.path.exists(filepath):
            print(f"SKIP {filename} - not found")
            continue

        original_size = get_file_size(filepath)
        print(f"\n=== {filename} ({original_size/1024/1024:.2f} MB) ===")

        file_results = {"original_size": original_size}

        # zstd
        print("  Running zstd -19...")
        zstd_size = run_zstd(filepath)
        file_results["zstd"] = zstd_size
        print(f"  zstd: {zstd_size/original_size*100:.2f}%")

        # LogLite
        print("  Running LogLite...")
        loglite_size = run_loglite(filepath)
        if loglite_size:
            file_results["loglite"] = loglite_size
            print(f"  LogLite: {loglite_size/original_size*100:.2f}%")
        else:
            file_results["loglite"] = None
            print("  LogLite: FAILED")

        # CLP
        print("  Running CLP...")
        clp_size = run_clp(filepath)
        if clp_size:
            file_results["clp"] = clp_size
            print(f"  CLP: {clp_size/original_size*100:.2f}%")
        else:
            file_results["clp"] = None
            print("  CLP: FAILED")

        results[filename] = file_results

    # Save to cache file
    with open(CACHE_FILE, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n\nResults saved to {CACHE_FILE}")

    # Print summary table
    print("\n" + "="*80)
    print("BASELINE RESULTS TABLE")
    print("="*80)
    print(f"{'File':<28} {'Size':>10} {'zstd':>10} {'LogLite':>10} {'CLP':>10}")
    print("-"*80)

    for filename, data in results.items():
        orig = data["original_size"]
        zstd_pct = f"{data['zstd']/orig*100:.2f}%" if data.get('zstd') else "N/A"
        loglite_pct = f"{data['loglite']/orig*100:.2f}%" if data.get('loglite') else "N/A"
        clp_pct = f"{data['clp']/orig*100:.2f}%" if data.get('clp') else "N/A"
        print(f"{filename:<28} {orig/1024/1024:>7.1f} MB {zstd_pct:>10} {loglite_pct:>10} {clp_pct:>10}")

if __name__ == "__main__":
    main()

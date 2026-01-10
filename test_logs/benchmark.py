#!/usr/bin/env python3
"""
Benchmark V3/V4 JSON codec vs raw zstd compression.
Tests on real log files only.
"""
import subprocess
import os
import sys
import tempfile
from json_codec_v3 import verify_file
from json_codec_v4 import verify_file_v4

def get_file_size(path):
    return os.path.getsize(path) if os.path.exists(path) else 0

def count_lines(path):
    with open(path, 'rb') as f:
        return sum(1 for _ in f)

def compress_zstd(input_path, level=3):
    """Compress with raw zstd, return size"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zst') as tmp:
        tmp_path = tmp.name
    try:
        subprocess.run(['zstd', f'-{level}', '-f', '-o', tmp_path, input_path],
                      check=True, capture_output=True)
        size = get_file_size(tmp_path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
    return size

def compress_v3_zstd(input_path, level=3):
    """Compress with V3 codec + zstd, return size"""
    success, v3_data = verify_file(input_path)
    if not success or v3_data is None:
        return None

    with tempfile.NamedTemporaryFile(delete=False, suffix='.v3') as tmp_v3:
        tmp_v3.write(v3_data)
        tmp_v3_path = tmp_v3.name

    with tempfile.NamedTemporaryFile(delete=False, suffix='.v3.zst') as tmp_zst:
        tmp_zst_path = tmp_zst.name

    try:
        subprocess.run(['zstd', f'-{level}', '-f', '-o', tmp_zst_path, tmp_v3_path],
                      check=True, capture_output=True)
        size = get_file_size(tmp_zst_path)
        v3_size = get_file_size(tmp_v3_path)
    finally:
        if os.path.exists(tmp_v3_path):
            os.unlink(tmp_v3_path)
        if os.path.exists(tmp_zst_path):
            os.unlink(tmp_zst_path)

    return size, v3_size

def compress_v4_zstd(input_path, level=3):
    """Compress with V4 codec + zstd, return size"""
    success, v4_data = verify_file_v4(input_path)
    if not success or v4_data is None:
        return None

    with tempfile.NamedTemporaryFile(delete=False, suffix='.v4') as tmp_v4:
        tmp_v4.write(v4_data)
        tmp_v4_path = tmp_v4.name

    with tempfile.NamedTemporaryFile(delete=False, suffix='.v4.zst') as tmp_zst:
        tmp_zst_path = tmp_zst.name

    try:
        subprocess.run(['zstd', f'-{level}', '-f', '-o', tmp_zst_path, tmp_v4_path],
                      check=True, capture_output=True)
        size = get_file_size(tmp_zst_path)
        v4_size = get_file_size(tmp_v4_path)
    finally:
        if os.path.exists(tmp_v4_path):
            os.unlink(tmp_v4_path)
        if os.path.exists(tmp_zst_path):
            os.unlink(tmp_zst_path)

    return size, v4_size

def benchmark_file(path, level=3):
    """Benchmark a single file"""
    name = os.path.basename(path)
    orig_size = get_file_size(path)
    lines = count_lines(path)

    print(f"\n{'='*60}")
    print(f"File: {name}")
    print(f"Original: {orig_size:,} bytes ({orig_size/1024/1024:.1f} MB), {lines:,} lines")
    print(f"{'='*60}")

    # Raw zstd
    print(f"Compressing with zstd -{level}...")
    zstd_size = compress_zstd(path, level)
    zstd_ratio = zstd_size / orig_size * 100
    print(f"  zstd-{level}: {zstd_size:,} bytes ({zstd_ratio:.2f}%)")

    # V3 + zstd
    print(f"Compressing with V3 codec + zstd-{level}...")
    v3_result = compress_v3_zstd(path, level)
    if v3_result is None:
        print("  V3: FAILED (not valid JSON or codec error)")
        return {
            'name': name,
            'orig': orig_size,
            'lines': lines,
            'zstd': zstd_size,
            'zstd_ratio': zstd_ratio,
            'v3': None,
            'v3_zstd': None,
            'v3_ratio': None,
            'improvement': None
        }

    v3_zstd_size, v3_raw_size = v3_result
    v3_ratio = v3_zstd_size / orig_size * 100
    improvement = (zstd_size - v3_zstd_size) / zstd_size * 100 if zstd_size > 0 else 0

    print(f"  V3 raw: {v3_raw_size:,} bytes ({v3_raw_size/orig_size*100:.2f}%)")
    print(f"  V3+zstd: {v3_zstd_size:,} bytes ({v3_ratio:.2f}%)")
    print(f"  V3 improvement over zstd: {improvement:.1f}%")

    # V4 + zstd
    print(f"Compressing with V4 codec (flattened) + zstd-{level}...")
    v4_result = compress_v4_zstd(path, level)
    if v4_result is None:
        print("  V4: FAILED (not valid JSON or codec error)")
        v4_zstd_size = None
        v4_raw_size = None
        v4_ratio = None
        v4_improvement = None
    else:
        v4_zstd_size, v4_raw_size = v4_result
        v4_ratio = v4_zstd_size / orig_size * 100
        v4_improvement = (zstd_size - v4_zstd_size) / zstd_size * 100 if zstd_size > 0 else 0

        print(f"  V4 raw: {v4_raw_size:,} bytes ({v4_raw_size/orig_size*100:.2f}%)")
        print(f"  V4+zstd: {v4_zstd_size:,} bytes ({v4_ratio:.2f}%)")
        print(f"  V4 improvement over zstd: {v4_improvement:.1f}%")

    return {
        'name': name,
        'orig': orig_size,
        'lines': lines,
        'zstd': zstd_size,
        'zstd_ratio': zstd_ratio,
        'v3': v3_raw_size,
        'v3_zstd': v3_zstd_size,
        'v3_ratio': v3_ratio,
        'v3_improvement': improvement,
        'v4': v4_raw_size,
        'v4_zstd': v4_zstd_size,
        'v4_ratio': v4_ratio,
        'v4_improvement': v4_improvement
    }

def main():
    # List of JSON log files to benchmark
    json_logs = [
        'nginx_json_elastic.log',   # Real nginx JSON logs
        'cloudtrail_flat.log',      # Real AWS CloudTrail (flattened)
        'gharchive_50mb.log',       # GitHub Archive events (deeply nested)
    ]

    results = []
    for log in json_logs:
        if os.path.exists(log):
            result = benchmark_file(log)
            results.append(result)
        else:
            print(f"Skipping {log} - not found")

    # Print summary table
    print("\n" + "="*130)
    print("SUMMARY: V3 vs V4 vs Raw zstd-3")
    print("="*130)
    print(f"{'File':<28} {'Lines':>10} {'Orig':>10} {'zstd-3':>10} {'V3+zstd':>10} {'V3 Impr':>8} {'V4+zstd':>10} {'V4 Impr':>8} {'Winner':>10}")
    print("-"*130)

    total_zstd = 0
    total_v3 = 0
    total_v4 = 0

    for r in results:
        v3_str = f"{r['v3_zstd']/1e6:>9.2f}M" if r['v3_zstd'] else "FAILED"
        v3_impr = f"{r['v3_improvement']:>7.1f}%" if r['v3_improvement'] else "N/A"
        v4_str = f"{r['v4_zstd']/1e6:>9.2f}M" if r['v4_zstd'] else "FAILED"
        v4_impr = f"{r['v4_improvement']:>7.1f}%" if r['v4_improvement'] else "N/A"

        # Determine winner
        if r['v3_zstd'] and r['v4_zstd']:
            if r['v3_zstd'] < r['v4_zstd']:
                winner = "V3"
            elif r['v4_zstd'] < r['v3_zstd']:
                winner = "V4"
            else:
                winner = "TIE"
        elif r['v3_zstd']:
            winner = "V3"
        elif r['v4_zstd']:
            winner = "V4"
        else:
            winner = "N/A"

        print(f"{r['name']:<28} {r['lines']:>10,} {r['orig']/1e6:>9.1f}M {r['zstd']/1e6:>9.2f}M {v3_str:>10} {v3_impr:>8} {v4_str:>10} {v4_impr:>8} {winner:>10}")

        if r['v3_zstd']:
            total_v3 += r['v3_zstd']
        if r['v4_zstd']:
            total_v4 += r['v4_zstd']
        total_zstd += r['zstd']

    print("-"*130)
    if total_zstd > 0:
        v3_overall = (total_zstd - total_v3) / total_zstd * 100 if total_v3 else 0
        v4_overall = (total_zstd - total_v4) / total_zstd * 100 if total_v4 else 0
        v3_total = f"{total_v3/1e6:>9.2f}M" if total_v3 else "N/A"
        v4_total = f"{total_v4/1e6:>9.2f}M" if total_v4 else "N/A"
        print(f"{'TOTAL':<28} {'':<10} {'':<10} {total_zstd/1e6:>9.2f}M {v3_total:>10} {v3_overall:>7.1f}% {v4_total:>10} {v4_overall:>7.1f}%")
    print("="*130)

if __name__ == '__main__':
    main()

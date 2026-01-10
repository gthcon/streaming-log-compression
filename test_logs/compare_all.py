#!/usr/bin/env python3
"""
Compare V10 codec against all baselines:
- zstd level 3 (fast)
- zstd level 19 (best)
- LogLite
- CLP IR + zstd-3
- CLP IR + zstd-19

External baselines are loaded from external_baselines.json to avoid re-running.
"""
import os
import subprocess
import tempfile
import json
import sys
from pathlib import Path

# Add test_logs to path
sys.path.insert(0, str(Path(__file__).parent))
from codec_v10 import encode_v10, decode_v10

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

LOGLITE_PATH = "/root/streaming-log-compression/LogLite/LogLite-B/src/tools/xorc-cli"
BASELINES_FILE = os.path.join(os.path.dirname(__file__), "external_baselines.json")

def get_file_size(path):
    return os.path.getsize(path)

def load_external_baselines():
    """Load cached external baseline results"""
    if os.path.exists(BASELINES_FILE):
        with open(BASELINES_FILE) as f:
            return json.load(f)
    return {}

def save_external_baselines(baselines):
    """Save external baseline results"""
    with open(BASELINES_FILE, 'w') as f:
        json.dump(baselines, f, indent=2)

def compress_zstd(filepath, level=19):
    """Compress with zstd and return compressed size"""
    with tempfile.NamedTemporaryFile(suffix='.zst', delete=False) as f:
        temp_out = f.name
    try:
        result = subprocess.run(
            ['zstd', f'-{level}', '-f', '-q', filepath, '-o', temp_out],
            capture_output=True, timeout=300
        )
        if result.returncode == 0:
            return get_file_size(temp_out)
    except Exception as e:
        pass
    finally:
        if os.path.exists(temp_out):
            os.unlink(temp_out)
    return None

def compress_loglite(filepath):
    """Compress with LogLite (xorc-cli) and return compressed size"""
    if not os.path.exists(LOGLITE_PATH):
        return None

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "out.loglite")
        try:
            result = subprocess.run(
                [LOGLITE_PATH, '--compress', '--file-path', filepath, '--com-output-path', out_path],
                capture_output=True, timeout=600
            )
            if os.path.exists(out_path):
                return get_file_size(out_path)
        except Exception as e:
            pass
    return None

def compress_clp_ir(filepath, zstd_level=19):
    """Compress with CLP IR format + zstd"""
    try:
        from clp_ffi_py.ir import FourByteEncoder
    except ImportError:
        return None

    # Read lines
    with open(filepath, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    # Encode to CLP IR
    encoder = FourByteEncoder()
    chunks = []

    # Preamble
    chunks.append(encoder.encode_preamble(0, "%Y-%m-%d %H:%M:%S", "UTC"))

    # Encode messages (using 0 timestamp delta for simplicity)
    for line in lines:
        chunks.append(encoder.encode_message_and_timestamp_delta(0, line.encode('utf-8', errors='replace')))

    # End of IR
    chunks.append(encoder.encode_end_of_ir())

    ir_data = b''.join(chunks)

    # Compress with zstd
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(ir_data)
        temp_in = f.name

    with tempfile.NamedTemporaryFile(suffix='.zst', delete=False) as f:
        temp_out = f.name

    try:
        result = subprocess.run(
            ['zstd', f'-{zstd_level}', '-f', '-q', temp_in, '-o', temp_out],
            capture_output=True, timeout=300
        )
        if result.returncode == 0:
            return get_file_size(temp_out)
    except Exception as e:
        pass
    finally:
        if os.path.exists(temp_in):
            os.unlink(temp_in)
        if os.path.exists(temp_out):
            os.unlink(temp_out)
    return None

def compress_v10_zstd(filepath, zstd_level=19, long_mode=False):
    """Compress with V10 + zstd and return compressed size"""
    with open(filepath, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    try:
        encoded = encode_v10(lines)
    except Exception as e:
        return None

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(encoded)
        temp_in = f.name

    with tempfile.NamedTemporaryFile(suffix='.zst', delete=False) as f:
        temp_out = f.name

    try:
        cmd = ['zstd', f'-{zstd_level}', '-f', '-q', temp_in, '-o', temp_out]
        if long_mode:
            cmd.insert(2, '--long=27')
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        if result.returncode == 0:
            return get_file_size(temp_out)
    except Exception as e:
        pass
    finally:
        if os.path.exists(temp_in):
            os.unlink(temp_in)
        if os.path.exists(temp_out):
            os.unlink(temp_out)
    return None

def compress_v10_best_zstd(filepath, zstd_level=3, long_mode=True):
    """Compress with best of (raw, V10) + zstd-long - optimal for fast mode"""
    with open(filepath, 'r', errors='replace') as f:
        lines = [l.rstrip('\n') for l in f]

    raw_text = '\n'.join(lines).encode('utf-8')

    try:
        encoded = encode_v10(lines)
    except Exception as e:
        encoded = raw_text

    def compress(data):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            temp_in = f.name
        with tempfile.NamedTemporaryFile(suffix='.zst', delete=False) as f:
            temp_out = f.name
        try:
            cmd = ['zstd', f'-{zstd_level}', '-f', '-q', temp_in, '-o', temp_out]
            if long_mode:
                cmd.insert(2, '--long=27')
            result = subprocess.run(cmd, capture_output=True, timeout=300)
            if result.returncode == 0:
                return get_file_size(temp_out)
        except:
            pass
        finally:
            if os.path.exists(temp_in):
                os.unlink(temp_in)
            if os.path.exists(temp_out):
                os.unlink(temp_out)
        return None

    raw_size = compress(raw_text)
    v10_size = compress(encoded)

    if raw_size is None:
        return v10_size
    if v10_size is None:
        return raw_size
    return min(raw_size, v10_size)

def main():
    # Check for --rerun-external flag
    rerun_external = '--rerun-external' in sys.argv

    # Load cached baselines
    baselines = load_external_baselines()
    if baselines and not rerun_external:
        print("Using cached external baselines from external_baselines.json")
        print("(Use --rerun-external to re-run external compressors)\n")

    print("=" * 160)
    print("COMPREHENSIVE COMPRESSION COMPARISON: V10 vs zstd vs LogLite vs CLP-IR")
    print("=" * 160)

    results = {}

    # Header
    print(f"{'File':<28} {'Size':>7} {'zstd-3':>8} {'zstd-19':>8} {'LogLite':>8} {'CLP+z3':>8} {'CLP+z19':>8} {'V10+z3':>8} {'V10+z19':>8} {'V10fast':>8} {'Best':>10}")
    print("-" * 175)

    for filename in TEST_FILES:
        filepath = os.path.join(os.path.dirname(__file__), filename)
        if not os.path.exists(filepath):
            print(f"{filename:<28} NOT FOUND")
            continue

        orig_size = get_file_size(filepath)
        orig_mb = orig_size / (1024 * 1024)

        # Run compressors
        print(f"{filename:<28} {orig_mb:>5.1f}MB ", end='', flush=True)

        # Get external baselines (cached or run)
        cached = baselines.get(filename, {})
        if cached and not rerun_external:
            zstd3 = cached.get('zstd_3')
            zstd19 = cached.get('zstd_19')
            loglite = cached.get('loglite')
            clp_ir_3 = cached.get('clp_ir_3')
            clp_ir_19 = cached.get('clp_ir') or cached.get('clp_ir_19')
        else:
            zstd3 = compress_zstd(filepath, level=3)
            zstd19 = compress_zstd(filepath, level=19)
            loglite = compress_loglite(filepath)
            clp_ir_3 = compress_clp_ir(filepath, zstd_level=3)
            clp_ir_19 = compress_clp_ir(filepath, zstd_level=19)

        # Always run V10 (it's what we're testing)
        v10_z3 = compress_v10_zstd(filepath, zstd_level=3)
        v10_z19 = compress_v10_zstd(filepath, zstd_level=19)
        v10_fast = compress_v10_best_zstd(filepath, zstd_level=3, long_mode=True)  # V10 fast mode

        # Calculate ratios
        def ratio(size):
            if size is None:
                return None
            return size / orig_size * 100

        r_zstd3 = ratio(zstd3)
        r_zstd19 = ratio(zstd19)
        r_loglite = ratio(loglite)
        r_clp_ir_3 = ratio(clp_ir_3)
        r_clp_ir_19 = ratio(clp_ir_19)
        r_v10_z3 = ratio(v10_z3)
        r_v10_z19 = ratio(v10_z19)
        r_v10_fast = ratio(v10_fast)

        # Find best
        ratios = {
            'zstd-3': r_zstd3,
            'zstd-19': r_zstd19,
            'LogLite': r_loglite,
            'CLP+z3': r_clp_ir_3,
            'CLP+z19': r_clp_ir_19,
            'V10+z3': r_v10_z3,
            'V10+z19': r_v10_z19,
            'V10fast': r_v10_fast,
        }
        valid_ratios = {k: v for k, v in ratios.items() if v is not None}
        best = min(valid_ratios, key=valid_ratios.get) if valid_ratios else 'N/A'

        # Format output
        def fmt(r):
            return f"{r:>7.2f}%" if r is not None else "    N/A "

        print(f"{fmt(r_zstd3)} {fmt(r_zstd19)} {fmt(r_loglite)} {fmt(r_clp_ir_3)} {fmt(r_clp_ir_19)} {fmt(r_v10_z3)} {fmt(r_v10_z19)} {fmt(r_v10_fast)} {best:>10}")

        results[filename] = {
            'original_size': orig_size,
            'zstd_3': zstd3,
            'zstd_19': zstd19,
            'loglite': loglite,
            'clp_ir_3': clp_ir_3,
            'clp_ir_19': clp_ir_19,
            'v10_zstd_3': v10_z3,
            'v10_zstd_19': v10_z19,
            'v10_fast': v10_fast,
        }

    print("-" * 175)

    # Summary stats
    print("\nAVERAGE COMPRESSION RATIOS:")
    methods = [
        ('zstd_3', 'zstd -3'),
        ('zstd_19', 'zstd -19'),
        ('loglite', 'LogLite'),
        ('clp_ir_3', 'CLP-IR+zstd-3'),
        ('clp_ir_19', 'CLP-IR+zstd-19'),
        ('v10_zstd_3', 'V10+zstd-3'),
        ('v10_zstd_19', 'V10+zstd-19'),
        ('v10_fast', 'V10-fast (z3+long)'),
    ]

    for method, name in methods:
        total = sum(r[method] for r in results.values() if r.get(method) is not None)
        count = sum(1 for r in results.values() if r.get(method) is not None)
        if count > 0:
            total_orig = sum(r['original_size'] for r in results.values() if r.get(method) is not None)
            ratio = total / total_orig * 100
            print(f"  {name:<20}: {ratio:>6.2f}% ({count} files)")

    # Win/Tie/Loss analysis for V10-fast vs zstd-19 (the key comparison)
    print("\nV10-fast vs zstd-19 (CAN FAST MODE BEAT BEST COMPRESSION?):")
    wins = ties = losses = 0
    for r in results.values():
        if r.get('v10_fast') is None or r.get('zstd_19') is None:
            continue
        v10_ratio = r['v10_fast'] / r['original_size']
        other_ratio = r['zstd_19'] / r['original_size']
        if abs(v10_ratio - other_ratio) < 0.0001:
            ties += 1
        elif v10_ratio < other_ratio:
            wins += 1
        else:
            losses += 1
    print(f"  V10-fast vs zstd-19: {wins} wins, {ties} ties, {losses} losses")

    # Win/Tie/Loss analysis
    print("\nV10+zstd-19 vs OTHER METHODS:")
    for method, name in methods:
        if method == 'v10_zstd_19':
            continue
        wins = ties = losses = 0
        for r in results.values():
            if r.get('v10_zstd_19') is None or r.get(method) is None:
                continue
            v10_ratio = r['v10_zstd_19'] / r['original_size']
            other_ratio = r[method] / r['original_size']
            if abs(v10_ratio - other_ratio) < 0.0001:  # Within 0.01%
                ties += 1
            elif v10_ratio < other_ratio:
                wins += 1
            else:
                losses += 1
        total = wins + ties + losses
        if total > 0:
            print(f"  vs {name:<20}: {wins} wins, {ties} ties, {losses} losses")

    # Save results
    with open('comparison_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to comparison_results.json")

if __name__ == "__main__":
    main()

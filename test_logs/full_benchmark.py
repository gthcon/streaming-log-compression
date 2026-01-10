#!/usr/bin/env python3
"""
Full benchmark comparing: zstd-3, V3+zstd, V4+zstd, LogLite-B, LogLite-BZ
"""
import os
import sys
import time
import subprocess
import json
import tempfile

# Add paths
sys.path.insert(0, '/root/streaming-log-compression/test_logs')

LOGLITE_BIN = "/root/streaming-log-compression/LogLite/LogLite-B/src/loglite-B"

def get_file_size(path):
    return os.path.getsize(path) if os.path.exists(path) else 0

def compress_zstd(input_path, level=3):
    """Compress with zstd"""
    with tempfile.NamedTemporaryFile(suffix='.zst', delete=False) as f:
        out_path = f.name
    start = time.time()
    subprocess.run(['zstd', f'-{level}', '-f', '-q', input_path, '-o', out_path], check=True)
    elapsed = time.time() - start
    size = get_file_size(out_path)
    os.unlink(out_path)
    return size, elapsed

def compress_loglite(input_path):
    """Compress with LogLite-B"""
    with tempfile.NamedTemporaryFile(suffix='.loglite', delete=False) as f:
        out_path = f.name
    with tempfile.NamedTemporaryFile(suffix='.dec', delete=False) as f:
        dec_path = f.name
    
    start = time.time()
    result = subprocess.run([
        LOGLITE_BIN, '--compress',
        '--file-path', input_path,
        '--com-output-path', out_path
    ], capture_output=True, text=True, timeout=300)
    elapsed = time.time() - start
    
    size = get_file_size(out_path)
    os.unlink(out_path) if os.path.exists(out_path) else None
    os.unlink(dec_path) if os.path.exists(dec_path) else None
    return size, elapsed

def compress_loglite_zstd(input_path):
    """Compress with LogLite-B + zstd"""
    with tempfile.NamedTemporaryFile(suffix='.loglite', delete=False) as f:
        out_path = f.name
    
    subprocess.run([
        LOGLITE_BIN, '--compress',
        '--file-path', input_path,
        '--com-output-path', out_path
    ], capture_output=True, timeout=300)
    
    # Now zstd compress the loglite output
    zst_path = out_path + '.zst'
    start = time.time()
    subprocess.run(['zstd', '-3', '-f', '-q', out_path, '-o', zst_path], check=True)
    elapsed = time.time() - start
    
    size = get_file_size(zst_path)
    os.unlink(out_path) if os.path.exists(out_path) else None
    os.unlink(zst_path) if os.path.exists(zst_path) else None
    return size, elapsed

def is_json_log(filepath):
    """Check if log is JSON format"""
    with open(filepath, 'r', errors='ignore') as f:
        first_line = f.readline().strip()
        try:
            json.loads(first_line)
            return True
        except:
            return False

def compress_clp(input_path):
    """Compress with CLP KV-IR + zstd (for JSON only)"""
    if not is_json_log(input_path):
        return None, None

    try:
        from clp_ffi_py.ir import Serializer
        import msgpack
        import io
        import zstandard as zstd

        with open(input_path, 'r') as f:
            lines = [l.rstrip('\n') for l in f]

        start = time.time()
        with io.BytesIO() as buf:
            serializer = Serializer(buf)
            for line in lines:
                try:
                    obj = json.loads(line)
                    user_gen = msgpack.packb(obj)
                    auto_gen = msgpack.packb({})
                    serializer.serialize_log_event_from_msgpack_map(auto_gen, user_gen)
                except:
                    pass
            serializer.flush()
            clp_data = buf.getvalue()

        # CLP IR + zstd for fair comparison
        compressed = zstd.compress(clp_data, level=3)
        elapsed = time.time() - start

        return len(compressed), elapsed
    except Exception as e:
        return None, None

def compress_v3(input_path):
    """Compress with V3 codec + zstd"""
    if not is_json_log(input_path):
        return None, None

    try:
        from json_codec_v3 import verify_file
        import zstandard as zstd
        import io
        import sys

        # Suppress output
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()

        start = time.time()
        success, v3_data = verify_file(input_path)
        elapsed = time.time() - start

        sys.stdout = old_stdout

        if not success or v3_data is None:
            return None, None
        compressed = zstd.compress(v3_data, level=3)

        return len(compressed), elapsed
    except Exception as e:
        sys.stdout = old_stdout if 'old_stdout' in dir() else sys.stdout
        return None, None

def compress_v4(input_path):
    """Compress with V4 codec + zstd"""
    if not is_json_log(input_path):
        return None, None

    try:
        from json_codec_v4 import verify_file_v4
        import zstandard as zstd
        import io
        import sys

        # Suppress output
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()

        start = time.time()
        success, v4_data = verify_file_v4(input_path)
        elapsed = time.time() - start

        sys.stdout = old_stdout

        if not success or v4_data is None:
            return None, None
        compressed = zstd.compress(bytes(v4_data), level=3)

        return len(compressed), elapsed
    except Exception as e:
        sys.stdout = old_stdout if 'old_stdout' in dir() else sys.stdout
        return None, None

def compress_drain(input_path):
    """Compress with Drain v4 codec + zstd (for text logs)"""
    if is_json_log(input_path):
        return None, None

    try:
        from drain_lossless_v4 import verify_file
        import zstandard as zstd
        import io
        import sys

        # Suppress output
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()

        start = time.time()
        success, drain_data = verify_file(input_path)
        elapsed = time.time() - start

        sys.stdout = old_stdout

        if not success or drain_data is None:
            return None, None
        compressed = zstd.compress(drain_data, level=3)

        return len(compressed), elapsed
    except Exception as e:
        sys.stdout = old_stdout if 'old_stdout' in dir() else sys.stdout
        return None, None

def compress_v5(input_path):
    """Compress with V5 unified codec + zstd"""
    try:
        from codec_v5 import encode_v5
        import zstandard as zstd

        with open(input_path, 'r', errors='replace') as f:
            lines = [l.rstrip('\n') for l in f]

        start = time.time()
        v5_data = encode_v5(lines)
        elapsed = time.time() - start

        compressed = zstd.compress(v5_data, level=3)
        return len(compressed), elapsed
    except Exception as e:
        return None, None

def compress_v6(input_path):
    """Compress with V6 recursive unified codec + zstd"""
    try:
        from codec_v6 import encode_v6
        import zstandard as zstd

        with open(input_path, 'r', errors='replace') as f:
            lines = [l.rstrip('\n') for l in f]

        start = time.time()
        v6_data = encode_v6(lines)
        elapsed = time.time() - start

        compressed = zstd.compress(v6_data, level=3)
        return len(compressed), elapsed
    except Exception as e:
        return None, None

def compress_v7(input_path):
    """Compress with V7 ultimate codec + zstd"""
    try:
        from codec_v7 import encode_v7
        import zstandard as zstd

        with open(input_path, 'r', errors='replace') as f:
            lines = [l.rstrip('\n') for l in f]

        start = time.time()
        v7_data = encode_v7(lines)
        elapsed = time.time() - start

        compressed = zstd.compress(v7_data, level=3)
        return len(compressed), elapsed
    except Exception as e:
        return None, None

def compress_v8(input_path):
    """Compress with V8 XOR delta codec + zstd"""
    try:
        from codec_v8 import encode_v8
        import zstandard as zstd

        with open(input_path, 'r', errors='replace') as f:
            lines = [l.rstrip('\n') for l in f]

        start = time.time()
        v8_data = encode_v8(lines)
        elapsed = time.time() - start

        compressed = zstd.compress(v8_data, level=3)
        return len(compressed), elapsed
    except Exception as e:
        return None, None

def compress_v10(input_path):
    """Compress with V10 LogLite-style hybrid codec + zstd"""
    try:
        from codec_v10 import encode_v10
        import zstandard as zstd

        with open(input_path, 'r', errors='replace') as f:
            lines = [l.rstrip('\n') for l in f]

        start = time.time()
        v10_data = encode_v10(lines)
        elapsed = time.time() - start

        compressed = zstd.compress(v10_data, level=3)
        return len(compressed), elapsed
    except Exception as e:
        import traceback
        traceback.print_exc()
        return None, None

def format_size(size):
    if size is None:
        return "N/A"
    if size >= 1024*1024:
        return f"{size/1024/1024:.2f}M"
    elif size >= 1024:
        return f"{size/1024:.1f}K"
    return f"{size}B"

def format_ratio(compressed, original):
    if compressed is None:
        return "N/A"
    return f"{compressed/original*100:.1f}%"

def main():
    log_files = sorted([f for f in os.listdir('.') if f.endswith('_50mb.log')])

    print("=" * 260)
    print("FULL BENCHMARK: zstd-3, LogLite-BZ, CLP+zstd, V3+zstd, V6+zstd, V10+zstd, Drain+zstd")
    print("=" * 260)
    print(f"{'File':<30} {'Orig':>8} {'zstd-3':>10} {'LL+zst':>10} {'CLP+zst':>10} {'V3+zst':>10} {'V6+zst':>10} {'V10+zst':>10} {'Drain':>10} {'Best':>10}")
    print("-" * 260)

    totals = {'orig': 0, 'zstd': 0, 'loglite_zstd': 0, 'clp': 0, 'v3': 0, 'v6': 0, 'v10': 0, 'drain': 0}

    for logfile in log_files:
        orig_size = get_file_size(logfile)
        totals['orig'] += orig_size

        print(f"{logfile:<30} {format_size(orig_size):>8}", end='', flush=True)

        # zstd-3
        zstd_size, _ = compress_zstd(logfile)
        totals['zstd'] += zstd_size
        print(f" {format_ratio(zstd_size, orig_size):>10}", end='', flush=True)

        # LogLite-B + zstd
        llz_size, _ = compress_loglite_zstd(logfile)
        if llz_size: totals['loglite_zstd'] += llz_size
        print(f" {format_ratio(llz_size, orig_size):>10}", end='', flush=True)

        # CLP+zstd (JSON only)
        clp_size, _ = compress_clp(logfile)
        if clp_size: totals['clp'] += clp_size
        print(f" {format_ratio(clp_size, orig_size):>10}", end='', flush=True)

        # V3+zstd (JSON only)
        v3_size, _ = compress_v3(logfile)
        if v3_size: totals['v3'] += v3_size
        print(f" {format_ratio(v3_size, orig_size):>10}", end='', flush=True)

        # V6+zstd (all logs)
        v6_size, _ = compress_v6(logfile)
        if v6_size: totals['v6'] += v6_size
        print(f" {format_ratio(v6_size, orig_size):>10}", end='', flush=True)

        # V10+zstd (all logs - LogLite-style hybrid)
        v10_size, _ = compress_v10(logfile)
        if v10_size: totals['v10'] += v10_size
        print(f" {format_ratio(v10_size, orig_size):>10}", end='', flush=True)

        # Drain+zstd (text logs only)
        drain_size, _ = compress_drain(logfile)
        if drain_size: totals['drain'] += drain_size
        print(f" {format_ratio(drain_size, orig_size):>10}", end='', flush=True)

        # Find best
        results = {'zstd': zstd_size, 'LL+zst': llz_size, 'CLP': clp_size, 'V3': v3_size, 'V6': v6_size, 'V10': v10_size, 'Drain': drain_size}
        valid = {k: v for k, v in results.items() if v is not None and v > 0}
        if valid:
            best = min(valid, key=valid.get)
            print(f" {best:>10}")
        else:
            print(f" {'N/A':>10}")

    print("-" * 260)
    print(f"{'TOTAL':<30} {format_size(totals['orig']):>8}", end='')
    print(f" {format_ratio(totals['zstd'], totals['orig']):>10}", end='')
    print(f" {format_ratio(totals['loglite_zstd'] or None, totals['orig']):>10}", end='')
    print(f" {format_ratio(totals['clp'] or None, totals['orig']):>10}", end='')
    print(f" {format_ratio(totals['v3'] or None, totals['orig']):>10}", end='')
    print(f" {format_ratio(totals['v6'] or None, totals['orig']):>10}", end='')
    print(f" {format_ratio(totals['v10'] or None, totals['orig']):>10}", end='')
    print(f" {format_ratio(totals['drain'] or None, totals['orig']):>10}")
    print("=" * 260)

if __name__ == '__main__':
    main()

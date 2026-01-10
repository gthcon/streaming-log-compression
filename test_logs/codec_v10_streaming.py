#!/usr/bin/env python3
"""
V10 Streaming Codec - Streaming version of V10-fast

Key features:
1. Processes logs in configurable chunk sizes (default 10K lines)
2. Each chunk is independently decodable after zstd decompression
3. zstd applied once at the end with --long=27 for cross-chunk pattern matching
4. Picks best of raw vs V10 encoding per-chunk (before zstd)
5. Supports both file and iterator input

Format (before zstd compression):
  [4 bytes] MAGIC: "LGS1" (Log Stream v1)
  [1 byte]  VERSION
  [varint]  chunk_size (lines per chunk)
  [chunks...]

Each chunk:
  [1 byte]  chunk_type (0=raw, 1=v10_text, 2=v10_json)
  [varint]  n_lines in chunk
  [varint]  uncompressed_size
  [bytes]   chunk data (NOT zstd compressed - zstd applied at end)

The entire stream is then zstd compressed with --long=27 for best cross-chunk matching.
"""

import sys
import struct
import subprocess
import tempfile
import os
from io import BytesIO
from typing import Iterator, List, Optional, Tuple, BinaryIO

# Import V10 codec
sys.path.insert(0, os.path.dirname(__file__))
from codec_v10 import (
    encode_v10, decode_v10,
    encode_text_logs, decode_text_logs,
    encode_json_columnar, decode_json_columnar,
    encode_varint, decode_varint,
    detect_format, FMT_JSON, FMT_TEXT, FMT_RAW,
    MAGIC as V10_MAGIC
)

# Streaming codec constants
STREAM_MAGIC = b'LGS1'
STREAM_VERSION = 1

# Chunk types
CHUNK_RAW = 0
CHUNK_V10_TEXT = 1
CHUNK_V10_JSON = 2

# Default chunk size (lines)
DEFAULT_CHUNK_SIZE = 10000

# zstd settings for fast mode
ZSTD_LEVEL = 3
ZSTD_LONG = 27


def compress_zstd_streaming(data: bytes, level: int = ZSTD_LEVEL, long_mode: int = ZSTD_LONG) -> bytes:
    """Compress data with zstd using streaming-friendly settings."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        temp_in = f.name
    with tempfile.NamedTemporaryFile(suffix='.zst', delete=False) as f:
        temp_out = f.name

    try:
        cmd = ['zstd', f'-{level}', '-f', '-q', temp_in, '-o', temp_out]
        if long_mode:
            cmd.insert(2, f'--long={long_mode}')
        result = subprocess.run(cmd, capture_output=True, timeout=60)
        if result.returncode == 0:
            with open(temp_out, 'rb') as f:
                return f.read()
    finally:
        if os.path.exists(temp_in):
            os.unlink(temp_in)
        if os.path.exists(temp_out):
            os.unlink(temp_out)
    return None


def decompress_zstd(data: bytes) -> bytes:
    """Decompress zstd data."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        temp_in = f.name
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_out = f.name

    try:
        result = subprocess.run(
            ['zstd', '-d', '-f', '-q', temp_in, '-o', temp_out],
            capture_output=True, timeout=60
        )
        if result.returncode == 0:
            with open(temp_out, 'rb') as f:
                return f.read()
    finally:
        if os.path.exists(temp_in):
            os.unlink(temp_in)
        if os.path.exists(temp_out):
            os.unlink(temp_out)
    return None


def encode_chunk(lines: List[str]) -> Tuple[int, bytes]:
    """
    Encode a chunk of lines, picking the best encoding.
    Returns (chunk_type, encoded_data) - data is NOT zstd compressed here.

    IMPORTANT: V10 encoding is verified for losslessness before use.
    If V10 produces lossy output, we fall back to raw encoding.
    """
    if not lines:
        return CHUNK_RAW, b''

    # Try raw encoding (always works, always lossless)
    raw_data = '\n'.join(lines).encode('utf-8')

    best_type = CHUNK_RAW
    best_data = raw_data
    best_size = len(raw_data)

    # Try V10 encoding (text or JSON, automatically detected)
    try:
        v10_data = encode_v10(lines)

        # CRITICAL: Verify V10 encoding is lossless before using it
        v10_decoded = decode_v10(v10_data)
        is_lossless = (
            len(v10_decoded) == len(lines) and
            all(v10_decoded[i] == lines[i] for i in range(len(lines)))
        )

        if is_lossless and len(v10_data) < best_size:
            # Detect format for chunk type
            fmt = detect_format(lines)
            best_type = CHUNK_V10_JSON if fmt == FMT_JSON else CHUNK_V10_TEXT
            best_data = v10_data
            best_size = len(v10_data)
    except Exception:
        pass

    return best_type, best_data


def decode_chunk(chunk_type: int, data: bytes) -> List[str]:
    """Decode a chunk back to lines. Data is already decompressed."""
    if not data:
        return []

    if chunk_type == CHUNK_RAW:
        return data.decode('utf-8').split('\n')
    elif chunk_type in (CHUNK_V10_TEXT, CHUNK_V10_JSON):
        return decode_v10(data)
    else:
        raise ValueError(f"Unknown chunk type: {chunk_type}")


class StreamingEncoder:
    """
    Streaming encoder that processes lines in chunks.

    Usage:
        encoder = StreamingEncoder(output_file, chunk_size=10000)
        for line in lines:
            encoder.write_line(line)
        encoder.close()

    Or with context manager:
        with StreamingEncoder(output_file) as encoder:
            for line in lines:
                encoder.write_line(line)
    """

    def __init__(self, output: BinaryIO, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.output = output
        self.chunk_size = chunk_size
        self.buffer: List[str] = []
        self.total_lines = 0
        self.total_chunks = 0
        self.header_written = False

    def _write_header(self):
        """Write stream header."""
        if self.header_written:
            return
        self.output.write(STREAM_MAGIC)
        self.output.write(bytes([STREAM_VERSION]))
        self.output.write(encode_varint(self.chunk_size))
        self.header_written = True

    def _flush_chunk(self):
        """Encode and write the current buffer as a chunk."""
        if not self.buffer:
            return

        self._write_header()

        chunk_type, compressed_data = encode_chunk(self.buffer)
        n_lines = len(self.buffer)

        # Write chunk header
        self.output.write(bytes([chunk_type]))
        self.output.write(encode_varint(n_lines))
        self.output.write(encode_varint(len(compressed_data)))
        self.output.write(compressed_data)

        self.total_lines += n_lines
        self.total_chunks += 1
        self.buffer = []

    def write_line(self, line: str):
        """Add a line to the stream."""
        self.buffer.append(line.rstrip('\n'))
        if len(self.buffer) >= self.chunk_size:
            self._flush_chunk()

    def write_lines(self, lines: Iterator[str]):
        """Add multiple lines to the stream."""
        for line in lines:
            self.write_line(line)

    def close(self):
        """Flush remaining buffer and close."""
        self._flush_chunk()
        # Write end marker (empty chunk)
        if self.header_written:
            self.output.write(bytes([CHUNK_RAW]))
            self.output.write(encode_varint(0))
            self.output.write(encode_varint(0))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class StreamingDecoder:
    """
    Streaming decoder that yields lines from chunks.

    Usage:
        decoder = StreamingDecoder(input_file)
        for line in decoder:
            process(line)

    Or read all at once:
        lines = list(StreamingDecoder(input_file))
    """

    def __init__(self, input_data: BinaryIO):
        self.input = input_data
        self.data = input_data.read()
        self.pos = 0
        self.chunk_size = 0
        self._read_header()

    def _read_header(self):
        """Read and validate stream header."""
        if self.data[self.pos:self.pos+4] != STREAM_MAGIC:
            raise ValueError(f"Invalid stream magic: {self.data[self.pos:self.pos+4]}")
        self.pos += 4

        version = self.data[self.pos]
        if version != STREAM_VERSION:
            raise ValueError(f"Unsupported stream version: {version}")
        self.pos += 1

        self.chunk_size, self.pos = decode_varint(self.data, self.pos)

    def _read_chunk(self) -> Optional[List[str]]:
        """Read and decode the next chunk. Returns None at end of stream."""
        if self.pos >= len(self.data):
            return None

        chunk_type = self.data[self.pos]
        self.pos += 1

        n_lines, self.pos = decode_varint(self.data, self.pos)
        compressed_size, self.pos = decode_varint(self.data, self.pos)

        if n_lines == 0 and compressed_size == 0:
            return None  # End marker

        compressed_data = self.data[self.pos:self.pos + compressed_size]
        self.pos += compressed_size

        return decode_chunk(chunk_type, compressed_data)

    def __iter__(self):
        """Yield lines one at a time."""
        while True:
            chunk = self._read_chunk()
            if chunk is None:
                break
            for line in chunk:
                yield line

    def read_all(self) -> List[str]:
        """Read all lines at once."""
        return list(self)


def encode_streaming(lines: Iterator[str], output: BinaryIO, chunk_size: int = DEFAULT_CHUNK_SIZE):
    """
    Encode lines to a streaming format.

    Args:
        lines: Iterator of log lines
        output: Binary output stream
        chunk_size: Number of lines per chunk
    """
    with StreamingEncoder(output, chunk_size) as encoder:
        encoder.write_lines(lines)


def decode_streaming(input_data: BinaryIO) -> Iterator[str]:
    """
    Decode a streaming format back to lines.

    Args:
        input_data: Binary input stream

    Yields:
        Log lines
    """
    decoder = StreamingDecoder(input_data)
    yield from decoder


def encode_file_streaming(input_path: str, output_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> dict:
    """
    Encode a file using streaming compression.

    Returns dict with stats.
    """
    with open(input_path, 'r', errors='replace') as f_in:
        with open(output_path, 'wb') as f_out:
            encoder = StreamingEncoder(f_out, chunk_size)
            for line in f_in:
                encoder.write_line(line)
            encoder.close()

    orig_size = os.path.getsize(input_path)
    compressed_size = os.path.getsize(output_path)

    return {
        'original_size': orig_size,
        'compressed_size': compressed_size,
        'ratio': compressed_size / orig_size * 100,
        'total_lines': encoder.total_lines,
        'total_chunks': encoder.total_chunks,
    }


def decode_file_streaming(input_path: str, output_path: str) -> dict:
    """
    Decode a streaming-compressed file.

    Returns dict with stats.
    """
    with open(input_path, 'rb') as f_in:
        decoder = StreamingDecoder(f_in)
        with open(output_path, 'w') as f_out:
            line_count = 0
            for line in decoder:
                f_out.write(line + '\n')
                line_count += 1

    return {
        'lines': line_count,
    }


def verify_streaming(input_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bool:
    """Verify that streaming encode/decode is lossless."""
    # Read original
    with open(input_path, 'r', errors='replace') as f:
        original_lines = [l.rstrip('\n') for l in f]

    # Encode
    output = BytesIO()
    with StreamingEncoder(output, chunk_size) as encoder:
        for line in original_lines:
            encoder.write_line(line)

    # Decode
    output.seek(0)
    decoded_lines = list(StreamingDecoder(output))

    # Compare
    if len(original_lines) != len(decoded_lines):
        print(f"Line count mismatch: {len(original_lines)} vs {len(decoded_lines)}")
        return False

    for i, (orig, dec) in enumerate(zip(original_lines, decoded_lines)):
        if orig != dec:
            print(f"Line {i} mismatch:")
            print(f"  Original: {orig[:100]}...")
            print(f"  Decoded:  {dec[:100]}...")
            return False

    return True


if __name__ == '__main__':
    import time

    # Test files
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

    print("V10 Streaming Codec Benchmark (with zstd-3 --long=27)")
    print("=" * 90)
    print(f"{'File':<28} {'Size':>8} {'PreZstd':>9} {'Final':>8} {'Lines':>10} {'Chunks':>8} {'Time':>8}")
    print("-" * 90)

    for filename in TEST_FILES:
        if not os.path.exists(filename):
            continue

        start = time.time()

        # Verify lossless first
        if not verify_streaming(filename, chunk_size=10000):
            print(f"{filename:<28} VERIFICATION FAILED")
            continue

        # Benchmark - encode to stream format
        output = BytesIO()
        with open(filename, 'r', errors='replace') as f:
            with StreamingEncoder(output, chunk_size=10000) as encoder:
                for line in f:
                    encoder.write_line(line)

        # Apply zstd compression with --long=27
        stream_data = output.getvalue()
        compressed_data = compress_zstd_streaming(stream_data, level=ZSTD_LEVEL, long_mode=ZSTD_LONG)

        elapsed = time.time() - start
        orig_size = os.path.getsize(filename)
        pre_zstd_size = len(stream_data)
        final_size = len(compressed_data) if compressed_data else pre_zstd_size
        pre_ratio = pre_zstd_size / orig_size * 100
        final_ratio = final_size / orig_size * 100

        print(f"{filename:<28} {orig_size/1024/1024:>6.1f}MB {pre_ratio:>8.1f}% {final_ratio:>7.2f}% {encoder.total_lines:>10,} {encoder.total_chunks:>8} {elapsed:>7.1f}s")

    print("-" * 90)

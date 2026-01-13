#!/bin/bash
cd /root/streaming-log-compression/v10-rs
echo "=== SPEED BENCHMARK ==="
echo ""

for f in ../test_logs/hdfs_50mb.log ../test_logs/thunderbird_50mb.log; do
  name=$(basename "$f")
  size=$(stat -c%s "$f")
  size_mb=$(echo "scale=1; $size / 1048576" | bc)

  echo "File: $name ($size_mb MB)"

  # Rust V10 compression
  echo -n "  Rust V10 compress: "
  start=$(date +%s.%N)
  ./target/release/v10c compress "$f" /tmp/test.v10rs 2>/dev/null
  end=$(date +%s.%N)
  elapsed=$(echo "$end - $start" | bc)
  speed=$(echo "scale=1; $size_mb / $elapsed" | bc)
  echo "${elapsed}s (${speed} MB/s)"

  # Rust V10 decompression
  echo -n "  Rust V10 decompress: "
  start=$(date +%s.%N)
  ./target/release/v10c decompress /tmp/test.v10rs /tmp/out.log 2>/dev/null
  end=$(date +%s.%N)
  elapsed=$(echo "$end - $start" | bc)
  speed=$(echo "scale=1; $size_mb / $elapsed" | bc)
  echo "${elapsed}s (${speed} MB/s)"

  # zstd compression
  echo -n "  zstd-3 compress: "
  start=$(date +%s.%N)
  zstd -3 -f "$f" -o /tmp/test.zst 2>/dev/null
  end=$(date +%s.%N)
  elapsed=$(echo "$end - $start" | bc)
  speed=$(echo "scale=1; $size_mb / $elapsed" | bc)
  echo "${elapsed}s (${speed} MB/s)"

  # zstd decompression
  echo -n "  zstd decompress: "
  start=$(date +%s.%N)
  zstd -d -f /tmp/test.zst -o /tmp/out.log 2>/dev/null
  end=$(date +%s.%N)
  elapsed=$(echo "$end - $start" | bc)
  speed=$(echo "scale=1; $size_mb / $elapsed" | bc)
  echo "${elapsed}s (${speed} MB/s)"

  echo ""
done

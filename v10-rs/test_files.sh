#!/bin/bash
set -e

cd /root/streaming-log-compression/v10-rs

for f in ../test_logs/nginx_json_50mb.log ../test_logs/hdfs_50mb.log ../test_logs/thunderbird_50mb.log; do
  echo "=== $(basename "$f") ==="
  ./target/release/v10c compress "$f" /tmp/test.v10rs
  ./target/release/v10c decompress /tmp/test.v10rs /tmp/test_out.log
  if diff -q "$f" /tmp/test_out.log >/dev/null 2>&1; then
    original=$(stat -c%s "$f")
    compressed=$(stat -c%s /tmp/test.v10rs)
    ratio=$(echo "scale=2; $compressed * 100 / $original" | bc)
    echo "LOSSLESS OK - ${ratio}% of original ($original -> $compressed)"
  else
    echo "LOSSLESS FAIL"
  fi
  echo ""
done

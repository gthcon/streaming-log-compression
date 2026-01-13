#!/bin/bash
cd /root/streaming-log-compression/v10-rs

echo "=== LOSSLESS ROUNDTRIP TESTS ==="
for f in ../test_logs/nginx_1k.log ../test_logs/Spark.log ../test_logs/hdfs_50mb.log ../test_logs/thunderbird_50mb.log ../test_logs/nginx_json_50mb.log; do
  name=$(basename "$f")
  ./target/release/v10c compress "$f" /tmp/test.v10rs 2>&1 | head -1
  ./target/release/v10c decompress /tmp/test.v10rs /tmp/test_out.log 2>&1 > /dev/null
  if diff -q "$f" /tmp/test_out.log >/dev/null 2>&1; then
    original=$(stat -c%s "$f")
    compressed=$(stat -c%s /tmp/test.v10rs)
    ratio=$(echo "scale=2; $compressed * 100 / $original" | bc)
    echo "$name: LOSSLESS ✓ (${ratio}%)"
  else
    echo "$name: FAIL"
  fi
done

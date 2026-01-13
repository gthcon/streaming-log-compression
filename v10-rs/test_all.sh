#!/bin/bash
cd /root/streaming-log-compression/v10-rs
export PATH="$HOME/.cargo/bin:$PATH"

echo "=== LOSSLESS ROUNDTRIP TESTS ==="
for f in ../test_logs/*.log; do
  name=$(basename "$f")
  ./target/release/v10c compress "$f" /tmp/test.v10rs 2>/dev/null
  ./target/release/v10c decompress /tmp/test.v10rs /tmp/test_out.log 2>/dev/null
  if diff -q "$f" /tmp/test_out.log >/dev/null 2>&1; then
    original=$(stat -c%s "$f")
    compressed=$(stat -c%s /tmp/test.v10rs)
    ratio=$(echo "scale=3; $compressed * 100 / $original" | bc)
    echo "$name: OK ($ratio%)"
  else
    echo "$name: MISMATCH"
  fi
done

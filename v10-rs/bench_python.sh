#!/bin/bash
cd /root/streaming-log-compression
echo "=== PYTHON V10 BENCHMARK ==="
echo ""

for f in test_logs/hdfs_50mb.log test_logs/thunderbird_50mb.log; do
  name=$(basename "$f")
  size=$(stat -c%s "$f")
  size_mb=$(echo "scale=1; $size / 1048576" | bc)

  echo "File: $name ($size_mb MB)"

  # Python V10 compression
  echo -n "  Python V10 compress: "
  start=$(date +%s.%N)
  python3 test_logs/codec_v10_true_streaming.py compress "$f" /tmp/test.v10py 2>/dev/null
  end=$(date +%s.%N)
  elapsed=$(echo "$end - $start" | bc)
  speed=$(echo "scale=1; $size_mb / $elapsed" | bc)
  py_compressed=$(stat -c%s /tmp/test.v10py)
  py_ratio=$(echo "scale=2; $py_compressed * 100 / $size" | bc)
  echo "${elapsed}s (${speed} MB/s) -> ${py_ratio}%"

  echo ""
done

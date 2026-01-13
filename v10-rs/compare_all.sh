#!/bin/bash
# Compare Rust V10, Python V10, zstd, gzip across all test files
cd /root/streaming-log-compression/v10-rs

echo "=== COMPRESSION RATIO COMPARISON ==="
echo ""
printf "%-30s %10s %10s %10s %10s %10s\n" "File" "Original" "Rust-V10" "zstd-3" "zstd-19" "gzip"
printf "%-30s %10s %10s %10s %10s %10s\n" "----" "--------" "--------" "------" "-------" "----"

for f in ../test_logs/*.log; do
  name=$(basename "$f")
  size=$(stat -c%s "$f")

  # Skip very small files
  if [ $size -lt 1000 ]; then
    continue
  fi

  # Rust V10
  ./target/release/v10c compress "$f" /tmp/test.v10rs 2>/dev/null
  rust_size=$(stat -c%s /tmp/test.v10rs 2>/dev/null || echo "0")

  # zstd level 3
  zstd -3 -f "$f" -o /tmp/test.zst3 2>/dev/null
  zst3_size=$(stat -c%s /tmp/test.zst3 2>/dev/null || echo "0")

  # zstd level 19
  zstd -19 -f "$f" -o /tmp/test.zst19 2>/dev/null
  zst19_size=$(stat -c%s /tmp/test.zst19 2>/dev/null || echo "0")

  # gzip
  gzip -c "$f" > /tmp/test.gz 2>/dev/null
  gz_size=$(stat -c%s /tmp/test.gz 2>/dev/null || echo "0")

  # Calculate ratios
  rust_pct=$(echo "scale=2; $rust_size * 100 / $size" | bc)
  zst3_pct=$(echo "scale=2; $zst3_size * 100 / $size" | bc)
  zst19_pct=$(echo "scale=2; $zst19_size * 100 / $size" | bc)
  gz_pct=$(echo "scale=2; $gz_size * 100 / $size" | bc)

  # Format size
  if [ $size -gt 1048576 ]; then
    size_fmt="$(echo "scale=1; $size / 1048576" | bc)M"
  else
    size_fmt="$(echo "scale=1; $size / 1024" | bc)K"
  fi

  printf "%-30s %10s %9s%% %9s%% %9s%% %9s%%\n" "$name" "$size_fmt" "$rust_pct" "$zst3_pct" "$zst19_pct" "$gz_pct"
done

echo ""
echo "=== SUMMARY (50MB files) ==="
echo ""

# Summary for 50MB files only
total_orig=0
total_rust=0
total_zst3=0
total_zst19=0
total_gz=0

for f in ../test_logs/*_50mb.log; do
  if [ ! -f "$f" ]; then continue; fi

  size=$(stat -c%s "$f")
  total_orig=$((total_orig + size))

  ./target/release/v10c compress "$f" /tmp/test.v10rs 2>/dev/null
  rust_size=$(stat -c%s /tmp/test.v10rs 2>/dev/null || echo "0")
  total_rust=$((total_rust + rust_size))

  zstd -3 -f "$f" -o /tmp/test.zst3 2>/dev/null
  zst3_size=$(stat -c%s /tmp/test.zst3 2>/dev/null || echo "0")
  total_zst3=$((total_zst3 + zst3_size))

  zstd -19 -f "$f" -o /tmp/test.zst19 2>/dev/null
  zst19_size=$(stat -c%s /tmp/test.zst19 2>/dev/null || echo "0")
  total_zst19=$((total_zst19 + zst19_size))

  gzip -c "$f" > /tmp/test.gz 2>/dev/null
  gz_size=$(stat -c%s /tmp/test.gz 2>/dev/null || echo "0")
  total_gz=$((total_gz + gz_size))
done

echo "50MB files total:"
echo "  Original:  $(echo "scale=1; $total_orig / 1048576" | bc) MB"
echo "  Rust V10:  $(echo "scale=1; $total_rust / 1048576" | bc) MB ($(echo "scale=2; $total_rust * 100 / $total_orig" | bc)%)"
echo "  zstd-3:    $(echo "scale=1; $total_zst3 / 1048576" | bc) MB ($(echo "scale=2; $total_zst3 * 100 / $total_orig" | bc)%)"
echo "  zstd-19:   $(echo "scale=1; $total_zst19 / 1048576" | bc) MB ($(echo "scale=2; $total_zst19 * 100 / $total_orig" | bc)%)"
echo "  gzip:      $(echo "scale=1; $total_gz / 1048576" | bc) MB ($(echo "scale=2; $total_gz * 100 / $total_orig" | bc)%)"

# Cleanup
rm -f /tmp/test.v10rs /tmp/test.zst3 /tmp/test.zst19 /tmp/test.gz

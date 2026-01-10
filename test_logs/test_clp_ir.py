#!/usr/bin/env python3
"""
Test CLP's IR (Intermediate Representation) format compression.
This is what CLP uses internally before optional zstd compression.
"""
import sys
import time
from clp_ffi_py.ir import FourByteSerializer
import io

def compress_with_clp_ir(input_file):
    """Compress using CLP's four-byte IR format"""
    with open(input_file, 'r', errors='replace') as f:
        lines = f.readlines()

    print(f"Lines: {len(lines)}")

    # Calculate original size
    orig_size = sum(len(line.encode('utf-8')) for line in lines)
    print(f"Original size: {orig_size:,} bytes")

    start = time.time()

    # Use CLP's four-byte IR serializer
    output = bytearray()

    # Serialize preamble (positional args: ref_timestamp, timestamp_format, timezone)
    preamble = FourByteSerializer.serialize_preamble(0, "%Y-%m-%d %H:%M:%S", "UTC")
    output.extend(preamble)

    # Serialize each line
    prev_ts = 0
    for i, line in enumerate(lines):
        msg = line.rstrip('\n')
        # Use line number as timestamp (milliseconds)
        ts = i * 1000
        delta = ts - prev_ts
        prev_ts = ts

        try:
            # CLP expects bytes, not str
            msg_bytes = msg.encode('utf-8')
            serialized = FourByteSerializer.serialize_message_and_timestamp_delta(delta, msg_bytes)
            output.extend(serialized)
        except Exception as e:
            # Fallback: just serialize message without timestamp
            try:
                serialized = FourByteSerializer.serialize_message(msg_bytes)
                output.extend(serialized)
            except Exception as e2:
                if i < 5:  # Log first few errors
                    print(f"Error on line {i}: {e} / {e2}")

    # End of IR
    output.extend(FourByteSerializer.serialize_end_of_ir())

    encode_time = time.time() - start
    ir_size = len(output)

    print(f"Encode time: {encode_time:.2f}s ({len(lines)/encode_time:.0f} lines/sec)")
    print(f"CLP IR size: {ir_size:,} bytes ({ir_size*100/orig_size:.2f}%)")

    # Write IR to file
    ir_file = f"{input_file}.clp_ir"
    with open(ir_file, 'wb') as f:
        f.write(output)

    return ir_file, ir_size

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: test_clp_ir.py <logfile>")
        sys.exit(1)

    compress_with_clp_ir(sys.argv[1])

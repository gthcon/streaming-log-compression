//! Variable-length integer encoding (LEB128)
//!
//! Zero-allocation varint encoding/decoding.

use std::io::{self, Write, Read};

/// Encode a u64 as varint into a buffer. Returns number of bytes written.
#[inline]
pub fn encode(mut n: u64, buf: &mut [u8]) -> usize {
    let mut i = 0;
    while n >= 0x80 {
        buf[i] = (n as u8) | 0x80;
        n >>= 7;
        i += 1;
    }
    buf[i] = n as u8;
    i + 1
}

/// Decode a varint from a byte slice. Returns (value, bytes_consumed).
#[inline]
pub fn decode(buf: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut i = 0;

    loop {
        let b = buf[i];
        result |= ((b & 0x7F) as u64) << shift;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    (result, i)
}

/// Encode a signed i64 using zigzag encoding.
#[inline]
pub fn encode_signed(n: i64, buf: &mut [u8]) -> usize {
    // Zigzag encoding: (n << 1) ^ (n >> 63)
    let unsigned = ((n << 1) ^ (n >> 63)) as u64;
    encode(unsigned, buf)
}

/// Decode a signed i64 using zigzag encoding.
#[inline]
pub fn decode_signed(buf: &[u8]) -> (i64, usize) {
    let (val, len) = decode(buf);
    // Zigzag decoding: (val >> 1) ^ -((val & 1) as i64)
    let signed = ((val >> 1) as i64) ^ (-((val & 1) as i64));
    (signed, len)
}

/// Write a varint to a writer
#[inline]
pub fn write_varint<W: Write>(writer: &mut W, n: u64) -> io::Result<usize> {
    let mut buf = [0u8; 10];
    let len = encode(n, &mut buf);
    writer.write_all(&buf[..len])?;
    Ok(len)
}

/// Write a signed varint to a writer
#[inline]
pub fn write_signed<W: Write>(writer: &mut W, n: i64) -> io::Result<usize> {
    let mut buf = [0u8; 10];
    let len = encode_signed(n, &mut buf);
    writer.write_all(&buf[..len])?;
    Ok(len)
}

/// Read a varint from a reader
#[inline]
pub fn read_varint<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut buf = [0u8; 1];

    loop {
        reader.read_exact(&mut buf)?;
        let b = buf[0];
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    Ok(result)
}

/// Read a signed varint from a reader
#[inline]
pub fn read_signed<R: Read>(reader: &mut R) -> io::Result<i64> {
    let val = read_varint(reader)?;
    let signed = ((val >> 1) as i64) ^ (-((val & 1) as i64));
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let mut buf = [0u8; 10];

        for &n in &[0u64, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX] {
            let len = encode(n, &mut buf);
            let (decoded, decoded_len) = decode(&buf);
            assert_eq!(n, decoded);
            assert_eq!(len, decoded_len);
        }
    }

    #[test]
    fn test_signed_roundtrip() {
        let mut buf = [0u8; 10];

        for &n in &[0i64, 1, -1, 127, -127, 128, -128, i64::MAX, i64::MIN] {
            let len = encode_signed(n, &mut buf);
            let (decoded, decoded_len) = decode_signed(&buf);
            assert_eq!(n, decoded);
            assert_eq!(len, decoded_len);
        }
    }
}

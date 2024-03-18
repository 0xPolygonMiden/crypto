use crate::dsa::rpo_falcon512::N;
use alloc::vec::Vec;

/// Encodes a sequence of signed integers such that each integer x satisfies |x| < 2^(bits-1)
/// for a given parameter bits. bits can take either the value 6 or 8.
pub fn encode_i8(x: &[i8], bits: usize) -> Option<Vec<u8>> {
    let maxv = (1 << (bits - 1)) - 1_usize;
    let maxv = maxv as i8;
    let minv = -maxv;

    for &c in x {
        if c > maxv || c < minv {
            return None;
        }
    }

    let out_len = ((N * bits) + 7) >> 3;
    let mut buf = vec![0_u8; out_len];

    let mut acc = 0_u32;
    let mut acc_len = 0;
    let mask = ((1_u16 << bits) - 1) as u8;

    let mut input_pos = 0;
    for &c in x {
        acc = (acc << bits) | (c as u8 & mask) as u32;
        acc_len += bits;
        while acc_len >= 8 {
            acc_len -= 8;
            buf[input_pos] = (acc >> acc_len) as u8;
            input_pos += 1;
        }
    }
    if acc_len > 0 {
        buf[input_pos] = (acc >> (8 - acc_len)) as u8;
    }

    Some(buf)
}

/// Decodes a sequence of bytes into a sequence of signed integers such that each integer x
/// satisfies |x| < 2^(bits-1) for a given parameter bits. bits can take either the value 6 or 8.
pub fn decode_i8(buf: &[u8], bits: usize) -> Option<Vec<i8>> {
    let mut x = [0_i8; N];

    let mut i = 0;
    let mut j = 0;
    let mut acc = 0_u32;
    let mut acc_len = 0;
    let mask = (1_u32 << bits) - 1;
    let a = (1 << bits) as u8;
    let b = ((1 << (bits - 1)) - 1) as u8;

    while i < N {
        acc = (acc << 8) | (buf[j] as u32);
        j += 1;
        acc_len += 8;

        while acc_len >= bits && i < N {
            acc_len -= bits;
            let w = (acc >> acc_len) & mask;

            let w = w as u8;

            let z = if w > b { w as i8 - a as i8 } else { w as i8 };

            x[i] = z;
            i += 1;
        }
    }

    if (acc & ((1u32 << acc_len) - 1)) == 0 {
        Some(x.to_vec())
    } else {
        None
    }
}

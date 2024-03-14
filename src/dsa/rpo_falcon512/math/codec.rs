use super::{vec, FalconFelt, Polynomial, Vec, MODULUS};
use crate::dsa::rpo_falcon512::{FalconError, N, SIG_LEN};
use num::Zero;

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

/// Takes as input a list of integers x and returns a bytestring that encodes/compress' it.
/// If this is not possible, it returns False.
///
/// For each coefficient of x:
/// - the sign is encoded on 1 bit
/// - the 7 lower bits are encoded naively (binary)
/// - the high bits are encoded in unary encoding
///
/// This method can fail, in which case it returns None.
///
/// Algorithm 17 p. 47 of the specification [1].
///
/// [1]: https://falcon-sign.info/falcon.pdf
pub fn compress_signature(x: &[i16]) -> Option<Vec<u8>> {
    let mut buf = vec![0_u8; SIG_LEN];
    if x.len() != N {
        return None;
    }

    for &c in x {
        if !(-2047..=2047).contains(&c) {
            return None;
        }
    }

    let mut acc = 0;
    let mut acc_len = 0;
    let mut v = 0;
    let mut t;
    let mut w;

    for &c in x {
        acc <<= 1;
        t = c;

        if t < 0 {
            t = -t;
            acc |= 1;
        }
        w = t as u16;

        acc <<= 7;
        let mask = 127_u32;
        acc |= (w as u32) & mask;
        w >>= 7;

        acc_len += 8;

        acc <<= w + 1;
        acc |= 1;
        acc_len += w + 1;

        while acc_len >= 8 {
            acc_len -= 8;

            buf[v] = (acc >> acc_len) as u8;
            v += 1;
        }
    }

    if acc_len > 0 {
        buf[v] = (acc << (8 - acc_len)) as u8;
    }

    Some(buf)
}

/// Takes as input an encoding `input` and returns a list of integers x of length N such that
/// `inputs` encodes x. If such a list does not exist, the encoding is invalid and we output
/// an error.
///
/// Algorithm 18 p. 48 of the specification [1].
///
/// [1]: https://falcon-sign.info/falcon.pdf
pub fn decompress_signature(input: &[u8]) -> Result<Polynomial<FalconFelt>, FalconError> {
    let (encoding, log_n) = (input[0] >> 4, input[0] & 0b00001111);
    if encoding != 0b0011 {
        return Err(FalconError::SigDecodingIncorrectEncodingAlgorithm);
    }
    if log_n != 0b1001 {
        return Err(FalconError::SigDecodingNotSupportedDegree(log_n));
    }

    let input = &input[41..];
    let mut input_idx = 0;
    let mut acc = 0u32;
    let mut acc_len = 0;
    let mut coefficients = [FalconFelt::zero(); N];

    for c in coefficients.iter_mut() {
        acc = (acc << 8) | (input[input_idx] as u32);
        input_idx += 1;
        let b = acc >> acc_len;
        let s = b & 128;
        let mut m = b & 127;

        loop {
            if acc_len == 0 {
                acc = (acc << 8) | (input[input_idx] as u32);
                input_idx += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            if m >= 2048 {
                return Err(FalconError::SigDecodingTooBigHighBits(m));
            }
        }
        if s != 0 && m == 0 {
            return Err(FalconError::SigDecodingMinusZero);
        }

        let felt = if s != 0 { (MODULUS as u32 - m) as u16 } else { m as u16 };
        *c = FalconFelt::new(felt as i16);
    }

    if (acc & ((1 << acc_len) - 1)) != 0 {
        return Err(FalconError::SigDecodingNonZeroUnusedBitsLastByte);
    }
    Ok(Polynomial::new(coefficients.to_vec()))
}

use super::*;
use core::f64::consts::LN_2;
use rand::Rng;

/// Samples an integer from {0, ..., 18} according to the distribution χ, which is close to
/// the half-Gaussian distribution on the natural numbers with mean 0 and standard deviation
/// equal to sigma_max.
fn base_sampler(bytes: [u8; 9]) -> i16 {
    const RCDT: [u128; 18] = [
        3024686241123004913666,
        1564742784480091954050,
        636254429462080897535,
        199560484645026482916,
        47667343854657281903,
        8595902006365044063,
        1163297957344668388,
        117656387352093658,
        8867391802663976,
        496969357462633,
        20680885154299,
        638331848991,
        14602316184,
        247426747,
        3104126,
        28824,
        198,
        1,
    ];
    let u = u128::from_be_bytes([vec![0u8; 7], bytes.to_vec()].concat().try_into().unwrap());
    RCDT.into_iter().filter(|r| u < *r).count() as i16
}

/// Computes an integer approximation of 2^63 * ccs * exp(-x).
fn approx_exp(x: f64, ccs: f64) -> u64 {
    // The constants C are used to approximate exp(-x); these
    // constants are taken from FACCT (up to a scaling factor
    // of 2^63):
    //   https://eprint.iacr.org/2018/1234
    //   https://github.com/raykzhao/gaussian
    const C: [u64; 13] = [
        0x00000004741183A3u64,
        0x00000036548CFC06u64,
        0x0000024FDCBF140Au64,
        0x0000171D939DE045u64,
        0x0000D00CF58F6F84u64,
        0x000680681CF796E3u64,
        0x002D82D8305B0FEAu64,
        0x011111110E066FD0u64,
        0x0555555555070F00u64,
        0x155555555581FF00u64,
        0x400000000002B400u64,
        0x7FFFFFFFFFFF4800u64,
        0x8000000000000000u64,
    ];

    let mut z: u64;
    let mut y: u64;
    let twoe63 = 1u64 << 63;

    y = C[0];
    z = f64::floor(x * (twoe63 as f64)) as u64;
    for cu in C.iter().skip(1) {
        let zy = (z as u128) * (y as u128);
        y = cu - ((zy >> 63) as u64);
    }

    z = f64::floor((twoe63 as f64) * ccs) as u64;

    (((z as u128) * (y as u128)) >> 63) as u64
}

/// A random bool that is true with probability ≈ ccs · exp(-x).
fn ber_exp(x: f64, ccs: f64, random_bytes: [u8; 7]) -> bool {
    // 0.69314718055994530941 = ln(2)
    let s = f64::floor(x / LN_2) as usize;
    let r = x - LN_2 * (s as f64);
    let shamt = usize::min(s, 63);
    let z = ((((approx_exp(r, ccs) as u128) << 1) - 1) >> shamt) as u64;
    let mut w = 0i16;
    for (index, i) in (0..64).step_by(8).rev().enumerate() {
        let byte = random_bytes[index];
        w = (byte as i16) - (((z >> i) & 0xff) as i16);
        if w != 0 {
            break;
        }
    }
    w < 0
}

/// Samples an integer from the Gaussian distribution with given mean (mu) and standard deviation
/// (sigma).
pub(crate) fn sampler_z<R: Rng>(mu: f64, sigma: f64, sigma_min: f64, rng: &mut R) -> i16 {
    const SIGMA_MAX: f64 = 1.8205;
    const INV_2SIGMA_MAX_SQ: f64 = 1f64 / (2f64 * SIGMA_MAX * SIGMA_MAX);
    let isigma = 1f64 / sigma;
    let dss = 0.5f64 * isigma * isigma;
    let s = f64::floor(mu);
    let r = mu - s;
    let ccs = sigma_min * isigma;
    loop {
        let z0 = base_sampler(rng.gen());
        let random_byte: u8 = rng.gen();
        let b = (random_byte & 1) as i16;
        let z = b + ((b << 1) - 1) * z0;
        let zf_min_r = (z as f64) - r;
        //    x = ((z-r)^2)/(2*sigma^2) - ((z-b)^2)/(2*sigma0^2)
        let x = zf_min_r * zf_min_r * dss - (z0 * z0) as f64 * INV_2SIGMA_MAX_SQ;
        if ber_exp(x, ccs, rng.gen()) {
            return z + (s as i16);
        }
    }
}

#[cfg(test)]
mod test {
    use rand::RngCore;
    use std::{thread::sleep, time::Duration};

    use super::{approx_exp, ber_exp, sampler_z};

    /// RNG used only for testing purposes, whereby the produced
    /// string of random bytes is equal to the one it is initialized
    /// with. Whatever you do, do not use this RNG in production.
    struct UnsafeBufferRng {
        buffer: Vec<u8>,
        index: usize,
    }

    impl UnsafeBufferRng {
        fn new(buffer: &[u8]) -> Self {
            Self { buffer: buffer.to_vec(), index: 0 }
        }

        fn next(&mut self) -> u8 {
            if self.buffer.len() <= self.index {
                // panic!("Ran out of buffer.");
                sleep(Duration::from_millis(10));
                0u8
            } else {
                let return_value = self.buffer[self.index];
                self.index += 1;
                return_value
            }
        }
    }

    impl RngCore for UnsafeBufferRng {
        fn next_u32(&mut self) -> u32 {
            // let bytes: [u8; 4] = (0..4)
            //     .map(|_| self.next())
            //     .collect_vec()
            //     .try_into()
            //     .unwrap();
            // u32::from_be_bytes(bytes)
            u32::from_le_bytes([self.next(), 0, 0, 0])
        }

        fn next_u64(&mut self) -> u64 {
            // let bytes: [u8; 8] = (0..8)
            //     .map(|_| self.next())
            //     .collect_vec()
            //     .try_into()
            //     .unwrap();
            // u64::from_be_bytes(bytes)
            u64::from_le_bytes([self.next(), 0, 0, 0, 0, 0, 0, 0])
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for d in dest.iter_mut() {
                *d = self.next();
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            for d in dest.iter_mut() {
                *d = self.next();
            }
            Ok(())
        }
    }

    #[test]
    fn test_unsafe_buffer_rng() {
        let seed_bytes = hex::decode("7FFECD162AE2").unwrap();
        let mut rng = UnsafeBufferRng::new(&seed_bytes);
        let generated_bytes: Vec<u8> = (0..seed_bytes.len()).map(|_| rng.next()).collect();
        assert_eq!(seed_bytes, generated_bytes);
    }

    #[test]
    fn test_approx_exp() {
        let precision = 1u64 << 14;
        // known answers were generated with the following sage script:
        //```sage
        // num_samples = 10
        // precision = 200
        // R = Reals(precision)
        //
        // print(f"let kats : [(f64, f64, u64);{num_samples}] = [")
        // for i in range(num_samples):
        //     x = RDF.random_element(0.0, 0.693147180559945)
        //     ccs = RDF.random_element(0.0, 1.0)
        //     res = round(2^63 * R(ccs) * exp(R(-x)))
        //     print(f"({x}, {ccs}, {res}),")
        // print("];")
        // ```
        let kats: [(f64, f64, u64); 10] = [
            (0.2314993926072656, 0.8148006314615972, 5962140072160879737),
            (0.2648875572812225, 0.12769669655309035, 903712282351034505),
            (0.11251957513682391, 0.9264611470305881, 7635725498677341553),
            (0.04353439307256617, 0.5306497137523327, 4685877322232397936),
            (0.41834495299784347, 0.879438856118578, 5338392138535350986),
            (0.32579398973228557, 0.16513412873289002, 1099603299296456803),
            (0.5939508073919817, 0.029776019144967303, 151637565622779016),
            (0.2932367999399056, 0.37123847662857923, 2553827649386670452),
            (0.5005699297417507, 0.31447208863888976, 1758235618083658825),
            (0.4876437338498085, 0.6159515298936868, 3488632981903743976),
        ];
        for (x, ccs, answer) in kats {
            let difference = (answer as i128) - (approx_exp(x, ccs) as i128);
            assert!(
                (difference * difference) as u64 <= precision * precision,
                "answer: {answer} versus approximation: {}\ndifference: {} whereas precision: {}",
                approx_exp(x, ccs),
                difference,
                precision
            );
        }
    }

    #[test]
    fn test_ber_exp() {
        let kats = [
            (
                1.268_314_048_020_498_4,
                0.749_990_853_267_664_9,
                hex::decode("ea000000000000").unwrap(),
                false,
            ),
            (
                0.001_563_917_959_143_409_6,
                0.749_990_853_267_664_9,
                hex::decode("6c000000000000").unwrap(),
                true,
            ),
            (
                0.017_921_215_753_999_235,
                0.749_990_853_267_664_9,
                hex::decode("c2000000000000").unwrap(),
                false,
            ),
            (
                0.776_117_648_844_980_6,
                0.751_181_554_542_520_8,
                hex::decode("58000000000000").unwrap(),
                true,
            ),
        ];
        for (x, ccs, bytes, answer) in kats {
            assert_eq!(answer, ber_exp(x, ccs, bytes.try_into().unwrap()));
        }
    }

    #[test]
    fn test_sampler_z() {
        let sigma_min = 1.277833697;
        // known answers from the doc, table 3.2, page 44
        // https://falcon-sign.info/falcon.pdf
        // The zeros were added to account for dropped bytes.
        let kats = [
            (-91.90471153063714,1.7037990414754918,hex::decode("0fc5442ff043d66e91d1ea000000000000cac64ea5450a22941edc6c").unwrap(),-92),
            (-8.322564895434937,1.7037990414754918,hex::decode("f4da0f8d8444d1a77265c2000000000000ef6f98bbbb4bee7db8d9b3").unwrap(),-8),
            (-19.096516109216804,1.7035823083824078,hex::decode("db47f6d7fb9b19f25c36d6000000000000b9334d477a8bc0be68145d").unwrap(),-20),
            (-11.335543982423326, 1.7035823083824078, hex::decode("ae41b4f5209665c74d00dc000000000000c1a8168a7bb516b3190cb42c1ded26cd52000000000000aed770eca7dd334e0547bcc3c163ce0b").unwrap(), -12),
            (7.9386734193997555, 1.6984647769450156, hex::decode("31054166c1012780c603ae0000000000009b833cec73f2f41ca5807c000000000000c89c92158834632f9b1555").unwrap(), 8),
            (-28.990850086867255, 1.6984647769450156, hex::decode("737e9d68a50a06dbbc6477").unwrap(), -30),
            (-9.071257914091655, 1.6980782114808988, hex::decode("a98ddd14bf0bf22061d632").unwrap(), -10),
            (-43.88754568839566, 1.6980782114808988, hex::decode("3cbf6818a68f7ab9991514").unwrap(), -41),
            (-58.17435547946095,1.7010983419195522,hex::decode("6f8633f5bfa5d26848668e0000000000003d5ddd46958e97630410587c").unwrap(),-61),
            (-43.58664906684732, 1.7010983419195522, hex::decode("272bc6c25f5c5ee53f83c40000000000003a361fbc7cc91dc783e20a").unwrap(), -46),
            (-34.70565203313315, 1.7009387219711465, hex::decode("45443c59574c2c3b07e2e1000000000000d9071e6d133dbe32754b0a").unwrap(), -34),
            (-44.36009577368896, 1.7009387219711465, hex::decode("6ac116ed60c258e2cbaeab000000000000728c4823e6da36e18d08da0000000000005d0cc104e21cc7fd1f5ca8000000000000d9dbb675266c928448059e").unwrap(), -44),
            (-21.783037079346236, 1.6958406126012802, hex::decode("68163bc1e2cbf3e18e7426").unwrap(), -23),
            (-39.68827784633828, 1.6958406126012802, hex::decode("d6a1b51d76222a705a0259").unwrap(), -40),
            (-18.488607061056847, 1.6955259305261838, hex::decode("f0523bfaa8a394bf4ea5c10000000000000f842366fde286d6a30803").unwrap(), -22),
            (-48.39610939101591, 1.6955259305261838, hex::decode("87bd87e63374cee62127fc0000000000006931104aab64f136a0485b").unwrap(), -50),
        ];
        for (mu, sigma, random_bytes, answer) in kats {
            assert_eq!(
                sampler_z(mu, sigma, sigma_min, &mut UnsafeBufferRng::new(&random_bytes)),
                answer
            );
        }
    }
}

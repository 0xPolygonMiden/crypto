use super::{
    ElementHasher, Felt, FieldElement, HashFn, Rpo, RpoDigest256, StarkField, ALPHA, INV_ALPHA,
    INV_MDS, MDS, STATE_WIDTH, ZERO,
};
use core::convert::TryInto;
use rand_utils::rand_value;

#[test]
fn mds_inv_test() {
    let mut mul_result = [[Felt::new(0); STATE_WIDTH]; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            let result = {
                let mut result = Felt::new(0);
                for k in 0..STATE_WIDTH {
                    result += MDS[i][k] * INV_MDS[k][j]
                }
                result
            };
            mul_result[i][j] = result;
            if i == j {
                assert_eq!(result, Felt::new(1));
            } else {
                assert_eq!(result, Felt::new(0));
            }
        }
    }
}
#[test]
fn test_alphas() {
    let e: Felt = Felt::new(rand_value());
    let e_exp = e.exp(ALPHA.into());
    assert_eq!(e, e_exp.exp(INV_ALPHA));
}

#[test]
fn test_sbox() {
    let state = [Felt::new(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp(ALPHA));

    let mut actual = state;
    Rpo::apply_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn test_inv_sbox() {
    let state = [Felt::new(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp(INV_ALPHA));

    let mut actual = state;
    Rpo::apply_inv_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn hash_elements_vs_merge() {
    let elements = [Felt::new(rand_value()); 8];

    let digests: [RpoDigest256; 2] = [
        RpoDigest256::new(elements[..4].try_into().unwrap()),
        RpoDigest256::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = Rpo::merge(&digests);
    let h_result = Rpo::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn hash_elements_vs_merge_with_int() {
    let tmp = [Felt::new(rand_value()); 4];
    let seed = RpoDigest256::new(tmp);

    // ----- value fits into a field element ------------------------------------------------------
    let val: Felt = Felt::new(rand_value());
    let m_result = Rpo::merge_with_int(seed, val.as_int());

    let mut elements = seed.as_elements().to_vec();
    elements.push(val);
    let h_result = Rpo::hash_elements(&elements);

    assert_eq!(m_result, h_result);

    // ----- value does not fit into a field element ----------------------------------------------
    let val = Felt::MODULUS + 2;
    let m_result = Rpo::merge_with_int(seed, val);

    let mut elements = seed.as_elements().to_vec();
    elements.push(Felt::new(val));
    elements.push(Felt::new(1));
    let h_result = Rpo::hash_elements(&elements);

    assert_eq!(m_result, h_result);
}

#[test]
fn hash_padding() {
    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Rpo::hash(&[1_u8, 2, 3]);
    let r2 = Rpo::hash(&[1_u8, 2, 3, 0]);
    assert_ne!(r1, r2);

    // same as above but with bigger inputs
    let r1 = Rpo::hash(&[1_u8, 2, 3, 4, 5, 6]);
    let r2 = Rpo::hash(&[1_u8, 2, 3, 4, 5, 6, 0]);
    assert_ne!(r1, r2);

    // same as above but with input splitting over two elements
    let r1 = Rpo::hash(&[1_u8, 2, 3, 4, 5, 6, 7]);
    let r2 = Rpo::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0]);
    assert_ne!(r1, r2);

    // same as above but with multiple zeros
    let r1 = Rpo::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0]);
    let r2 = Rpo::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0]);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_padding() {
    let e1 = [Felt::new(rand_value()); 2];
    let e2 = [e1[0], e1[1], ZERO];

    let r1 = Rpo::hash_elements(&e1);
    let r2 = Rpo::hash_elements(&e2);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements() {
    let elements = [
        Felt::new(0),
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
    ];

    let digests: [RpoDigest256; 2] = [
        RpoDigest256::new(elements[..4].try_into().unwrap()),
        RpoDigest256::new(elements[4..8].try_into().unwrap()),
    ];

    let m_result = Rpo::merge(&digests);
    let h_result = Rpo::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

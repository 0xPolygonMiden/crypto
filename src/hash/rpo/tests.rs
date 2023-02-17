use super::{
    Felt, FieldElement, Hasher, Rpo256, RpoDigest, StarkField, ALPHA, INV_ALPHA, ONE, STATE_WIDTH,
    ZERO,
};
use crate::utils::collections::{BTreeSet, Vec};
use core::convert::TryInto;
use proptest::prelude::*;
use rand_utils::rand_value;

#[test]
fn test_alphas() {
    let e: Felt = Felt::new(rand_value());
    let e_exp = e.exp(ALPHA);
    assert_eq!(e, e_exp.exp(INV_ALPHA));
}

#[test]
fn test_sbox() {
    let state = [Felt::new(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp(ALPHA));

    let mut actual = state;
    Rpo256::apply_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn test_inv_sbox() {
    let state = [Felt::new(rand_value()); STATE_WIDTH];

    let mut expected = state;
    expected.iter_mut().for_each(|v| *v = v.exp(INV_ALPHA));

    let mut actual = state;
    Rpo256::apply_inv_sbox(&mut actual);

    assert_eq!(expected, actual);
}

#[test]
fn hash_elements_vs_merge() {
    let elements = [Felt::new(rand_value()); 8];

    let digests: [RpoDigest; 2] = [
        RpoDigest::new(elements[..4].try_into().unwrap()),
        RpoDigest::new(elements[4..].try_into().unwrap()),
    ];

    let m_result = Rpo256::merge(&digests);
    let h_result = Rpo256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn merge_vs_merge_in_domain() {
    let elements = [Felt::new(rand_value()); 8];

    let digests: [RpoDigest; 2] = [
        RpoDigest::new(elements[..4].try_into().unwrap()),
        RpoDigest::new(elements[4..].try_into().unwrap()),
    ];
    let merge_result = Rpo256::merge(&digests);

    // ------------- merge with domain = 0 ----------------------------------------------------------

    // set domain to ZERO. This should not change the result.
    let domain = ZERO;

    let merge_in_domain_result = Rpo256::merge_in_domain(&digests, domain);
    assert_eq!(merge_result, merge_in_domain_result);

    // ------------- merge with domain = 1 ----------------------------------------------------------

    // set domain to ONE. This should change the result.
    let domain = ONE;

    let merge_in_domain_result = Rpo256::merge_in_domain(&digests, domain);
    assert_ne!(merge_result, merge_in_domain_result);
}

#[test]
fn hash_elements_vs_merge_with_int() {
    let tmp = [Felt::new(rand_value()); 4];
    let seed = RpoDigest::new(tmp);

    // ----- value fits into a field element ------------------------------------------------------
    let val: Felt = Felt::new(rand_value());
    let m_result = Rpo256::merge_with_int(seed, val.as_int());

    let mut elements = seed.as_elements().to_vec();
    elements.push(val);
    let h_result = Rpo256::hash_elements(&elements);

    assert_eq!(m_result, h_result);

    // ----- value does not fit into a field element ----------------------------------------------
    let val = Felt::MODULUS + 2;
    let m_result = Rpo256::merge_with_int(seed, val);

    let mut elements = seed.as_elements().to_vec();
    elements.push(Felt::new(val));
    elements.push(Felt::new(1));
    let h_result = Rpo256::hash_elements(&elements);

    assert_eq!(m_result, h_result);
}

#[test]
fn hash_padding() {
    // adding a zero bytes at the end of a byte string should result in a different hash
    let r1 = Rpo256::hash(&[1_u8, 2, 3]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 0]);
    assert_ne!(r1, r2);

    // same as above but with bigger inputs
    let r1 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 0]);
    assert_ne!(r1, r2);

    // same as above but with input splitting over two elements
    let r1 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0]);
    assert_ne!(r1, r2);

    // same as above but with multiple zeros
    let r1 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0]);
    let r2 = Rpo256::hash(&[1_u8, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0]);
    assert_ne!(r1, r2);
}

#[test]
fn hash_elements_padding() {
    let e1 = [Felt::new(rand_value()); 2];
    let e2 = [e1[0], e1[1], ZERO];

    let r1 = Rpo256::hash_elements(&e1);
    let r2 = Rpo256::hash_elements(&e2);
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

    let digests: [RpoDigest; 2] = [
        RpoDigest::new(elements[..4].try_into().unwrap()),
        RpoDigest::new(elements[4..8].try_into().unwrap()),
    ];

    let m_result = Rpo256::merge(&digests);
    let h_result = Rpo256::hash_elements(&elements);
    assert_eq!(m_result, h_result);
}

#[test]
fn hash_test_vectors() {
    let elements = [
        Felt::new(0),
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
        Felt::new(8),
        Felt::new(9),
        Felt::new(10),
        Felt::new(11),
        Felt::new(12),
        Felt::new(13),
        Felt::new(14),
        Felt::new(15),
        Felt::new(16),
        Felt::new(17),
        Felt::new(18),
    ];

    for i in 0..elements.len() {
        let expected = RpoDigest::new(EXPECTED[i]);
        let result = Rpo256::hash_elements(&elements[..(i + 1)]);
        assert_eq!(result, expected);
    }
}

#[test]
fn sponge_bytes_with_remainder_length_wont_panic() {
    // this test targets to assert that no panic will happen with the edge case of having an inputs
    // with length that is not divisible by the used binary chunk size. 113 is a non-negligible
    // input length that is prime; hence guaranteed to not be divisible by any choice of chunk
    // size.
    //
    // this is a preliminary test to the fuzzy-stress of proptest.
    Rpo256::hash(&vec![0; 113]);
}

#[test]
fn sponge_collision_for_wrapped_field_element() {
    let a = Rpo256::hash(&[0; 8]);
    let b = Rpo256::hash(&Felt::MODULUS.to_le_bytes());
    assert_ne!(a, b);
}

#[test]
fn sponge_zeroes_collision() {
    let mut zeroes = Vec::with_capacity(255);
    let mut set = BTreeSet::new();
    (0..255).for_each(|_| {
        let hash = Rpo256::hash(&zeroes);
        zeroes.push(0);
        // panic if a collision was found
        assert!(set.insert(hash));
    });
}

proptest! {
    #[test]
    fn rpo256_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Rpo256::hash(&vec);
    }
}

const EXPECTED: [[Felt; 4]; 19] = [
    [
        Felt::new(1502364727743950833),
        Felt::new(5880949717274681448),
        Felt::new(162790463902224431),
        Felt::new(6901340476773664264),
    ],
    [
        Felt::new(7478710183745780580),
        Felt::new(3308077307559720969),
        Felt::new(3383561985796182409),
        Felt::new(17205078494700259815),
    ],
    [
        Felt::new(17439912364295172999),
        Felt::new(17979156346142712171),
        Felt::new(8280795511427637894),
        Felt::new(9349844417834368814),
    ],
    [
        Felt::new(5105868198472766874),
        Felt::new(13090564195691924742),
        Felt::new(1058904296915798891),
        Felt::new(18379501748825152268),
    ],
    [
        Felt::new(9133662113608941286),
        Felt::new(12096627591905525991),
        Felt::new(14963426595993304047),
        Felt::new(13290205840019973377),
    ],
    [
        Felt::new(3134262397541159485),
        Felt::new(10106105871979362399),
        Felt::new(138768814855329459),
        Felt::new(15044809212457404677),
    ],
    [
        Felt::new(162696376578462826),
        Felt::new(4991300494838863586),
        Felt::new(660346084748120605),
        Felt::new(13179389528641752698),
    ],
    [
        Felt::new(2242391899857912644),
        Felt::new(12689382052053305418),
        Felt::new(235236990017815546),
        Felt::new(5046143039268215739),
    ],
    [
        Felt::new(9585630502158073976),
        Felt::new(1310051013427303477),
        Felt::new(7491921222636097758),
        Felt::new(9417501558995216762),
    ],
    [
        Felt::new(1994394001720334744),
        Felt::new(10866209900885216467),
        Felt::new(13836092831163031683),
        Felt::new(10814636682252756697),
    ],
    [
        Felt::new(17486854790732826405),
        Felt::new(17376549265955727562),
        Felt::new(2371059831956435003),
        Felt::new(17585704935858006533),
    ],
    [
        Felt::new(11368277489137713825),
        Felt::new(3906270146963049287),
        Felt::new(10236262408213059745),
        Felt::new(78552867005814007),
    ],
    [
        Felt::new(17899847381280262181),
        Felt::new(14717912805498651446),
        Felt::new(10769146203951775298),
        Felt::new(2774289833490417856),
    ],
    [
        Felt::new(3794717687462954368),
        Felt::new(4386865643074822822),
        Felt::new(8854162840275334305),
        Felt::new(7129983987107225269),
    ],
    [
        Felt::new(7244773535611633983),
        Felt::new(19359923075859320),
        Felt::new(10898655967774994333),
        Felt::new(9319339563065736480),
    ],
    [
        Felt::new(4935426252518736883),
        Felt::new(12584230452580950419),
        Felt::new(8762518969632303998),
        Felt::new(18159875708229758073),
    ],
    [
        Felt::new(14871230873837295931),
        Felt::new(11225255908868362971),
        Felt::new(18100987641405432308),
        Felt::new(1559244340089644233),
    ],
    [
        Felt::new(8348203744950016968),
        Felt::new(4041411241960726733),
        Felt::new(17584743399305468057),
        Felt::new(16836952610803537051),
    ],
    [
        Felt::new(16139797453633030050),
        Felt::new(1090233424040889412),
        Felt::new(10770255347785669036),
        Felt::new(16982398877290254028),
    ],
];

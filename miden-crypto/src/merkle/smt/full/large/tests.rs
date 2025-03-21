use alloc::vec::Vec;

use super::{EMPTY_WORD, LargeSmt, RpoDigest, Smt};
use crate::{Felt, ONE, WORD_SIZE, Word};
// LargeSMT
// --------------------------------------------------------------------------------------------

fn generate_entries(pair_count: u64) -> Vec<(RpoDigest, Word)> {
    (0..pair_count)
        .map(|i| {
            let leaf_index = ((i as f64 / pair_count as f64) * (pair_count as f64)) as u64;
            let key = RpoDigest::new([ONE, ONE, Felt::new(i), Felt::new(leaf_index)]);
            let value = [ONE, ONE, ONE, Felt::new(i)];
            (key, value)
        })
        .collect()
}

/// Tests that `get_value()` works as expected
#[test]
fn test_smt_get_value() {
    let key_1: RpoDigest = RpoDigest::from([ONE, ONE, ONE, ONE]);
    let key_2: RpoDigest = RpoDigest::from([2_u32, 2_u32, 2_u32, 2_u32]);

    let value_1 = [ONE; WORD_SIZE];
    let value_2 = [2_u32.into(); WORD_SIZE];

    let smt = LargeSmt::with_entries([(key_1, value_1), (key_2, value_2)]).unwrap();

    let returned_value_1 = smt.get_value(&key_1);
    let returned_value_2 = smt.get_value(&key_2);

    assert_eq!(value_1, returned_value_1);
    assert_eq!(value_2, returned_value_2);

    // Check that a key with no inserted value returns the empty word
    let key_no_value = RpoDigest::from([42_u32, 42_u32, 42_u32, 42_u32]);

    assert_eq!(EMPTY_WORD, smt.get_value(&key_no_value));
}

#[test]
fn test_smt_and_large_smt_are_equivalent() {
    let entries = generate_entries(1000);
    let smt = Smt::with_entries(entries.clone()).unwrap();
    let large_smt = LargeSmt::with_entries(entries).unwrap();
    assert_eq!(smt.root(), large_smt.root());
}

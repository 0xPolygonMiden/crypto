use super::*;
use crate::utils::collections::Vec;
use proptest::prelude::*;

proptest! {
    #[test]
    fn blake160_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Blake3_160::hash(vec);
    }

    #[test]
    fn blake192_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Blake3_192::hash(vec);
    }

    #[test]
    fn blake256_wont_panic_with_arbitrary_input(ref vec in any::<Vec<u8>>()) {
        Blake3_256::hash(vec);
    }
}

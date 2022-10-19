use winterfell::crypto::{ElementHasher};
use winterfell::math::StarkField;
use winterfell::crypto::Hasher as HashFn;
use winterfell::crypto::hashers::Rp64_256 as Hasher;

mod rpo;
pub use rpo::Rpo;


// TYPE ALIASES
// ================================================================================================

pub type Digest = <Hasher as HashFn>::Digest;


// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn exp_acc<B: StarkField, const N: usize, const M: usize>(base: [B; N], tail: [B; N]) -> [B; N] {
    let mut result = base;
    for _ in 0..M {
        result.iter_mut().for_each(|r| *r = r.square());
    }
    result.iter_mut().zip(tail).for_each(|(r, t)| *r *= t);
    result
}

#[inline(always)]
pub fn merge(values: &[Digest; 2]) -> Digest {
    Hasher::merge(values)
}
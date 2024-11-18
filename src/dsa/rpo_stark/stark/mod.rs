use core::marker::PhantomData;

use prover::RpoSignatureProver;
use rand::{distributions::Standard, prelude::Distribution};
use winter_crypto::{DefaultRandomCoin, ElementHasher, Hasher, MerkleTree, SaltedMerkleTree};
use winter_math::{fields::f64::BaseElement, FieldElement};
use winter_prover::{Proof, ProofOptions};
use winter_verifier::{verify, AcceptableOptions, VerifierError};
use winterfell::Prover;

use crate::{hash::rpo::{Rpo256, DIGEST_RANGE, DIGEST_SIZE, NUM_ROUNDS, STATE_WIDTH}, rand::RpoRandomCoin};

mod air;
pub use air::{PublicInputs, RescueAir};
mod prover;

/// Represents an abstract STARK-based signature scheme with knowledge of RPO pre-image as
/// the hard relation.
pub struct RpoSignatureScheme<H: ElementHasher> {
    options: ProofOptions,
    _h: PhantomData<H>,
}

impl<H: ElementHasher<BaseField = BaseElement> + Sync> RpoSignatureScheme<H>
where
    Standard: Distribution<<H as Hasher>::Digest>,
{
    pub fn new(options: ProofOptions) -> Self {
        RpoSignatureScheme { options, _h: PhantomData }
    }

    pub fn sign(&self, sk: [BaseElement; DIGEST_SIZE], msg: [BaseElement; DIGEST_SIZE]) -> Proof {
        // create a prover
        let prover = RpoSignatureProver::<H>::new(self.options.clone());

        // generate execution trace
        let trace = prover.build_trace(sk, msg);

        // generate the proof
        prover.prove(trace).expect("failed to generate the signature")
    }

    pub fn verify(
        &self,
        pub_key: [BaseElement; DIGEST_SIZE],
        msg: [BaseElement; DIGEST_SIZE],
        proof: Proof,
    ) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs { pub_key, msg };
        let acceptable_options = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        verify::<RescueAir, Rpo256, RpoRandomCoin, SaltedMerkleTree<Rpo256>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn compute_rpo_image(pre_image: [BaseElement; DIGEST_SIZE]) -> [BaseElement; DIGEST_SIZE] {
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[DIGEST_RANGE].copy_from_slice(&pre_image);
    for i in 0..NUM_ROUNDS {
        Rpo256::apply_round(&mut state, i);
    }
    state[DIGEST_RANGE]
        .try_into()
        .expect("should not fail given the size of the array")
}

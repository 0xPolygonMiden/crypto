use core::marker::PhantomData;

use prover::RpoSignatureProver;
use rand::{distributions::Standard, prelude::Distribution, thread_rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use winter_crypto::{ElementHasher, Hasher, SaltedMerkleTree};
use winter_math::fields::f64::BaseElement;
use winter_prover::{Proof, ProofOptions};
use winter_verifier::{verify, AcceptableOptions, VerifierError};
use winterfell::Prover;

use crate::{
    hash::{rpo::Rpo256, DIGEST_SIZE},
    rand::RpoRandomCoin,
};

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

        // generate the initial seed for the PRNG used for zero-knowledge
        let mut seed = <ChaCha20Rng as SeedableRng>::Seed::default();
        let mut rng = thread_rng();
        rng.fill_bytes(&mut seed);

        // generate the proof
        prover.prove(trace, Some(seed)).expect("failed to generate the signature")
    }

    pub fn verify(
        &self,
        pub_key: [BaseElement; DIGEST_SIZE],
        msg: [BaseElement; DIGEST_SIZE],
        proof: Proof,
    ) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs { pub_key, msg };
        let acceptable_options = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        verify::<RescueAir, Rpo256, RpoRandomCoin, SaltedMerkleTree<Rpo256, ChaCha20Rng>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}

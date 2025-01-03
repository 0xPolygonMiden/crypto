use alloc::vec::Vec;
use core::marker::PhantomData;

use prover::RpoSignatureProver;
use rand::{distributions::Standard, prelude::Distribution};
use rand_chacha::ChaCha20Rng;
use winter_crypto::{ElementHasher, Hasher, SaltedMerkleTree};
use winter_math::fields::f64::BaseElement;
use winter_prover::{Proof, ProofOptions, Prover};
use winter_utils::Serializable;
use winter_verifier::{verify, AcceptableOptions, VerifierError};

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
        let prover = RpoSignatureProver::<H>::new(msg, self.options.clone());

        // generate execution trace
        let trace = prover.build_trace(sk);

        // generate the initial seed for the PRNG used for zero-knowledge
        let seed: [u8; 32] = generate_seed(sk, msg);

        // generate the proof
        prover.prove(trace, Some(seed)).expect("failed to generate the signature")
    }

    pub fn verify(
        &self,
        pub_key: [BaseElement; DIGEST_SIZE],
        msg: [BaseElement; DIGEST_SIZE],
        proof: Proof,
    ) -> Result<(), VerifierError> {
        // we make sure that the parameters used in generating the proof match the expected ones
        if *proof.options() != self.options {
            return Err(VerifierError::UnacceptableProofOptions);
        }
        let pub_inputs = PublicInputs { pub_key, msg };
        let acceptable_options = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        verify::<RescueAir, Rpo256, RpoRandomCoin, SaltedMerkleTree<Rpo256, ChaCha20Rng>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}

/// Deterministically generates a seed for seeding the PRNG used for zero-knowledge.
///
/// This uses the argument described in [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979#section-3.5)
/// § 3.5 where the concatenation of the private key and the hashed message, i.e., sk || H(m), is
/// used in order to construct the initial seed of a PRNG.
///
/// Note that we hash in also a context string in order to domain separate between different
/// instantiations of the signature scheme.
#[inline]
pub fn generate_seed(sk: [BaseElement; DIGEST_SIZE], msg: [BaseElement; DIGEST_SIZE]) -> [u8; 32] {
    let context_bytes = "
    Seed for PRNG used for Zero-knowledge in RPO-STARK signature scheme:
        1. Version: Conjectured security
        2. FRI queries: 30
        3. Blowup factor: 8
        4. Grinding bits: 12
        5. Field extension degree: 2
        6. FRI folding factor: 4
        7. FRI remainder polynomial max degree: 7
    "
    .to_bytes();
    let sk_bytes = sk.to_bytes();
    let msg_bytes = msg.to_bytes();

    let total_length = context_bytes.len() + sk_bytes.len() + msg_bytes.len();
    let mut buffer = Vec::with_capacity(total_length);
    buffer.extend_from_slice(&context_bytes);
    buffer.extend_from_slice(&sk_bytes);
    buffer.extend_from_slice(&msg_bytes);

    blake3::hash(&buffer).into()
}

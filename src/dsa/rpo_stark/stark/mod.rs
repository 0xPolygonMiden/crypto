use core::marker::PhantomData;

use prover::RpoSignatureProver;
use rand::{distributions::Standard, prelude::Distribution};
use rand_chacha::ChaCha20Rng;
use rfc6979::{consts::U32, ByteArray, HmacDrbg};
use sha3::{
    digest::{
        core_api::BlockSizeUser,
        generic_array::{ArrayLength, GenericArray},
        Digest as GenericDigest, FixedOutput, FixedOutputReset,
    },
    Sha3_256,
};
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
        let seed: [u8; 32] = generate_seed::<Sha3_256, U32>(sk, msg).into();

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
/// This uses the Algorithm described in [RFC 6979](https://tools.ietf.org/html/rfc6979#section-3) § 3.2.
/// The direct approach would be to just use the concatentation of the secret key and the message as
/// the value of the seed but we opt instead to use it as the seed of an `HMAC_DRBG` PRNG similar
/// to how it is used in `RFC 6979` to generate the value `k`.
///
/// Note that in `RFC 6979` the hash function used in the `HMAC_DRBG` PRNG is chosen to be the same
/// hash function used in hashing the message. In Section 3.6., however, a variant allowing
/// different hash functions is discussed and the overall security is claimed to be limited by
/// the weaker of the two.
#[inline]
pub fn generate_seed<D, N>(
    sk: [BaseElement; DIGEST_SIZE],
    msg: [BaseElement; DIGEST_SIZE],
) -> ByteArray<N>
where
    D: GenericDigest + BlockSizeUser + FixedOutput<OutputSize = N> + FixedOutputReset,
    N: ArrayLength<u8>,
{
    let sk_bytes = sk.to_bytes();
    let sk_byte_array: &GenericArray<u8, N> = ByteArray::from_slice(&sk_bytes);
    let msg_bytes = msg.to_bytes();
    let msg_byte_array: &GenericArray<u8, N> = ByteArray::from_slice(&msg_bytes);

    let mut hmac_drbg = HmacDrbg::<D>::new(sk_byte_array, msg_byte_array, &[]);

    let mut seed = ByteArray::<N>::default();
    hmac_drbg.fill_bytes(&mut seed);

    seed
}

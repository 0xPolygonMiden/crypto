use core::marker::PhantomData;

use rand_chacha::ChaCha20Rng;
use winter_air::ZkParameters;
use winter_crypto::{ElementHasher, SaltedMerkleTree};
use winter_math::{fields::f64::BaseElement, FieldElement};
use winter_prover::{
    matrix::ColMatrix, DefaultConstraintEvaluator, DefaultTraceLde, ProofOptions, Prover,
    StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
};
use winter_utils::{Deserializable, Serializable};
use winterfell::{
    AuxRandElements, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, PartitionOptions,
};

use super::air::{PublicInputs, RescueAir, HASH_CYCLE_LEN};
use crate::{hash::rpo::Rpo256, rand::RpoRandomCoin, Word, ZERO};

// PROVER
// ================================================================================================

pub struct RpoSignatureProver<H: ElementHasher>
where
    H: Sync,
{
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher + Sync> RpoSignatureProver<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self { options, _hasher: PhantomData }
    }

    pub fn build_trace(&self, sk: Word, msg: Word) -> TraceTable<BaseElement> {
        let trace_length = HASH_CYCLE_LEN;
        let mut target = vec![];
        msg.write_into(&mut target);
        let mut trace = TraceTable::with_meta(12, trace_length, target);

        trace.fill(
            |state| {
                // initialize first state of the computation
                state[0] = ZERO;
                state[1] = ZERO;
                state[2] = ZERO;
                state[3] = ZERO;
                state[4] = sk[0];
                state[5] = sk[1];
                state[6] = sk[2];
                state[7] = sk[3];
                state[8] = ZERO;
                state[9] = ZERO;
                state[10] = ZERO;
                state[11] = ZERO;
            },
            |step, state| {
                Rpo256::apply_round(
                    state.try_into().expect("should not fail given the size of the array"),
                    step,
                );
            },
        );
        trace
    }
}

impl<H: ElementHasher> Prover for RpoSignatureProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = RescueAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Rpo256;
    type VC = SaltedMerkleTree<Self::HashFn, Self::ZkPrng>;
    type RandomCoin = RpoRandomCoin;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::ZkPrng, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;
    type ZkPrng = ChaCha20Rng;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        let source = trace.info().meta();
        let msg = <Word>::read_from_bytes(source).expect("the message should be a Word");
        PublicInputs {
            pub_key: [
                trace.get(4, last_step),
                trace.get(5, last_step),
                trace.get(6, last_step),
                trace.get(7, last_step),
            ],
            msg,
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
        zk_parameters: Option<ZkParameters>,
        prng: &mut Option<Self::ZkPrng>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option, zk_parameters, prng)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
        zk_parameters: Option<ZkParameters>,
        prng: &mut Option<Self::ZkPrng>,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
            zk_parameters,
            prng,
        )
    }
}

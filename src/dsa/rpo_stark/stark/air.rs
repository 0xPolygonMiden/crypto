use alloc::vec::Vec;

use winter_math::{fields::f64::BaseElement, FieldElement, ToElements};
use winter_prover::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::{
    hash::{ARK1, ARK2, MDS, STATE_WIDTH},
    Word, ZERO,
};

// CONSTANTS
// ================================================================================================

pub const HASH_CYCLE_LEN: usize = 8;

// AIR
// ================================================================================================

pub struct RescueAir {
    context: AirContext<BaseElement>,
    pub_key: Word,
}

impl Air for RescueAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    type GkrProof = ();
    type GkrVerifier = ();

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            // Apply RPO rounds.
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(7),
        ];
        assert_eq!(STATE_WIDTH, trace_info.width());
        let context = AirContext::new(trace_info, degrees, 12, options);
        let context = context.set_num_transition_exemptions(1);
        RescueAir { context, pub_key: pub_inputs.pub_key }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        // expected state width is 12 field elements
        debug_assert_eq!(STATE_WIDTH, current.len());
        debug_assert_eq!(STATE_WIDTH, next.len());

        enforce_rpo_round(frame, result, periodic_values);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let initial_step = 0;
        let last_step = self.trace_length() - 1;
        vec![
            // Assert that the capacity as well as the second half of the rate portion of the state
            // are initialized to `ZERO`.The first half of the rate is unconstrained as it will
            // contain the secret key
            Assertion::single(0, initial_step, Self::BaseField::ZERO),
            Assertion::single(1, initial_step, Self::BaseField::ZERO),
            Assertion::single(2, initial_step, Self::BaseField::ZERO),
            Assertion::single(3, initial_step, Self::BaseField::ZERO),
            Assertion::single(8, initial_step, Self::BaseField::ZERO),
            Assertion::single(9, initial_step, Self::BaseField::ZERO),
            Assertion::single(10, initial_step, Self::BaseField::ZERO),
            Assertion::single(11, initial_step, Self::BaseField::ZERO),
            // Assert that the public key is the correct one
            Assertion::single(4, last_step, self.pub_key[0]),
            Assertion::single(5, last_step, self.pub_key[1]),
            Assertion::single(6, last_step, self.pub_key[2]),
            Assertion::single(7, last_step, self.pub_key[3]),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        get_round_constants()
    }
}

pub struct PublicInputs {
    pub(crate) pub_key: Word,
    pub(crate) msg: Word,
}

impl PublicInputs {
    pub fn new(pub_key: Word, msg: Word) -> Self {
        Self { pub_key, msg }
    }
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut res = self.pub_key.to_vec();
        res.extend_from_slice(self.msg.as_ref());
        res
    }
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

/// Enforces constraints for a single round of the Rescue Prime Optimized hash functions.
pub fn enforce_rpo_round<E: FieldElement + From<BaseElement>>(
    frame: &EvaluationFrame<E>,
    result: &mut [E],
    ark: &[E],
) {
    // compute the state that should result from applying the first 5 operations of the RPO round to
    // the current hash state.
    let mut step1 = [E::ZERO; STATE_WIDTH];
    step1.copy_from_slice(frame.current());

    apply_mds(&mut step1);
    // add constants
    for i in 0..STATE_WIDTH {
        step1[i] += ark[i];
    }
    apply_sbox(&mut step1);
    apply_mds(&mut step1);
    // add constants
    for i in 0..STATE_WIDTH {
        step1[i] += ark[STATE_WIDTH + i];
    }

    // compute the state that should result from applying the inverse of the last operation of the
    // RPO round to the next step of the computation.
    let mut step2 = [E::ZERO; STATE_WIDTH];
    step2.copy_from_slice(frame.next());
    apply_sbox(&mut step2);

    // make sure that the results are equal.
    for i in 0..STATE_WIDTH {
        result[i] = step2[i] - step1[i]
    }
}

#[inline(always)]
fn apply_sbox<E: FieldElement + From<BaseElement>>(state: &mut [E; STATE_WIDTH]) {
    state.iter_mut().for_each(|v| {
        let t2 = v.square();
        let t4 = t2.square();
        *v *= t2 * t4;
    });
}

#[inline(always)]
fn apply_mds<E: FieldElement + From<BaseElement>>(state: &mut [E; STATE_WIDTH]) {
    let mut result = [E::ZERO; STATE_WIDTH];
    result.iter_mut().zip(MDS).for_each(|(r, mds_row)| {
        state.iter().zip(mds_row).for_each(|(&s, m)| {
            *r += E::from(m) * s;
        });
    });
    *state = result
}

/// Returns RPO round constants arranged in column-major form.
pub fn get_round_constants() -> Vec<Vec<BaseElement>> {
    let mut constants = Vec::new();
    for _ in 0..(STATE_WIDTH * 2) {
        constants.push(vec![ZERO; HASH_CYCLE_LEN]);
    }

    #[allow(clippy::needless_range_loop)]
    for i in 0..HASH_CYCLE_LEN - 1 {
        for j in 0..STATE_WIDTH {
            constants[j][i] = ARK1[i][j];
            constants[j + STATE_WIDTH][i] = ARK2[i][j];
        }
    }

    constants
}

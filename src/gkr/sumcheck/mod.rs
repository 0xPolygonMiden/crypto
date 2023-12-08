use super::{
    multivariate::{ComposedMultiLinears, ComposedMultiLinearsOracle},
    utils::{barycentric_weights, evaluate_barycentric},
};
use winter_math::FieldElement;

mod prover;
pub use prover::sum_check_prove;
mod verifier;
pub use verifier::{sum_check_verify, sum_check_verify_and_reduce};
mod tests;

#[derive(Debug, Clone)]
pub struct RoundProof<E> {
    pub poly_evals: Vec<E>,
}

impl<E: FieldElement> RoundProof<E> {
    pub fn to_evals(&self, claim: E) -> Vec<E> {
        let mut result = vec![];

        // s(0) + s(1) = claim
        let c0 = claim - self.poly_evals[0];

        result.push(c0);
        result.extend_from_slice(&self.poly_evals);
        result
    }

    // TODO: refactor once we move to coefficient form
    pub(crate) fn evaluate(&self, claim: E, r: E) -> E {
        let poly_evals = self.to_evals(claim);

        let points: Vec<E> = (0..poly_evals.len()).map(|i| E::from(i as u8)).collect();
        let evalss: Vec<(E, E)> =
            points.iter().zip(poly_evals.iter()).map(|(x, y)| (*x, *y)).collect();
        let weights = barycentric_weights(&evalss);
        let new_claim = evaluate_barycentric(&evalss, r, &weights);
        new_claim
    }
}

#[derive(Debug, Clone)]
pub struct PartialProof<E> {
    pub round_proofs: Vec<RoundProof<E>>,
}

#[derive(Clone)]
pub struct FinalEvaluationClaim<E: FieldElement> {
    pub evaluation_point: Vec<E>,
    pub claimed_evaluation: E,
    pub polynomial: ComposedMultiLinearsOracle<E>,
}

#[derive(Clone)]
pub struct FullProof<E: FieldElement> {
    pub sum_check_proof: PartialProof<E>,
    pub final_evaluation_claim: FinalEvaluationClaim<E>,
}

pub struct Claim<E: FieldElement> {
    pub sum_value: E,
    pub polynomial: ComposedMultiLinearsOracle<E>,
}

#[derive(Debug)]
pub struct RoundClaim<E: FieldElement> {
    pub partial_eval_point: Vec<E>,
    pub current_claim: E,
}

pub struct RoundOutput<E: FieldElement> {
    proof: PartialProof<E>,
    witness: Witness<E>,
}

impl<E: FieldElement> From<Claim<E>> for RoundClaim<E> {
    fn from(value: Claim<E>) -> Self {
        Self {
            partial_eval_point: vec![],
            current_claim: value.sum_value,
        }
    }
}

pub struct Witness<E: FieldElement> {
    pub(crate) polynomial: ComposedMultiLinears<E>,
}

pub fn reduce_claim<E: FieldElement>(
    current_poly: RoundProof<E>,
    current_round_claim: RoundClaim<E>,
    round_challenge: E,
) -> RoundClaim<E> {
    let poly_evals = current_poly.to_evals(current_round_claim.current_claim);
    let points: Vec<E> = (0..poly_evals.len()).map(|i| E::from(i as u8)).collect();
    let evalss: Vec<(E, E)> = points.iter().zip(poly_evals.iter()).map(|(x, y)| (*x, *y)).collect();
    let weights = barycentric_weights(&evalss);
    let new_claim = evaluate_barycentric(&evalss, round_challenge, &weights);

    let mut new_partial_eval_point = current_round_claim.partial_eval_point;
    new_partial_eval_point.push(round_challenge);

    RoundClaim {
        partial_eval_point: new_partial_eval_point,
        current_claim: new_claim,
    }
}

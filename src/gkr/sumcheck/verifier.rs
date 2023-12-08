use winter_crypto::{ElementHasher, RandomCoin};
use winter_math::{fields::f64::BaseElement, FieldElement};

use crate::gkr::utils::{barycentric_weights, evaluate_barycentric};

use super::{Claim, FinalEvaluationClaim, FullProof, PartialProof};

pub fn sum_check_verify_and_reduce<
    E: FieldElement<BaseField = BaseElement>,
    C: RandomCoin<Hasher = H, BaseField = BaseElement>,
    H: ElementHasher<BaseField = BaseElement>,
>(
    claim: &Claim<E>,
    proofs: PartialProof<E>,
    coin: &mut C,
) -> (E, Vec<E>) {
    let degree = 3;
    let points: Vec<E> = (0..degree + 1).map(|x| E::from(x as u8)).collect();
    let mut sum_value = claim.sum_value.clone();
    let mut randomness = vec![];

    for proof in proofs.round_proofs {
        let partial_evals = proof.poly_evals.clone();
        coin.reseed(H::hash_elements(&partial_evals));

        // get r
        let r: E = coin.draw().unwrap();
        randomness.push(r);
        let evals = proof.to_evals(sum_value);

        let point_evals: Vec<_> = points.iter().zip(evals.iter()).map(|(x, y)| (*x, *y)).collect();
        let weights = barycentric_weights(&point_evals);
        sum_value = evaluate_barycentric(&point_evals, r, &weights);
    }
    (sum_value, randomness)
}

pub fn sum_check_verify<
    E: FieldElement<BaseField = BaseElement>,
    C: RandomCoin<Hasher = H, BaseField = BaseElement>,
    H: ElementHasher<BaseField = BaseElement>,
>(
    claim: &Claim<E>,
    proofs: FullProof<E>,
    coin: &mut C,
) -> FinalEvaluationClaim<E> {
    let FullProof {
        sum_check_proof: proofs,
        final_evaluation_claim,
    } = proofs;
    let Claim { mut sum_value, polynomial } = claim;
    let degree = polynomial.composer.max_degree();
    let points: Vec<E> = (0..degree + 1).map(|x| E::from(x as u8)).collect();

    for proof in proofs.round_proofs {
        let partial_evals = proof.poly_evals.clone();
        coin.reseed(H::hash_elements(&partial_evals));

        // get r
        let r: E = coin.draw().unwrap();
        let evals = proof.to_evals(sum_value);

        let point_evals: Vec<_> = points.iter().zip(evals.iter()).map(|(x, y)| (*x, *y)).collect();
        let weights = barycentric_weights(&point_evals);
        sum_value = evaluate_barycentric(&point_evals, r, &weights);
    }

    assert_eq!(final_evaluation_claim.claimed_evaluation, sum_value);

    final_evaluation_claim
}

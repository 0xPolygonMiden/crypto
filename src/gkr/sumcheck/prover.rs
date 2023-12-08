use super::{Claim, FullProof, RoundProof, Witness};
use crate::gkr::{
    multivariate::{ComposedMultiLinears, ComposedMultiLinearsOracle},
    sumcheck::{reduce_claim, FinalEvaluationClaim, PartialProof, RoundClaim, RoundOutput},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use winter_crypto::{ElementHasher, RandomCoin};
use winter_math::{fields::f64::BaseElement, FieldElement};

pub fn sum_check_prove<
    E: FieldElement<BaseField = BaseElement>,
    C: RandomCoin<Hasher = H, BaseField = BaseElement>,
    H: ElementHasher<BaseField = BaseElement>,
>(
    claim: &Claim<E>,
    oracle: ComposedMultiLinearsOracle<E>,
    witness: Witness<E>,
    coin: &mut C,
) -> FullProof<E> {
    // Setup first round
    let mut prev_claim = RoundClaim {
        partial_eval_point: vec![],
        current_claim: claim.sum_value.clone(),
    };
    let prev_proof = PartialProof { round_proofs: vec![] };
    let num_vars = witness.polynomial.num_variables_ml();
    let prev_output = RoundOutput { proof: prev_proof, witness };

    let mut output = sumcheck_round(prev_output);
    let poly_evals = &output.proof.round_proofs[0].poly_evals;
    coin.reseed(H::hash_elements(&poly_evals));

    for i in 1..num_vars {
        let round_challenge = coin.draw().unwrap();
        let new_claim = reduce_claim(
            output.proof.round_proofs.last().unwrap().clone(),
            prev_claim,
            round_challenge,
        );
        output.witness.polynomial = output.witness.polynomial.bind(round_challenge);

        output = sumcheck_round(output);
        prev_claim = new_claim;

        let poly_evals = &output.proof.round_proofs[i].poly_evals;
        coin.reseed(H::hash_elements(&poly_evals));
    }

    let round_challenge = coin.draw().unwrap();
    let RoundClaim { partial_eval_point, current_claim } = reduce_claim(
        output.proof.round_proofs.last().unwrap().clone(),
        prev_claim,
        round_challenge,
    );
    let final_eval_claim = FinalEvaluationClaim {
        evaluation_point: partial_eval_point,
        claimed_evaluation: current_claim,
        polynomial: oracle,
    };

    FullProof {
        sum_check_proof: output.proof,
        final_evaluation_claim: final_eval_claim,
    }
}

fn sumcheck_round<E: FieldElement>(prev_proof: RoundOutput<E>) -> RoundOutput<E> {
    let RoundOutput { mut proof, witness } = prev_proof;

    let polynomial = witness.polynomial;
    let num_ml = polynomial.num_ml();
    let num_vars = polynomial.num_variables_ml();
    let num_rounds = num_vars - 1;

    let mut evals_zero = vec![E::ZERO; num_ml];
    let mut evals_one = vec![E::ZERO; num_ml];
    let mut deltas = vec![E::ZERO; num_ml];
    let mut evals_x = vec![E::ZERO; num_ml];

    let total_evals = (0..1 << num_rounds).into_iter().map(|i| {
        for (j, ml) in polynomial.multi_linears.iter().enumerate() {
            evals_zero[j] = ml.evaluations[(i << 1) as usize];
            evals_one[j] = ml.evaluations[(i << 1) + 1];
        }
        let mut total_evals = vec![E::ZERO; polynomial.degree()];
        total_evals[0] = polynomial.composer.evaluate(&evals_one);
        evals_zero
            .iter()
            .zip(evals_one.iter().zip(deltas.iter_mut().zip(evals_x.iter_mut())))
            .for_each(|(a0, (a1, (delta, evx)))| {
                *delta = *a1 - *a0;
                *evx = *a1;
            });
        total_evals.iter_mut().skip(1).for_each(|e| {
            evals_x.iter_mut().zip(deltas.iter()).for_each(|(evx, delta)| {
                *evx += *delta;
            });
            *e = polynomial.composer.evaluate(&evals_x);
        });
        total_evals
    });
    let evaluations = total_evals.fold(vec![E::ZERO; polynomial.degree()], |mut acc, evals| {
        acc.iter_mut().zip(evals.iter()).for_each(|(a, ev)| *a += *ev);
        acc
    });
    let proof_update = RoundProof { poly_evals: evaluations };
    proof.round_proofs.push(proof_update);
    RoundOutput { proof, witness: Witness { polynomial } }
}

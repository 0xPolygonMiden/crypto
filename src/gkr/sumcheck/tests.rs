use alloc::sync::Arc;
use rand::{distributions::Uniform, SeedableRng};
use winter_crypto::RandomCoin;
use winter_math::{fields::f64::BaseElement, FieldElement};

use crate::{
    gkr::{
        circuit::{CircuitProof, FractionalSumCircuit},
        multivariate::{
            compute_claim, gkr_composition_from_composition_polys, ComposedMultiLinears,
            ComposedMultiLinearsOracle, CompositionPolynomial, EqPolynomial, GkrComposition,
            GkrCompositionVanilla, LogUpDenominatorTableComposition,
            LogUpDenominatorWitnessComposition, MultiLinear, MultiLinearOracle,
            ProjectionComposition, SumComposition,
        },
        sumcheck::{
            prover::sum_check_prove, verifier::sum_check_verify, Claim, FinalEvaluationClaim,
            FullProof, Witness,
        },
    },
    hash::rpo::Rpo256,
    rand::RpoRandomCoin,
};

#[test]
fn gkr_workflow() {
    // generate the data witness for the LogUp argument
    let mut mls = generate_logup_witness::<BaseElement>(3);

    // the is sampled after receiving the main trace commitment
    let alpha = rand_utils::rand_value();

    // the composition polynomials defining the numerators/denominators
    let composition_polys: Vec<Vec<Arc<dyn CompositionPolynomial<BaseElement>>>> = vec![
        // left num
        vec![Arc::new(ProjectionComposition::new(0))],
        // right num
        vec![Arc::new(ProjectionComposition::new(1))],
        // left den
        vec![Arc::new(LogUpDenominatorTableComposition::new(2, alpha))],
        // right den
        vec![Arc::new(LogUpDenominatorWitnessComposition::new(3, alpha))],
    ];

    // run the GKR prover to obtain:
    // 1. The fractional sum circuit output.
    // 2. GKR proofs up to the last circuit layer counting backwards.
    // 3. GKR proof (i.e., a sum-check proof) for the last circuit layer counting backwards.
    let seed = [BaseElement::ZERO; 4];
    let mut transcript = RpoRandomCoin::new(seed.into());
    let (circuit_outputs, gkr_before_last_proof, final_layer_proof) =
        CircuitProof::prove_virtual_bus(composition_polys.clone(), &mut mls, &mut transcript);

    let seed = [BaseElement::ZERO; 4];
    let mut transcript = RpoRandomCoin::new(seed.into());

    // run the GKR verifier to obtain:
    // 1. A final evaluation claim.
    // 2. Randomness defining the Lagrange kernel in the final sum-check protocol. Note that this
    // Lagrange kernel is different from the one used by the STARK (outer) prover to open the MLs
    // at the evaluation point.
    let (final_eval_claim, gkr_lagrange_kernel_rand) = gkr_before_last_proof.verify_virtual_bus(
        composition_polys.clone(),
        final_layer_proof,
        &circuit_outputs,
        &mut transcript,
    );

    // the final verification step is composed of:
    // 1. Querying the oracles for the openings at the evaluation point. This will be done by the
    // (outer) STARK prover using:
    //      a. The Lagrange kernel (auxiliary) column at the evaluation point.
    //      b. An extra (auxiliary) column to compute an inner product between two vectors. The first
    //      being the Lagrange kernel and the second being  (\sum_{j=0}^3 mls[j][i] * \lambda_i)_{i\in\{0,..,n\}}
    // 2. Evaluating the composition polynomial at the previous openings and checking equality with
    // the claimed evaluation.

    // 1. Querying the oracles

    let FinalEvaluationClaim {
        evaluation_point,
        claimed_evaluation,
        polynomial,
    } = final_eval_claim;

    // The evaluation of the EQ polynomial can be done by the verifier directly
    let eq = (0..gkr_lagrange_kernel_rand.len())
        .map(|i| {
            gkr_lagrange_kernel_rand[i] * evaluation_point[i]
                + (BaseElement::ONE - gkr_lagrange_kernel_rand[i])
                    * (BaseElement::ONE - evaluation_point[i])
        })
        .fold(BaseElement::ONE, |acc, term| acc * term);

    // These are the queries to the oracles.
    // They should be provided by the prover non-deterministically
    let left_num_eval = mls[0].evaluate(&evaluation_point);
    let right_num_eval = mls[1].evaluate(&evaluation_point);
    let left_den_eval = mls[2].evaluate(&evaluation_point);
    let right_den_eval = mls[3].evaluate(&evaluation_point);

    // The verifier absorbs the claimed openings and generates batching randomness lambda
    let mut query = vec![left_num_eval, right_num_eval, left_den_eval, right_den_eval];
    transcript.reseed(Rpo256::hash_elements(&query));
    let lambdas: Vec<BaseElement> = vec![
        transcript.draw().unwrap(),
        transcript.draw().unwrap(),
        transcript.draw().unwrap(),
    ];
    let batched_query =
        query[0] + query[1] * lambdas[0] + query[2] * lambdas[1] + query[3] * lambdas[2];

    // The prover generates the Lagrange kernel as an auxiliary column
    let mut rev_evaluation_point = evaluation_point;
    rev_evaluation_point.reverse();
    let lagrange_kernel = EqPolynomial::new(rev_evaluation_point).evaluations();

    // The prover generates the additional auxiliary column for the inner product
    let tmp_col: Vec<BaseElement> = (0..mls[0].len())
        .map(|i| {
            mls[0][i] + mls[1][i] * lambdas[0] + mls[2][i] * lambdas[1] + mls[3][i] * lambdas[2]
        })
        .collect();
    let mut running_sum_col = vec![BaseElement::ZERO; tmp_col.len() + 1];
    running_sum_col[0] = BaseElement::ZERO;
    for i in 1..(tmp_col.len() + 1) {
        running_sum_col[i] = running_sum_col[i - 1] + tmp_col[i - 1] * lagrange_kernel[i - 1];
    }

    // Boundary constraint to check correctness of openings
    assert_eq!(batched_query, *running_sum_col.last().unwrap());

    // 2) Final evaluation and check
    query.push(eq);
    let verifier_computed = polynomial.composer.evaluate(&query);

    assert_eq!(verifier_computed, claimed_evaluation);
}

pub fn generate_logup_witness<E: FieldElement>(trace_len: usize) -> Vec<MultiLinear<E>> {
    let num_variables_ml = trace_len;
    let num_evaluations = 1 << num_variables_ml;
    let num_witnesses = 1;
    let (p, q) = generate_logup_data::<E>(num_variables_ml, num_witnesses);
    let numerators: Vec<Vec<E>> = p.chunks(num_evaluations).map(|x| x.into()).collect();
    let denominators: Vec<Vec<E>> = q.chunks(num_evaluations).map(|x| x.into()).collect();

    let mut mls = vec![];
    for i in 0..2 {
        let ml = MultiLinear::from_values(&numerators[i]);
        mls.push(ml);
    }
    for i in 0..2 {
        let ml = MultiLinear::from_values(&denominators[i]);
        mls.push(ml);
    }
    mls
}

pub fn generate_logup_data<E: FieldElement>(
    trace_len: usize,
    num_witnesses: usize,
) -> (Vec<E>, Vec<E>) {
    use rand::distributions::Slice;
    use rand::Rng;
    let n: usize = trace_len;
    let num_w: usize = num_witnesses; // This should be of the form 2^k - 1
    let rng = rand::rngs::StdRng::seed_from_u64(0);

    let t_table: Vec<u32> = (0..(1 << n)).collect();
    let mut m_table: Vec<u32> = (0..(1 << n)).map(|_| 0).collect();

    let t_table_slice = Slice::new(&t_table).unwrap();

    // Construct the witness columns. Uses sampling with replacement in order to have multiplicities
    // different from 1.
    let mut w_tables = Vec::new();
    for _ in 0..num_w {
        let wi_table: Vec<u32> =
            rng.clone().sample_iter(&t_table_slice).cloned().take(1 << n).collect();

        // Construct the multiplicities
        wi_table.iter().for_each(|w| {
            m_table[*w as usize] += 1;
        });
        w_tables.push(wi_table)
    }

    // The numerators
    let mut p: Vec<E> = m_table.iter().map(|m| E::from(*m as u32)).collect();
    p.extend((0..(num_w * (1 << n))).map(|_| E::from(1_u32)).collect::<Vec<E>>());

    // Construct the denominators
    let mut q: Vec<E> = t_table.iter().map(|t| E::from(*t)).collect();
    for w_table in w_tables {
        q.extend(w_table.iter().map(|w| E::from(*w)).collect::<Vec<E>>());
    }
    (p, q)
}

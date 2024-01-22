use alloc::sync::Arc;
use winter_crypto::{ElementHasher, RandomCoin};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

use crate::gkr::multivariate::{
    ComposedMultiLinearsOracle, EqPolynomial, GkrCompositionVanilla, MultiLinearOracle,
};
use crate::gkr::sumcheck::{sum_check_verify, Claim};

use super::multivariate::{
    gen_plain_gkr_oracle, gkr_composition_from_composition_polys, ComposedMultiLinears,
    CompositionPolynomial, MultiLinear,
};
use super::sumcheck::{
    sum_check_prove, sum_check_verify_and_reduce, FinalEvaluationClaim,
    PartialProof as SumcheckInstanceProof, RoundProof as SumCheckRoundProof, Witness,
};

/// Layered circuit for computing a sum of fractions.
///
/// The circuit computes a sum of fractions based on the formula a / c + b / d = (a * d + b * c) / (c * d)
/// which defines a "gate" ((a, b), (c, d)) --> (a * d + b * c, c * d) upon which the `FractionalSumCircuit`
/// is built.
/// TODO: Swap 1 and 0
#[derive(Debug)]
pub struct FractionalSumCircuit<E: FieldElement> {
    p_1_vec: Vec<MultiLinear<E>>,
    p_0_vec: Vec<MultiLinear<E>>,
    q_1_vec: Vec<MultiLinear<E>>,
    q_0_vec: Vec<MultiLinear<E>>,
}

impl<E: FieldElement> FractionalSumCircuit<E> {
    /// Computes The values of the gates outputs for each of the layers of the fractional sum circuit.
    pub fn new_(num_den: &Vec<MultiLinear<E>>) -> Self {
        let mut p_1_vec: Vec<MultiLinear<E>> = Vec::new();
        let mut p_0_vec: Vec<MultiLinear<E>> = Vec::new();
        let mut q_1_vec: Vec<MultiLinear<E>> = Vec::new();
        let mut q_0_vec: Vec<MultiLinear<E>> = Vec::new();

        let num_layers = num_den[0].len().ilog2() as usize;

        p_1_vec.push(num_den[0].to_owned());
        p_0_vec.push(num_den[1].to_owned());
        q_1_vec.push(num_den[2].to_owned());
        q_0_vec.push(num_den[3].to_owned());

        for i in 0..num_layers {
            let (output_p_1, output_p_0, output_q_1, output_q_0) =
                FractionalSumCircuit::compute_layer(
                    &p_1_vec[i],
                    &p_0_vec[i],
                    &q_1_vec[i],
                    &q_0_vec[i],
                );
            p_1_vec.push(output_p_1);
            p_0_vec.push(output_p_0);
            q_1_vec.push(output_q_1);
            q_0_vec.push(output_q_0);
        }

        FractionalSumCircuit { p_1_vec, p_0_vec, q_1_vec, q_0_vec }
    }

    /// Compute the output values of the layer given a set of input values
    fn compute_layer(
        inp_p_1: &MultiLinear<E>,
        inp_p_0: &MultiLinear<E>,
        inp_q_1: &MultiLinear<E>,
        inp_q_0: &MultiLinear<E>,
    ) -> (MultiLinear<E>, MultiLinear<E>, MultiLinear<E>, MultiLinear<E>) {
        let len = inp_q_1.len();
        let outp_p_1 = (0..len / 2)
            .map(|i| inp_p_1[i] * inp_q_0[i] + inp_p_0[i] * inp_q_1[i])
            .collect::<Vec<E>>();
        let outp_p_0 = (len / 2..len)
            .map(|i| inp_p_1[i] * inp_q_0[i] + inp_p_0[i] * inp_q_1[i])
            .collect::<Vec<E>>();
        let outp_q_1 = (0..len / 2).map(|i| inp_q_1[i] * inp_q_0[i]).collect::<Vec<E>>();
        let outp_q_0 = (len / 2..len).map(|i| inp_q_1[i] * inp_q_0[i]).collect::<Vec<E>>();

        (
            MultiLinear::new(outp_p_1),
            MultiLinear::new(outp_p_0),
            MultiLinear::new(outp_q_1),
            MultiLinear::new(outp_q_0),
        )
    }

    /// Computes The values of the gates outputs for each of the layers of the fractional sum circuit.
    pub fn new(poly: &MultiLinear<E>) -> Self {
        let mut p_1_vec: Vec<MultiLinear<E>> = Vec::new();
        let mut p_0_vec: Vec<MultiLinear<E>> = Vec::new();
        let mut q_1_vec: Vec<MultiLinear<E>> = Vec::new();
        let mut q_0_vec: Vec<MultiLinear<E>> = Vec::new();

        let num_layers = poly.len().ilog2() as usize - 1;
        let (output_p, output_q) = poly.split(poly.len() / 2);
        let (output_p_1, output_p_0) = output_p.split(output_p.len() / 2);
        let (output_q_1, output_q_0) = output_q.split(output_q.len() / 2);

        p_1_vec.push(output_p_1);
        p_0_vec.push(output_p_0);
        q_1_vec.push(output_q_1);
        q_0_vec.push(output_q_0);

        for i in 0..num_layers - 1 {
            let (output_p_1, output_p_0, output_q_1, output_q_0) =
                FractionalSumCircuit::compute_layer(
                    &p_1_vec[i],
                    &p_0_vec[i],
                    &q_1_vec[i],
                    &q_0_vec[i],
                );
            p_1_vec.push(output_p_1);
            p_0_vec.push(output_p_0);
            q_1_vec.push(output_q_1);
            q_0_vec.push(output_q_0);
        }

        FractionalSumCircuit { p_1_vec, p_0_vec, q_1_vec, q_0_vec }
    }

    /// Given a value r, computes the evaluation of the last layer at r when interpreted as (two)
    /// multilinear polynomials.
    pub fn evaluate(&self, r: E) -> (E, E) {
        let len = self.p_1_vec.len();
        assert_eq!(self.p_1_vec[len - 1].num_variables(), 0);
        assert_eq!(self.p_0_vec[len - 1].num_variables(), 0);
        assert_eq!(self.q_1_vec[len - 1].num_variables(), 0);
        assert_eq!(self.q_0_vec[len - 1].num_variables(), 0);

        let mut p_1 = self.p_1_vec[len - 1].clone();
        p_1.extend(&self.p_0_vec[len - 1]);
        let mut q_1 = self.q_1_vec[len - 1].clone();
        q_1.extend(&self.q_0_vec[len - 1]);

        (p_1.evaluate(&[r]), q_1.evaluate(&[r]))
    }
}

/// A proof for reducing a claim on the correctness of the output of a layer to that of:
///
/// 1. Correctness of a sumcheck proof on the claimed output.
/// 2. Correctness of the evaluation of the input (to the said layer) at a random point when
/// interpreted as multilinear polynomial.
///
/// The verifier will then have to work backward and:
///
/// 1. Verify that the sumcheck proof is valid.
/// 2. Recurse on the (claimed evaluations) using the same approach as above.
///
/// Note that the following struct batches proofs for many circuits of the same type that
/// are independent i.e., parallel.
#[derive(Debug)]
pub struct LayerProof<E: FieldElement> {
    pub proof: SumcheckInstanceProof<E>,
    pub claims_sum_p1: E,
    pub claims_sum_p0: E,
    pub claims_sum_q1: E,
    pub claims_sum_q0: E,
}

#[allow(dead_code)]
impl<E: FieldElement<BaseField = BaseElement> + 'static> LayerProof<E> {
    /// Checks the validity of a `LayerProof`.
    ///
    /// It first reduces the 2 claims to 1 claim using randomness and then checks that the sumcheck
    /// protocol was correctly executed.
    ///
    /// The method outputs:
    ///
    /// 1. A vector containing the randomness sent by the verifier throughout the course of the
    /// sum-check protocol.
    /// 2. The (claimed) evaluation of the inner polynomial (i.e., the one being summed) at the this random vector.
    /// 3. The random value used in the 2-to-1 reduction of the 2 sumchecks.  
    pub fn verify_sum_check_before_last<
        C: RandomCoin<Hasher = H, BaseField = BaseElement>,
        H: ElementHasher<BaseField = BaseElement>,
    >(
        &self,
        claim: (E, E),
        num_rounds: usize,
        transcript: &mut C,
    ) -> ((E, Vec<E>), E) {
        // Absorb the claims
        let data = vec![claim.0, claim.1];
        transcript.reseed(H::hash_elements(&data));

        // Squeeze challenge to reduce two sumchecks to one
        let r_sum_check: E = transcript.draw().unwrap();

        // Run the sumcheck protocol

        // Given r_sum_check and claim, we create a Claim with the GKR composer and then call the generic sum-check verifier
        let reduced_claim = claim.0 + claim.1 * r_sum_check;

        // Create vanilla oracle
        let oracle = gen_plain_gkr_oracle(num_rounds, r_sum_check);

        // Create sum-check claim
        let transformed_claim = Claim {
            sum_value: reduced_claim,
            polynomial: oracle,
        };

        let reduced_gkr_claim =
            sum_check_verify_and_reduce(&transformed_claim, self.proof.clone(), transcript);

        (reduced_gkr_claim, r_sum_check)
    }
}

#[derive(Debug)]
pub struct GkrClaim<E: FieldElement + 'static> {
    evaluation_point: Vec<E>,
    claimed_evaluation: (E, E),
}

#[derive(Debug)]
pub struct CircuitProof<E: FieldElement + 'static> {
    pub proof: Vec<LayerProof<E>>,
}

impl<E: FieldElement<BaseField = BaseElement> + 'static> CircuitProof<E> {
    pub fn prove<
        C: RandomCoin<Hasher = H, BaseField = BaseElement>,
        H: ElementHasher<BaseField = BaseElement>,
    >(
        circuit: &mut FractionalSumCircuit<E>,
        transcript: &mut C,
    ) -> (Self, Vec<E>, Vec<Vec<E>>) {
        let mut proof_layers: Vec<LayerProof<E>> = Vec::new();
        let num_layers = circuit.p_0_vec.len();

        let data = vec![
            circuit.p_1_vec[num_layers - 1][0],
            circuit.p_0_vec[num_layers - 1][0],
            circuit.q_1_vec[num_layers - 1][0],
            circuit.q_0_vec[num_layers - 1][0],
        ];
        transcript.reseed(H::hash_elements(&data));

        // Challenge to reduce p1, p0, q1, q0 to pr, qr
        let r_cord = transcript.draw().unwrap();

        // Compute the (2-to-1 folded) claim
        let mut claim = circuit.evaluate(r_cord);
        let mut all_rand = Vec::new();

        let mut rand = Vec::new();
        rand.push(r_cord);
        for layer_id in (0..num_layers - 1).rev() {
            let len = circuit.p_0_vec[layer_id].len();

            // Construct the Lagrange kernel evaluated at previous GKR round randomness.
            // TODO: Treat the direction of doing sum-check more robustly.
            let mut rand_reversed = rand.clone();
            rand_reversed.reverse();
            let eq_evals = EqPolynomial::new(rand_reversed.clone()).evaluations();
            let mut poly_x = MultiLinear::from_values(&eq_evals);
            assert_eq!(poly_x.len(), len);

            let num_rounds = poly_x.len().ilog2() as usize;

            // 1. A is a polynomial containing the evaluations `p_1`.
            // 2. B is a polynomial containing the evaluations `p_0`.
            // 3. C is a polynomial containing the evaluations `q_1`.
            // 4. D is a polynomial containing the evaluations `q_0`.
            let poly_a: &mut MultiLinear<E>;
            let poly_b: &mut MultiLinear<E>;
            let poly_c: &mut MultiLinear<E>;
            let poly_d: &mut MultiLinear<E>;
            poly_a = &mut circuit.p_1_vec[layer_id];
            poly_b = &mut circuit.p_0_vec[layer_id];
            poly_c = &mut circuit.q_1_vec[layer_id];
            poly_d = &mut circuit.q_0_vec[layer_id];

            let poly_vec_par = (poly_a, poly_b, poly_c, poly_d, &mut poly_x);

            // The (non-linear) polynomial combining the multilinear polynomials
            let comb_func = |a: &E, b: &E, c: &E, d: &E, x: &E, rho: &E| -> E {
                (*a * *d + *b * *c + *rho * *c * *d) * *x
            };

            // Run the sumcheck protocol
            let (proof, rand_sumcheck, claims_sum) = sum_check_prover_gkr_before_last::<E, _, _>(
                claim,
                num_rounds,
                poly_vec_par,
                comb_func,
                transcript,
            );

            let (claims_sum_p1, claims_sum_p0, claims_sum_q1, claims_sum_q0, _claims_eq) =
                claims_sum;

            let data = vec![claims_sum_p1, claims_sum_p0, claims_sum_q1, claims_sum_q0];
            transcript.reseed(H::hash_elements(&data));

            // Produce a random challenge to condense claims into a single claim
            let r_layer = transcript.draw().unwrap();

            claim = (
                claims_sum_p1 + r_layer * (claims_sum_p0 - claims_sum_p1),
                claims_sum_q1 + r_layer * (claims_sum_q0 - claims_sum_q1),
            );

            // Collect the randomness used for the current layer in order to construct the random
            // point where the input multilinear polynomials were evaluated.
            let mut ext = rand_sumcheck;
            ext.push(r_layer);
            all_rand.push(rand);
            rand = ext;

            proof_layers.push(LayerProof {
                proof,
                claims_sum_p1,
                claims_sum_p0,
                claims_sum_q1,
                claims_sum_q0,
            });
        }

        (CircuitProof { proof: proof_layers }, rand, all_rand)
    }

    pub fn prove_virtual_bus<
        C: RandomCoin<Hasher = H, BaseField = BaseElement>,
        H: ElementHasher<BaseField = BaseElement>,
    >(
        composition_polys: Vec<Vec<Arc<dyn CompositionPolynomial<E>>>>,
        mls: &mut Vec<MultiLinear<E>>,
        transcript: &mut C,
    ) -> (Vec<E>, Self, super::sumcheck::FullProof<E>) {
        let num_evaluations = 1 << mls[0].num_variables();

        // I) Evaluate the numerators and denominators over the boolean hyper-cube
        let mut num_den: Vec<Vec<E>> = vec![vec![]; 4];
        for i in 0..num_evaluations {
            for j in 0..4 {
                let query: Vec<E> = mls.iter().map(|ml| ml[i]).collect();

                composition_polys[j].iter().for_each(|c| {
                    let evaluation = c.as_ref().evaluate(&query);
                    num_den[j].push(evaluation);
                });
            }
        }

        // II) Evaluate the GKR fractional sum circuit
        let input: Vec<MultiLinear<E>> =
            (0..4).map(|i| MultiLinear::from_values(&num_den[i])).collect();
        let mut circuit = FractionalSumCircuit::new_(&input);

        // III) Run the GKR prover for all layers except the last one
        let (gkr_proofs, GkrClaim { evaluation_point, claimed_evaluation }) =
            CircuitProof::prove_before_final(&mut circuit, transcript);

        // IV) Run the sum-check prover for the last GKR layer counting backwards i.e., first layer
        // in the circuit.

        // 1) Build the EQ polynomial (Lagrange kernel) at the randomness sampled during the previous
        // sum-check protocol run
        let mut rand_reversed = evaluation_point.clone();
        rand_reversed.reverse();
        let eq_evals = EqPolynomial::new(rand_reversed.clone()).evaluations();
        let poly_x = MultiLinear::from_values(&eq_evals);

        // 2) Add the Lagrange kernel to the list of MLs
        mls.push(poly_x);

        // 3) Absorb the final sum-check claims and generate randomness for 2-to-1 sum-check reduction
        let data = vec![claimed_evaluation.0, claimed_evaluation.1];
        transcript.reseed(H::hash_elements(&data));
        // Squeeze challenge to reduce two sumchecks to one
        let r_sum_check = transcript.draw().unwrap();
        let reduced_claim = claimed_evaluation.0 + claimed_evaluation.1 * r_sum_check;

        // 4) Create the composed ML representing the numerators and denominators of the topmost GKR layer
        let gkr_final_composed_ml = gkr_composition_from_composition_polys(
            &composition_polys,
            r_sum_check,
            1 << mls[0].num_variables,
        );
        let composed_ml =
            ComposedMultiLinears::new(Arc::new(gkr_final_composed_ml.clone()), mls.to_vec());

        // 5) Create the composed ML oracle. This will be used for verifying the FinalEvaluationClaim downstream
        // TODO: This should be an input to the current function.
        // TODO: Make MultiLinearOracle a variant in an enum so that it is possible to capture other types of oracles.
        // For example, shifts of polynomials, Lagrange kernels at a random point or periodic (transparent) polynomials.
        let left_num_oracle = MultiLinearOracle { id: 0 };
        let right_num_oracle = MultiLinearOracle { id: 1 };
        let left_denom_oracle = MultiLinearOracle { id: 2 };
        let right_denom_oracle = MultiLinearOracle { id: 3 };
        let eq_oracle = MultiLinearOracle { id: 4 };
        let composed_ml_oracle = ComposedMultiLinearsOracle {
            composer: (Arc::new(gkr_final_composed_ml.clone())),
            multi_linears: vec![
                eq_oracle,
                left_num_oracle,
                right_num_oracle,
                left_denom_oracle,
                right_denom_oracle,
            ],
        };

        // 6) Create the claim for the final sum-check protocol.
        let claim = Claim {
            sum_value: reduced_claim,
            polynomial: composed_ml_oracle.clone(),
        };

        // 7) Create the witness for the sum-check claim.
        let witness = Witness { polynomial: composed_ml };
        let output = sum_check_prove(&claim, composed_ml_oracle, witness, transcript);

        // 8) Create the claimed output of the circuit.
        let circuit_outputs = vec![
            circuit.p_1_vec.last().unwrap()[0],
            circuit.p_0_vec.last().unwrap()[0],
            circuit.q_1_vec.last().unwrap()[0],
            circuit.q_0_vec.last().unwrap()[0],
        ];

        // 9) Return:
        //  1. The claimed circuit outputs.
        //  2. GKR proofs of all circuit layers except the initial layer.
        //  3. Output of the final sum-check protocol.
        (circuit_outputs, gkr_proofs, output)
    }

    pub fn prove_before_final<
        C: RandomCoin<Hasher = H, BaseField = BaseElement>,
        H: ElementHasher<BaseField = BaseElement>,
    >(
        sum_circuits: &mut FractionalSumCircuit<E>,
        transcript: &mut C,
    ) -> (Self, GkrClaim<E>) {
        let mut proof_layers: Vec<LayerProof<E>> = Vec::new();
        let num_layers = sum_circuits.p_0_vec.len();

        let data = vec![
            sum_circuits.p_1_vec[num_layers - 1][0],
            sum_circuits.p_0_vec[num_layers - 1][0],
            sum_circuits.q_1_vec[num_layers - 1][0],
            sum_circuits.q_0_vec[num_layers - 1][0],
        ];
        transcript.reseed(H::hash_elements(&data));

        // Challenge to reduce p1, p0, q1, q0 to pr, qr
        let r_cord = transcript.draw().unwrap();

        // Compute the (2-to-1 folded) claim
        let mut claims_to_verify = sum_circuits.evaluate(r_cord);
        let mut all_rand = Vec::new();

        let mut rand = Vec::new();
        rand.push(r_cord);
        for layer_id in (1..num_layers - 1).rev() {
            let len = sum_circuits.p_0_vec[layer_id].len();

            // Construct the Lagrange kernel evaluated at previous GKR round randomness.
            // TODO: Treat the direction of doing sum-check more robustly.
            let mut rand_reversed = rand.clone();
            rand_reversed.reverse();
            let eq_evals = EqPolynomial::new(rand_reversed.clone()).evaluations();
            let mut poly_x = MultiLinear::from_values(&eq_evals);
            assert_eq!(poly_x.len(), len);

            let num_rounds = poly_x.len().ilog2() as usize;

            // 1. A is a polynomial containing the evaluations `p_1`.
            // 2. B is a polynomial containing the evaluations `p_0`.
            // 3. C is a polynomial containing the evaluations `q_1`.
            // 4. D is a polynomial containing the evaluations `q_0`.
            let poly_a: &mut MultiLinear<E>;
            let poly_b: &mut MultiLinear<E>;
            let poly_c: &mut MultiLinear<E>;
            let poly_d: &mut MultiLinear<E>;
            poly_a = &mut sum_circuits.p_1_vec[layer_id];
            poly_b = &mut sum_circuits.p_0_vec[layer_id];
            poly_c = &mut sum_circuits.q_1_vec[layer_id];
            poly_d = &mut sum_circuits.q_0_vec[layer_id];

            let poly_vec = (poly_a, poly_b, poly_c, poly_d, &mut poly_x);

            let claim = claims_to_verify;

            // The (non-linear) polynomial combining the multilinear polynomials
            let comb_func = |a: &E, b: &E, c: &E, d: &E, x: &E, rho: &E| -> E {
                (*a * *d + *b * *c + *rho * *c * *d) * *x
            };

            // Run the sumcheck protocol
            let (proof, rand_sumcheck, claims_sum) = sum_check_prover_gkr_before_last::<E, _, _>(
                claim, num_rounds, poly_vec, comb_func, transcript,
            );

            let (claims_sum_p1, claims_sum_p0, claims_sum_q1, claims_sum_q0, _claims_eq) =
                claims_sum;

            let data = vec![claims_sum_p1, claims_sum_p0, claims_sum_q1, claims_sum_q0];
            transcript.reseed(H::hash_elements(&data));

            // Produce a random challenge to condense claims into a single claim
            let r_layer = transcript.draw().unwrap();

            claims_to_verify = (
                claims_sum_p1 + r_layer * (claims_sum_p0 - claims_sum_p1),
                claims_sum_q1 + r_layer * (claims_sum_q0 - claims_sum_q1),
            );

            // Collect the randomness used for the current layer in order to construct the random
            // point where the input multilinear polynomials were evaluated.
            let mut ext = rand_sumcheck;
            ext.push(r_layer);
            all_rand.push(rand);
            rand = ext;

            proof_layers.push(LayerProof {
                proof,
                claims_sum_p1,
                claims_sum_p0,
                claims_sum_q1,
                claims_sum_q0,
            });
        }
        let gkr_claim = GkrClaim {
            evaluation_point: rand.clone(),
            claimed_evaluation: claims_to_verify,
        };

        (CircuitProof { proof: proof_layers }, gkr_claim)
    }

    pub fn verify<
        C: RandomCoin<Hasher = H, BaseField = BaseElement>,
        H: ElementHasher<BaseField = BaseElement>,
    >(
        &self,
        claims_sum_vec: &[E],
        transcript: &mut C,
    ) -> ((E, E), Vec<E>) {
        let num_layers = self.proof.len() as usize - 1;
        let mut rand: Vec<E> = Vec::new();

        let data = claims_sum_vec;
        transcript.reseed(H::hash_elements(&data));

        let r_cord = transcript.draw().unwrap();

        let p_poly_coef = vec![claims_sum_vec[0], claims_sum_vec[1]];
        let q_poly_coef = vec![claims_sum_vec[2], claims_sum_vec[3]];

        let p_poly = MultiLinear::new(p_poly_coef);
        let q_poly = MultiLinear::new(q_poly_coef);
        let p_eval = p_poly.evaluate(&[r_cord]);
        let q_eval = q_poly.evaluate(&[r_cord]);

        let mut reduced_claim = (p_eval, q_eval);

        rand.push(r_cord);
        for (num_rounds, i) in (0..num_layers).enumerate() {
            let ((claim_last, rand_sumcheck), r_two_sumchecks) = self.proof[i]
                .verify_sum_check_before_last::<_, _>(reduced_claim, num_rounds + 1, transcript);

            let claims_sum_p1 = &self.proof[i].claims_sum_p1;
            let claims_sum_p0 = &self.proof[i].claims_sum_p0;
            let claims_sum_q1 = &self.proof[i].claims_sum_q1;
            let claims_sum_q0 = &self.proof[i].claims_sum_q0;

            let data = vec![
                claims_sum_p1.clone(),
                claims_sum_p0.clone(),
                claims_sum_q1.clone(),
                claims_sum_q0.clone(),
            ];
            transcript.reseed(H::hash_elements(&data));

            assert_eq!(rand.len(), rand_sumcheck.len());

            let eq: E = (0..rand.len())
                .map(|i| {
                    rand[i] * rand_sumcheck[i] + (E::ONE - rand[i]) * (E::ONE - rand_sumcheck[i])
                })
                .fold(E::ONE, |acc, term| acc * term);

            let claim_expected: E = (*claims_sum_p1 * *claims_sum_q0
                + *claims_sum_p0 * *claims_sum_q1
                + r_two_sumchecks * *claims_sum_q1 * *claims_sum_q0)
                * eq;

            assert_eq!(claim_expected, claim_last);

            // Produce a random challenge to condense claims into a single claim
            let r_layer = transcript.draw().unwrap();

            reduced_claim = (
                *claims_sum_p1 + r_layer * (*claims_sum_p0 - *claims_sum_p1),
                *claims_sum_q1 + r_layer * (*claims_sum_q0 - *claims_sum_q1),
            );

            // Collect the randomness' used for the current layer in order to construct the random
            // point where the input multilinear polynomials were evaluated.
            let mut ext = rand_sumcheck;
            ext.push(r_layer);
            rand = ext;
        }
        (reduced_claim, rand)
    }

    pub fn verify_virtual_bus<
        C: RandomCoin<Hasher = H, BaseField = BaseElement>,
        H: ElementHasher<BaseField = BaseElement>,
    >(
        &self,
        composition_polys: Vec<Vec<Arc<dyn CompositionPolynomial<E>>>>,
        final_layer_proof: super::sumcheck::FullProof<E>,
        claims_sum_vec: &[E],
        transcript: &mut C,
    ) -> (FinalEvaluationClaim<E>, Vec<E>) {
        let num_layers = self.proof.len() as usize;
        let mut rand: Vec<E> = Vec::new();

        // Check that a/b + d/e is equal to 0
        assert_ne!(claims_sum_vec[2], E::ZERO);
        assert_ne!(claims_sum_vec[3], E::ZERO);
        assert_eq!(
            claims_sum_vec[0] * claims_sum_vec[3] + claims_sum_vec[1] * claims_sum_vec[2],
            E::ZERO
        );

        let data = claims_sum_vec;
        transcript.reseed(H::hash_elements(&data));

        let r_cord = transcript.draw().unwrap();

        let p_poly_coef = vec![claims_sum_vec[0], claims_sum_vec[1]];
        let q_poly_coef = vec![claims_sum_vec[2], claims_sum_vec[3]];

        let p_poly = MultiLinear::new(p_poly_coef);
        let q_poly = MultiLinear::new(q_poly_coef);
        let p_eval = p_poly.evaluate(&[r_cord]);
        let q_eval = q_poly.evaluate(&[r_cord]);

        let mut reduced_claim = (p_eval, q_eval);

        // I) Verify all GKR layers but for the last one counting backwards.
        rand.push(r_cord);
        for (num_rounds, i) in (0..num_layers).enumerate() {
            let ((claim_last, rand_sumcheck), r_two_sumchecks) = self.proof[i]
                .verify_sum_check_before_last::<_, _>(reduced_claim, num_rounds + 1, transcript);

            let claims_sum_p1 = &self.proof[i].claims_sum_p1;
            let claims_sum_p0 = &self.proof[i].claims_sum_p0;
            let claims_sum_q1 = &self.proof[i].claims_sum_q1;
            let claims_sum_q0 = &self.proof[i].claims_sum_q0;

            let data = vec![
                claims_sum_p1.clone(),
                claims_sum_p0.clone(),
                claims_sum_q1.clone(),
                claims_sum_q0.clone(),
            ];
            transcript.reseed(H::hash_elements(&data));

            assert_eq!(rand.len(), rand_sumcheck.len());

            let eq: E = (0..rand.len())
                .map(|i| {
                    rand[i] * rand_sumcheck[i] + (E::ONE - rand[i]) * (E::ONE - rand_sumcheck[i])
                })
                .fold(E::ONE, |acc, term| acc * term);

            let claim_expected: E = (*claims_sum_p1 * *claims_sum_q0
                + *claims_sum_p0 * *claims_sum_q1
                + r_two_sumchecks * *claims_sum_q1 * *claims_sum_q0)
                * eq;

            assert_eq!(claim_expected, claim_last);

            // Produce a random challenge to condense claims into a single claim
            let r_layer = transcript.draw().unwrap();

            reduced_claim = (
                *claims_sum_p1 + r_layer * (*claims_sum_p0 - *claims_sum_p1),
                *claims_sum_q1 + r_layer * (*claims_sum_q0 - *claims_sum_q1),
            );

            let mut ext = rand_sumcheck;
            ext.push(r_layer);
            rand = ext;
        }

        // II) Verify the final GKR layer counting backwards.

        // Absorb the claims
        let data = vec![reduced_claim.0, reduced_claim.1];
        transcript.reseed(H::hash_elements(&data));

        // Squeeze challenge to reduce two sumchecks to one
        let r_sum_check = transcript.draw().unwrap();
        let reduced_claim = reduced_claim.0 + reduced_claim.1 * r_sum_check;

        let gkr_final_composed_ml = gkr_composition_from_composition_polys(
            &composition_polys,
            r_sum_check,
            1 << (num_layers + 1),
        );

        // TODO: refactor
        let composed_ml_oracle = {
            let left_num_oracle = MultiLinearOracle { id: 0 };
            let right_num_oracle = MultiLinearOracle { id: 1 };
            let left_denom_oracle = MultiLinearOracle { id: 2 };
            let right_denom_oracle = MultiLinearOracle { id: 3 };
            let eq_oracle = MultiLinearOracle { id: 4 };
            ComposedMultiLinearsOracle {
                composer: (Arc::new(gkr_final_composed_ml.clone())),
                multi_linears: vec![
                    eq_oracle,
                    left_num_oracle,
                    right_num_oracle,
                    left_denom_oracle,
                    right_denom_oracle,
                ],
            }
        };

        let claim = Claim {
            sum_value: reduced_claim,
            polynomial: composed_ml_oracle.clone(),
        };

        let final_eval_claim = sum_check_verify(&claim, final_layer_proof, transcript);

        (final_eval_claim, rand)
    }
}

fn sum_check_prover_gkr_before_last<
    E: FieldElement<BaseField = BaseElement>,
    C: RandomCoin<Hasher = H, BaseField = BaseElement>,
    H: ElementHasher<BaseField = BaseElement>,
>(
    claim: (E, E),
    num_rounds: usize,
    ml_polys: (
        &mut MultiLinear<E>,
        &mut MultiLinear<E>,
        &mut MultiLinear<E>,
        &mut MultiLinear<E>,
        &mut MultiLinear<E>,
    ),
    comb_func: impl Fn(&E, &E, &E, &E, &E, &E) -> E,
    transcript: &mut C,
) -> (SumcheckInstanceProof<E>, Vec<E>, (E, E, E, E, E)) {
    // Absorb the claims
    let data = vec![claim.0, claim.1];
    transcript.reseed(H::hash_elements(&data));

    // Squeeze challenge to reduce two sumchecks to one
    let r_sum_check = transcript.draw().unwrap();

    let (poly_a, poly_b, poly_c, poly_d, poly_x) = ml_polys;

    let mut e = claim.0 + claim.1 * r_sum_check;

    let mut r: Vec<E> = Vec::new();
    let mut round_proofs: Vec<SumCheckRoundProof<E>> = Vec::new();

    for _j in 0..num_rounds {
        let evals: (E, E, E) = {
            let mut eval_point_0 = E::ZERO;
            let mut eval_point_2 = E::ZERO;
            let mut eval_point_3 = E::ZERO;

            let len = poly_a.len() / 2;
            for i in 0..len {
                // The interpolation formula for a linear function is:
                // z * A(x) + (1 - z) * A (y)
                // z * A(1) + (1 - z) * A(0)

                // eval at z = 0: A(1)
                eval_point_0 += comb_func(
                    &poly_a[i << 1],
                    &poly_b[i << 1],
                    &poly_c[i << 1],
                    &poly_d[i << 1],
                    &poly_x[i << 1],
                    &r_sum_check,
                );

                let poly_a_u = poly_a[(i << 1) + 1];
                let poly_a_v = poly_a[i << 1];
                let poly_b_u = poly_b[(i << 1) + 1];
                let poly_b_v = poly_b[i << 1];
                let poly_c_u = poly_c[(i << 1) + 1];
                let poly_c_v = poly_c[i << 1];
                let poly_d_u = poly_d[(i << 1) + 1];
                let poly_d_v = poly_d[i << 1];
                let poly_x_u = poly_x[(i << 1) + 1];
                let poly_x_v = poly_x[i << 1];

                // eval at z = 2: 2 * A(1) - A(0)
                let poly_a_extrapolated_point = poly_a_u + poly_a_u - poly_a_v;
                let poly_b_extrapolated_point = poly_b_u + poly_b_u - poly_b_v;
                let poly_c_extrapolated_point = poly_c_u + poly_c_u - poly_c_v;
                let poly_d_extrapolated_point = poly_d_u + poly_d_u - poly_d_v;
                let poly_x_extrapolated_point = poly_x_u + poly_x_u - poly_x_v;
                eval_point_2 += comb_func(
                    &poly_a_extrapolated_point,
                    &poly_b_extrapolated_point,
                    &poly_c_extrapolated_point,
                    &poly_d_extrapolated_point,
                    &poly_x_extrapolated_point,
                    &r_sum_check,
                );

                // eval at z = 3: 3 * A(1) - 2 * A(0) = 2 * A(1) - A(0) + A(1) - A(0)
                // hence we can compute the evaluation at z + 1 from that of z for z > 1
                let poly_a_extrapolated_point = poly_a_extrapolated_point + poly_a_u - poly_a_v;
                let poly_b_extrapolated_point = poly_b_extrapolated_point + poly_b_u - poly_b_v;
                let poly_c_extrapolated_point = poly_c_extrapolated_point + poly_c_u - poly_c_v;
                let poly_d_extrapolated_point = poly_d_extrapolated_point + poly_d_u - poly_d_v;
                let poly_x_extrapolated_point = poly_x_extrapolated_point + poly_x_u - poly_x_v;

                eval_point_3 += comb_func(
                    &poly_a_extrapolated_point,
                    &poly_b_extrapolated_point,
                    &poly_c_extrapolated_point,
                    &poly_d_extrapolated_point,
                    &poly_x_extrapolated_point,
                    &r_sum_check,
                );
            }

            (eval_point_0, eval_point_2, eval_point_3)
        };

        let eval_0 = evals.0;
        let eval_2 = evals.1;
        let eval_3 = evals.2;

        let evals = vec![e - eval_0, eval_2, eval_3];
        let compressed_poly = SumCheckRoundProof { poly_evals: evals };

        // append the prover's message to the transcript
        transcript.reseed(H::hash_elements(&compressed_poly.poly_evals));

        // derive the verifier's challenge for the next round
        let r_j = transcript.draw().unwrap();
        r.push(r_j);

        poly_a.bind_assign(r_j);
        poly_b.bind_assign(r_j);
        poly_c.bind_assign(r_j);
        poly_d.bind_assign(r_j);

        poly_x.bind_assign(r_j);

        e = compressed_poly.evaluate(e, r_j);

        round_proofs.push(compressed_poly);
    }
    let claims_sum = (poly_a[0], poly_b[0], poly_c[0], poly_d[0], poly_x[0]);

    (SumcheckInstanceProof { round_proofs }, r, claims_sum)
}

#[cfg(test)]
mod sum_circuit_tests {
    use crate::rand::RpoRandomCoin;

    use super::*;
    use rand::Rng;
    use rand_utils::rand_value;
    use BaseElement as Felt;

    /// The following tests the fractional sum circuit to check that \sum_{i = 0}^{log(m)-1} m / 2^{i} = 2 * (m - 1)
    #[test]
    fn sum_circuit_example() {
        let n = 4; // n := log(m)
        let mut inp: Vec<Felt> = (0..n).map(|_| Felt::from(1_u64 << n)).collect();
        let inp_: Vec<Felt> = (0..n).map(|i| Felt::from(1_u64 << i)).collect();
        inp.extend(inp_.iter());

        let summation = MultiLinear::new(inp);

        let expected_output = Felt::from(2 * ((1_u64 << n) - 1));

        let mut circuit = FractionalSumCircuit::new(&summation);

        let seed = [BaseElement::ZERO; 4];
        let mut transcript = RpoRandomCoin::new(seed.into());

        let (proof, _evals, _) = CircuitProof::prove(&mut circuit, &mut transcript);

        let (p1, q1) = circuit.evaluate(Felt::from(1_u8));
        let (p0, q0) = circuit.evaluate(Felt::from(0_u8));
        assert_eq!(expected_output, (p1 * q0 + q1 * p0) / (q1 * q0));

        let seed = [BaseElement::ZERO; 4];
        let mut transcript = RpoRandomCoin::new(seed.into());
        let claims = vec![p0, p1, q0, q1];
        proof.verify(&claims, &mut transcript);
    }

    // Test the fractional sum GKR in the context of LogUp.
    #[test]
    fn log_up() {
        use rand::distributions::Slice;

        let n: usize = 16;
        let num_w: usize = 31; // This should be of the form 2^k - 1
        let rng = rand::thread_rng();

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
        let mut p: Vec<Felt> = m_table.iter().map(|m| Felt::from(*m as u32)).collect();
        p.extend((0..(num_w * (1 << n))).map(|_| Felt::from(1_u32)).collect::<Vec<Felt>>());

        // Sample the challenge alpha to construct the denominators.
        let alpha = rand_value();

        // Construct the denominators
        let mut q: Vec<Felt> = t_table.iter().map(|t| Felt::from(*t) - alpha).collect();
        for w_table in w_tables {
            q.extend(w_table.iter().map(|w| alpha - Felt::from(*w)).collect::<Vec<Felt>>());
        }

        // Build the input to the fractional sum GKR circuit
        p.extend(q);
        let input = p;

        let summation = MultiLinear::new(input);

        let expected_output = Felt::from(0_u8);

        let mut circuit = FractionalSumCircuit::new(&summation);

        let seed = [BaseElement::ZERO; 4];
        let mut transcript = RpoRandomCoin::new(seed.into());

        let (proof, _evals, _) = CircuitProof::prove(&mut circuit, &mut transcript);

        let (p1, q1) = circuit.evaluate(Felt::from(1_u8));
        let (p0, q0) = circuit.evaluate(Felt::from(0_u8));
        assert_eq!(expected_output, (p1 * q0 + q1 * p0) / (q1 * q0)); // This check should be part of verification

        let seed = [BaseElement::ZERO; 4];
        let mut transcript = RpoRandomCoin::new(seed.into());
        let claims = vec![p0, p1, q0, q1];
        proof.verify(&claims, &mut transcript);
    }
}

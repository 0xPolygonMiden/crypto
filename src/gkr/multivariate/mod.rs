use core::ops::Index;

use alloc::sync::Arc;
use winter_math::{fields::f64::BaseElement, log2, FieldElement, StarkField};

mod eq_poly;
pub use eq_poly::EqPolynomial;

#[derive(Clone, Debug)]
pub struct MultiLinear<E: FieldElement> {
    pub num_variables: usize,
    pub evaluations: Vec<E>,
}

impl<E: FieldElement> MultiLinear<E> {
    pub fn new(values: Vec<E>) -> Self {
        Self {
            num_variables: log2(values.len()) as usize,
            evaluations: values,
        }
    }

    pub fn from_values(values: &[E]) -> Self {
        Self {
            num_variables: log2(values.len()) as usize,
            evaluations: values.to_owned(),
        }
    }

    pub fn num_variables(&self) -> usize {
        self.num_variables
    }

    pub fn evaluations(&self) -> &[E] {
        &self.evaluations
    }

    pub fn len(&self) -> usize {
        self.evaluations.len()
    }

    pub fn evaluate(&self, query: &[E]) -> E {
        let tensored_query = tensorize(query);
        inner_product(&self.evaluations, &tensored_query)
    }

    pub fn bind(&self, round_challenge: E) -> Self {
        let mut result = vec![E::ZERO; 1 << (self.num_variables() - 1)];
        for i in 0..(1 << (self.num_variables() - 1)) {
            result[i] = self.evaluations[i << 1]
                + round_challenge * (self.evaluations[(i << 1) + 1] - self.evaluations[i << 1]);
        }
        Self::from_values(&result)
    }

    pub fn bind_assign(&mut self, round_challenge: E) {
        let mut result = vec![E::ZERO; 1 << (self.num_variables() - 1)];
        for i in 0..(1 << (self.num_variables() - 1)) {
            result[i] = self.evaluations[i << 1]
                + round_challenge * (self.evaluations[(i << 1) + 1] - self.evaluations[i << 1]);
        }
        *self = Self::from_values(&result);
    }

    pub fn split(&self, at: usize) -> (Self, Self) {
        assert!(at < self.len());
        (
            Self::new(self.evaluations[..at].to_vec()),
            Self::new(self.evaluations[at..2 * at].to_vec()),
        )
    }

    pub fn extend(&mut self, other: &MultiLinear<E>) {
        let other_vec = other.evaluations.to_vec();
        assert_eq!(other_vec.len(), self.len());
        self.evaluations.extend(other_vec);
        self.num_variables += 1;
    }
}

impl<E: FieldElement> Index<usize> for MultiLinear<E> {
    type Output = E;

    fn index(&self, index: usize) -> &E {
        &(self.evaluations[index])
    }
}

/// A multi-variate polynomial for composing individual multi-linear polynomials
pub trait CompositionPolynomial<E: FieldElement>: Sync + Send {
    /// The number of variables when interpreted as a multi-variate polynomial.
    fn num_variables(&self) -> usize;

    /// Maximum degree in all variables.
    fn max_degree(&self) -> usize;

    /// Given a query, of length equal the number of variables, evaluate [Self] at this query.
    fn evaluate(&self, query: &[E]) -> E;
}

pub struct ComposedMultiLinears<E: FieldElement> {
    pub composer: Arc<dyn CompositionPolynomial<E>>,
    pub multi_linears: Vec<MultiLinear<E>>,
}

impl<E: FieldElement> ComposedMultiLinears<E> {
    pub fn new(
        composer: Arc<dyn CompositionPolynomial<E>>,
        multi_linears: Vec<MultiLinear<E>>,
    ) -> Self {
        Self { composer, multi_linears }
    }

    pub fn num_ml(&self) -> usize {
        self.multi_linears.len()
    }

    pub fn num_variables(&self) -> usize {
        self.composer.num_variables()
    }

    pub fn num_variables_ml(&self) -> usize {
        self.multi_linears[0].num_variables
    }

    pub fn degree(&self) -> usize {
        self.composer.max_degree()
    }

    pub fn bind(&self, round_challenge: E) -> ComposedMultiLinears<E> {
        let result: Vec<MultiLinear<E>> =
            self.multi_linears.iter().map(|f| f.bind(round_challenge)).collect();

        Self {
            composer: self.composer.clone(),
            multi_linears: result,
        }
    }
}

#[derive(Clone)]
pub struct ComposedMultiLinearsOracle<E: FieldElement> {
    pub composer: Arc<dyn CompositionPolynomial<E>>,
    pub multi_linears: Vec<MultiLinearOracle>,
}

#[derive(Debug, Clone)]
pub struct MultiLinearOracle {
    pub id: usize,
}

// Composition polynomials

pub struct IdentityComposition {
    num_variables: usize,
}

impl IdentityComposition {
    pub fn new() -> Self {
        Self { num_variables: 1 }
    }
}

impl<E> CompositionPolynomial<E> for IdentityComposition
where
    E: FieldElement,
{
    fn num_variables(&self) -> usize {
        self.num_variables
    }

    fn max_degree(&self) -> usize {
        self.num_variables
    }

    fn evaluate(&self, query: &[E]) -> E {
        assert_eq!(query.len(), 1);
        query[0]
    }
}

pub struct ProjectionComposition {
    coordinate: usize,
}

impl ProjectionComposition {
    pub fn new(coordinate: usize) -> Self {
        Self { coordinate }
    }
}

impl<E> CompositionPolynomial<E> for ProjectionComposition
where
    E: FieldElement,
{
    fn num_variables(&self) -> usize {
        1
    }

    fn max_degree(&self) -> usize {
        1
    }

    fn evaluate(&self, query: &[E]) -> E {
        query[self.coordinate]
    }
}

pub struct LogUpDenominatorTableComposition<E>
where
    E: FieldElement,
{
    projection_coordinate: usize,
    alpha: E,
}

impl<E> LogUpDenominatorTableComposition<E>
where
    E: FieldElement,
{
    pub fn new(projection_coordinate: usize, alpha: E) -> Self {
        Self { projection_coordinate, alpha }
    }
}

impl<E> CompositionPolynomial<E> for LogUpDenominatorTableComposition<E>
where
    E: FieldElement,
{
    fn num_variables(&self) -> usize {
        1
    }

    fn max_degree(&self) -> usize {
        1
    }

    fn evaluate(&self, query: &[E]) -> E {
        query[self.projection_coordinate] + self.alpha
    }
}

pub struct LogUpDenominatorWitnessComposition<E>
where
    E: FieldElement,
{
    projection_coordinate: usize,
    alpha: E,
}

impl<E> LogUpDenominatorWitnessComposition<E>
where
    E: FieldElement,
{
    pub fn new(projection_coordinate: usize, alpha: E) -> Self {
        Self { projection_coordinate, alpha }
    }
}

impl<E> CompositionPolynomial<E> for LogUpDenominatorWitnessComposition<E>
where
    E: FieldElement,
{
    fn num_variables(&self) -> usize {
        1
    }

    fn max_degree(&self) -> usize {
        1
    }

    fn evaluate(&self, query: &[E]) -> E {
        -(query[self.projection_coordinate] + self.alpha)
    }
}

pub struct ProductComposition {
    num_variables: usize,
}

impl ProductComposition {
    pub fn new(num_variables: usize) -> Self {
        Self { num_variables }
    }
}

impl<E> CompositionPolynomial<E> for ProductComposition
where
    E: FieldElement,
{
    fn num_variables(&self) -> usize {
        self.num_variables
    }

    fn max_degree(&self) -> usize {
        self.num_variables
    }

    fn evaluate(&self, query: &[E]) -> E {
        query.iter().fold(E::ONE, |acc, x| acc * *x)
    }
}

pub struct SumComposition {
    num_variables: usize,
}

impl SumComposition {
    pub fn new(num_variables: usize) -> Self {
        Self { num_variables }
    }
}

impl<E> CompositionPolynomial<E> for SumComposition
where
    E: FieldElement,
{
    fn num_variables(&self) -> usize {
        self.num_variables
    }

    fn max_degree(&self) -> usize {
        self.num_variables
    }

    fn evaluate(&self, query: &[E]) -> E {
        query.iter().fold(E::ZERO, |acc, x| acc + *x)
    }
}

pub struct GkrCompositionVanilla<E: 'static>
where
    E: FieldElement,
{
    num_variables_ml: usize,
    num_variables_merge: usize,
    combining_randomness: E,
    gkr_randomness: Vec<E>,
}

impl<E> GkrCompositionVanilla<E>
where
    E: FieldElement,
{
    pub fn new(
        num_variables_ml: usize,
        num_variables_merge: usize,
        combining_randomness: E,
        gkr_randomness: Vec<E>,
    ) -> Self {
        Self {
            num_variables_ml,
            num_variables_merge,
            combining_randomness,
            gkr_randomness,
        }
    }
}

impl<E> CompositionPolynomial<E> for GkrCompositionVanilla<E>
where
    E: FieldElement,
{
    fn num_variables(&self) -> usize {
        self.num_variables_ml // + TODO
    }

    fn max_degree(&self) -> usize {
        self.num_variables_ml //TODO
    }

    fn evaluate(&self, query: &[E]) -> E {
        let eval_left_numerator = query[0];
        let eval_right_numerator = query[1];
        let eval_left_denominator = query[2];
        let eval_right_denominator = query[3];
        let eq_eval = query[4];

        eq_eval
            * ((eval_left_numerator * eval_right_denominator
                + eval_right_numerator * eval_left_denominator)
                + eval_left_denominator * eval_right_denominator * self.combining_randomness)
    }
}

#[derive(Clone)]
pub struct GkrComposition<E>
where
    E: FieldElement<BaseField = BaseElement>,
{
    pub num_variables_ml: usize,
    pub combining_randomness: E,

    eq_composer: Arc<dyn CompositionPolynomial<E>>,
    right_numerator_composer: Vec<Arc<dyn CompositionPolynomial<E>>>,
    left_numerator_composer: Vec<Arc<dyn CompositionPolynomial<E>>>,
    right_denominator_composer: Vec<Arc<dyn CompositionPolynomial<E>>>,
    left_denominator_composer: Vec<Arc<dyn CompositionPolynomial<E>>>,
}

impl<E> GkrComposition<E>
where
    E: FieldElement<BaseField = BaseElement>,
{
    pub fn new(
        num_variables_ml: usize,
        combining_randomness: E,
        eq_composer: Arc<dyn CompositionPolynomial<E>>,
        right_numerator_composer: Vec<Arc<dyn CompositionPolynomial<E>>>,
        left_numerator_composer: Vec<Arc<dyn CompositionPolynomial<E>>>,
        right_denominator_composer: Vec<Arc<dyn CompositionPolynomial<E>>>,
        left_denominator_composer: Vec<Arc<dyn CompositionPolynomial<E>>>,
    ) -> Self {
        Self {
            num_variables_ml,
            combining_randomness,
            eq_composer,
            right_numerator_composer,
            left_numerator_composer,
            right_denominator_composer,
            left_denominator_composer,
        }
    }
}

impl<E> CompositionPolynomial<E> for GkrComposition<E>
where
    E: FieldElement<BaseField = BaseElement>,
{
    fn num_variables(&self) -> usize {
        self.num_variables_ml // + TODO
    }

    fn max_degree(&self) -> usize {
        3 // TODO
    }

    fn evaluate(&self, query: &[E]) -> E {
        let eval_right_numerator = self.right_numerator_composer[0].evaluate(query);
        let eval_left_numerator = self.left_numerator_composer[0].evaluate(query);
        let eval_right_denominator = self.right_denominator_composer[0].evaluate(query);
        let eval_left_denominator = self.left_denominator_composer[0].evaluate(query);
        let eq_eval = self.eq_composer.evaluate(query);

        let res = eq_eval
            * ((eval_left_numerator * eval_right_denominator
                + eval_right_numerator * eval_left_denominator)
                + eval_left_denominator * eval_right_denominator * self.combining_randomness);
        res
    }
}

/// Generates a composed ML polynomial for the initial GKR layer from a vector of composition
/// polynomials.
/// The composition polynomials are divided into LeftNumerator, RightNumerator, LeftDenominator
/// and RightDenominator.
/// TODO: Generalize this to the case where each numerator/denominator contains more than one
/// composition polynomial i.e., a merged composed ML polynomial.
pub fn gkr_composition_from_composition_polys<
    E: FieldElement<BaseField = BaseElement> + 'static,
>(
    composition_polys: &Vec<Vec<Arc<dyn CompositionPolynomial<E>>>>,
    combining_randomness: E,
    num_variables: usize,
) -> GkrComposition<E> {
    let eq_composer = Arc::new(ProjectionComposition::new(4));
    let left_numerator = composition_polys[0].to_owned();
    let right_numerator = composition_polys[1].to_owned();
    let left_denominator = composition_polys[2].to_owned();
    let right_denominator = composition_polys[3].to_owned();
    GkrComposition::new(
        num_variables,
        combining_randomness,
        eq_composer,
        right_numerator,
        left_numerator,
        right_denominator,
        left_denominator,
    )
}

/// Generates a plain oracle for the sum-check protocol except the final one.
pub fn gen_plain_gkr_oracle<E: FieldElement<BaseField = BaseElement> + 'static>(
    num_rounds: usize,
    r_sum_check: E,
) -> ComposedMultiLinearsOracle<E> {
    let gkr_composer = Arc::new(GkrCompositionVanilla::new(num_rounds, 0, r_sum_check, vec![]));

    let ml_oracles = vec![
        MultiLinearOracle { id: 0 },
        MultiLinearOracle { id: 1 },
        MultiLinearOracle { id: 2 },
        MultiLinearOracle { id: 3 },
        MultiLinearOracle { id: 4 },
    ];

    let oracle = ComposedMultiLinearsOracle {
        composer: gkr_composer,
        multi_linears: ml_oracles,
    };
    oracle
}

fn to_index<E: FieldElement<BaseField = BaseElement>>(index: &[E]) -> usize {
    let res = index.iter().fold(E::ZERO, |acc, term| acc * E::ONE.double() + (*term));
    let res = res.base_element(0);
    res.as_int() as usize
}

fn inner_product<E: FieldElement>(evaluations: &[E], tensored_query: &[E]) -> E {
    assert_eq!(evaluations.len(), tensored_query.len());
    evaluations
        .iter()
        .zip(tensored_query.iter())
        .fold(E::ZERO, |acc, (x_i, y_i)| acc + *x_i * *y_i)
}

pub fn tensorize<E: FieldElement>(query: &[E]) -> Vec<E> {
    let nu = query.len();
    let n = 1 << nu;

    (0..n).map(|i| lagrange_basis_eval(query, i)).collect()
}

fn lagrange_basis_eval<E: FieldElement>(query: &[E], i: usize) -> E {
    query
        .iter()
        .enumerate()
        .map(|(j, x_j)| if i & (1 << j) == 0 { E::ONE - *x_j } else { *x_j })
        .fold(E::ONE, |acc, v| acc * v)
}

pub fn compute_claim<E: FieldElement>(poly: &ComposedMultiLinears<E>) -> E {
    let cube_size = 1 << poly.num_variables_ml();
    let mut res = E::ZERO;

    for i in 0..cube_size {
        let eval_point: Vec<E> =
            poly.multi_linears.iter().map(|poly| poly.evaluations[i]).collect();
        res += poly.composer.evaluate(&eval_point);
    }
    res
}

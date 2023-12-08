use super::FieldElement;

pub struct EqPolynomial<E> {
    r: Vec<E>,
}

impl<E: FieldElement> EqPolynomial<E> {
    pub fn new(r: Vec<E>) -> Self {
        EqPolynomial { r }
    }

    pub fn evaluate(&self, rho: &[E]) -> E {
        assert_eq!(self.r.len(), rho.len());
        (0..rho.len())
            .map(|i| self.r[i] * rho[i] + (E::ONE - self.r[i]) * (E::ONE - rho[i]))
            .fold(E::ONE, |acc, term| acc * term)
    }

    pub fn evaluations(&self) -> Vec<E> {
        let nu = self.r.len();

        let mut evals: Vec<E> = vec![E::ONE; 1 << nu];
        let mut size = 1;
        for j in 0..nu {
            size *= 2;
            for i in (0..size).rev().step_by(2) {
                let scalar = evals[i / 2];
                evals[i] = scalar * self.r[j];
                evals[i - 1] = scalar - evals[i];
            }
        }
        evals
    }
}

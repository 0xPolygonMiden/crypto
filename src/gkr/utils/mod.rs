use winter_math::{FieldElement, batch_inversion};


pub fn barycentric_weights<E: FieldElement>(points: &[(E, E)]) -> Vec<E> {
    let n = points.len();
    let tmp = (0..n)
        .map(|i| (0..n).filter(|&j| j != i).fold(E::ONE, |acc, j| acc * (points[i].0 - points[j].0)))
        .collect::<Vec<_>>();
    batch_inversion(&tmp)
}

pub fn evaluate_barycentric<E: FieldElement>(
    points: &[(E, E)],
    x: E,
    barycentric_weights: &[E],
) -> E {
    for &(x_i, y_i) in points {
        if x_i == x {
            return y_i;
        }
    }

    let l_x: E = points.iter().fold(E::ONE, |acc, &(x_i, _y_i)| acc * (x - x_i));

    let sum = (0..points.len()).fold(E::ZERO, |acc, i| {
        let x_i = points[i].0;
        let y_i = points[i].1;
        let w_i = barycentric_weights[i];
        acc + (w_i / (x - x_i) * y_i)
    });

    l_x * sum
}
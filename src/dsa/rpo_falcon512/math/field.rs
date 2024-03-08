use super::{fft::CyclotomicFourier, Inverse};
use crate::dsa::rpo_falcon512::MODULUS;
use core::ops::DivAssign;
use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};
use num::{One, Zero};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FalconFelt(u32);

impl FalconFelt {
    pub const fn new(value: i16) -> Self {
        let gtz_bool = value >= 0;
        let gtz_int = gtz_bool as i16;
        let gtz_sign = gtz_int - ((!gtz_bool) as i16);
        let reduced = gtz_sign * ((gtz_sign * value) % (MODULUS as i16));
        let canonical_representative = (reduced + (MODULUS as i16) * (1 - gtz_int)) as u32;
        FalconFelt(canonical_representative)
    }

    pub const fn value(&self) -> i16 {
        self.0 as i16
    }

    pub fn balanced_value(&self) -> i16 {
        let value = self.value();
        let g = (value > ((MODULUS as i16) / 2)) as i16;
        value - (MODULUS as i16) * g
    }

    pub const fn multiply(&self, other: Self) -> Self {
        FalconFelt((self.0 * other.0) % MODULUS)
    }
}

impl Add for FalconFelt {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        let (s, _) = self.0.overflowing_add(rhs.0);
        let (d, n) = s.overflowing_sub(MODULUS);
        let (r, _) = d.overflowing_add(MODULUS * (n as u32));
        FalconFelt(r)
    }
}

impl AddAssign for FalconFelt {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for FalconFelt {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
    }
}

impl SubAssign for FalconFelt {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Neg for FalconFelt {
    type Output = FalconFelt;

    fn neg(self) -> Self::Output {
        let is_nonzero = self.0 != 0;
        let r = MODULUS - self.0;
        FalconFelt(r * (is_nonzero as u32))
    }
}

impl Mul for FalconFelt {
    fn mul(self, rhs: Self) -> Self::Output {
        FalconFelt((self.0 * rhs.0) % MODULUS)
    }

    type Output = Self;
}

impl MulAssign for FalconFelt {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Div for FalconFelt {
    type Output = FalconFelt;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse_or_zero()
    }
}

impl DivAssign for FalconFelt {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl Zero for FalconFelt {
    fn zero() -> Self {
        FalconFelt::new(0)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl One for FalconFelt {
    fn one() -> Self {
        FalconFelt::new(1)
    }
}

impl Inverse for FalconFelt {
    fn inverse_or_zero(self) -> Self {
        // q-2 = 0b10 11 11 11  11 11 11
        let two = self.multiply(self);
        let three = two.multiply(self);
        let six = three.multiply(three);
        let twelve = six.multiply(six);
        let fifteen = twelve.multiply(three);
        let thirty = fifteen.multiply(fifteen);
        let sixty = thirty.multiply(thirty);
        let sixty_three = sixty.multiply(three);

        let sixty_three_sq = sixty_three.multiply(sixty_three);
        let sixty_three_qu = sixty_three_sq.multiply(sixty_three_sq);
        let sixty_three_oc = sixty_three_qu.multiply(sixty_three_qu);
        let sixty_three_hx = sixty_three_oc.multiply(sixty_three_oc);
        let sixty_three_tt = sixty_three_hx.multiply(sixty_three_hx);
        let sixty_three_sf = sixty_three_tt.multiply(sixty_three_tt);

        let all_ones = sixty_three_sf.multiply(sixty_three);
        let two_e_twelve = all_ones.multiply(self);
        let two_e_thirteen = two_e_twelve.multiply(two_e_twelve);

        two_e_thirteen.multiply(all_ones)
    }
}

impl CyclotomicFourier for FalconFelt {
    fn primitive_root_of_unity(n: usize) -> Self {
        let log2n = n.ilog2();
        assert!(log2n <= 12);
        // and 1331 is a twelfth root of unity
        let mut a = FalconFelt::new(1331);
        let num_squarings = 12 - n.ilog2();
        for _ in 0..num_squarings {
            a *= a;
        }
        a
    }
}

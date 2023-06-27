#include "test_sve.h"
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define ZERO_ARRAY                                                                                                     \
	{                                                                                                              \
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                                                                     \
	}

const uint64_t ONES[STATE_WIDTH] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
const uint64_t ZEROES[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const uint64_t THIRTY_TWOS[STATE_WIDTH] = {32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32};

bool will_sum_overflow(uint64_t a, uint64_t b)
{
	if ((UINT_MAX - a) < b)
	{
		return true;
	}

	return false;
}

bool will_sub_overflow(uint64_t a, uint64_t b) { return a < b; }

void sve_shift_left(uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
{
	int64_t i = 0;
	svbool_t pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH);
	do
	{
		svuint64_t x_vec = svld1(pg, &x[i]);
		svuint64_t y_vec = svld1(pg, &y[i]);
		svst1(pg, &result[i], svlsl_z(pg, x_vec, y_vec));

		i += svcntd();
		pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH); // [1]
	} while (svptest_any(svptrue_b64(), pg));
}

void sve_shift_right(uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
{
	int64_t i = 0;
	svbool_t pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH);
	do
	{
		svuint64_t x_vec = svld1(pg, &x[i]);
		svuint64_t y_vec = svld1(pg, &y[i]);
		svst1(pg, &result[i], svlsr_z(pg, x_vec, y_vec));

		i += svcntd();
		pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH); // [1]
	} while (svptest_any(svptrue_b64(), pg));
}

void sve_add(uint64_t x[STATE_WIDTH], uint64_t y[STATE_WIDTH], uint64_t *result, uint64_t *overflowed)
{
	int64_t i = 0;
	svbool_t pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH);
	svbool_t addition_overflowed;
	do
	{
		svuint64_t x_vec = svld1(pg, &x[i]);
		svuint64_t y_vec = svld1(pg, &y[i]);
		svuint64_t addition_result = svadd_z(pg, x_vec, y_vec);
		svst1(pg, &result[i], addition_result);

		svuint64_t one_vec = svld1(pg, &ONES[i]);

		addition_overflowed = svcmplt(pg, addition_result, svmax_z(pg, x_vec, y_vec));
		svst1(addition_overflowed, &overflowed[i], one_vec);

		i += svcntd();
		pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH); // [1]
	} while (svptest_any(svptrue_b64(), pg));
}

void sve_substract(uint64_t x[STATE_WIDTH], uint64_t y[STATE_WIDTH], uint64_t *result, uint64_t *underflowed)
{
	int64_t i = 0;
	svbool_t pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH);
	svbool_t substraction_underflowed;
	do
	{
		svuint64_t x_vec = svld1(pg, &x[i]);
		svuint64_t y_vec = svld1(pg, &y[i]);
		svst1(pg, &result[i], svsub_z(pg, x_vec, y_vec));

		svuint64_t one_vec = svld1(pg, &ONES[i]);

		substraction_underflowed = svcmplt_u64(pg, x_vec, y_vec);
		svst1(substraction_underflowed, &underflowed[i], one_vec);

		i += svcntd();
		pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH); // [1]
	} while (svptest_any(svptrue_b64(), pg));
}

void sve_substract_as_u32(const uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
{
	int64_t i = 0;
	svbool_t pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH);
	do
	{
		svuint32_t x_vec = svld1(pg, (uint32_t *)&x[i]);
		svuint32_t y_vec = svld1(pg, (uint32_t *)&y[i]);
		svst1(pg, (uint32_t *)&result[i], svsub_z(pg, x_vec, y_vec));

		i += svcntd();
		pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH); // [1]
	} while (svptest_any(svptrue_b64(), pg));
}

void sve_multiply_low(const uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
{
	int64_t i = 0;
	svbool_t pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH);
	do
	{
		svuint64_t x_vec = svld1(pg, &x[i]);
		svuint64_t y_vec = svld1(pg, &y[i]);
		svst1(pg, &result[i], svmul_z(pg, x_vec, y_vec));

		i += svcntd();
		pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH); // [1]
	} while (svptest_any(svptrue_b64(), pg));
}

void sve_multiply_high(const uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
{
	int64_t i = 0;
	svbool_t pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH);
	do
	{
		svuint64_t x_vec = svld1(pg, &x[i]);
		svuint64_t y_vec = svld1(pg, &y[i]);
		svst1(pg, &result[i], svmulh_z(pg, x_vec, y_vec));

		i += svcntd();
		pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH); // [1]
	} while (svptest_any(svptrue_b64(), pg));
}

void sve_mont_red_cst(uint64_t x[STATE_WIDTH], uint64_t y[STATE_WIDTH], uint64_t *result)
{
	uint64_t e[STATE_WIDTH] = ZERO_ARRAY;
	uint64_t a[STATE_WIDTH];
	uint64_t x_shifted[STATE_WIDTH];

	sve_shift_left(x, THIRTY_TWOS, x_shifted);
	sve_add(x, x_shifted, a, e);

	uint64_t a_shifted[STATE_WIDTH];
	sve_shift_right(a, THIRTY_TWOS, a_shifted);

	uint64_t b[STATE_WIDTH];
	uint64_t _unused[STATE_WIDTH];
	sve_substract(a, a_shifted, b, _unused);
	sve_substract(b, e, b, _unused);

	uint64_t r[STATE_WIDTH];
	uint64_t c[STATE_WIDTH] = ZERO_ARRAY;

	sve_substract(y, b, r, c);

	uint64_t minus_c[STATE_WIDTH] = ZERO_ARRAY;
	sve_substract_as_u32(ZEROES, c, minus_c);

	sve_substract(r, minus_c, result, _unused);
}

void sve_multiply_montgomery_form_felts(const uint64_t a[STATE_WIDTH], const uint64_t b[STATE_WIDTH], uint64_t *result)
{
	uint64_t low[STATE_WIDTH];
	uint64_t high[STATE_WIDTH];

	sve_multiply_low(a, b, low);
	sve_multiply_high(a, b, high);

	sve_mont_red_cst(low, high, result);
}

void sve_square(uint64_t *a) { sve_multiply_montgomery_form_felts(a, a, a); }

void sve_copy(const uint64_t a[STATE_WIDTH], uint64_t *copy)
{
	int64_t i = 0;
	svbool_t pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH);
	do
	{
		svuint64_t a_vec = svld1(pg, &a[i]);
		svst1(pg, &copy[i], a_vec);

		i += svcntd();
		pg = svwhilelt_b64(i, (int64_t)STATE_WIDTH); // [1]
	} while (svptest_any(svptrue_b64(), pg));
}

void sve_exp_acc_3(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
{
	sve_copy(base, result);

	// Square each element of `result` M number of times
	for (int i = 0; i < 3; i++)
	{
		sve_square(result);
	}

	sve_multiply_montgomery_form_felts(result, tail, result);
}

void sve_exp_acc_6(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
{
	sve_copy(base, result);

	// Square each element of `result` M number of times
	for (int i = 0; i < 6; i++)
	{
		sve_square(result);
	}

	sve_multiply_montgomery_form_felts(result, tail, result);
}

void sve_exp_acc_12(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
{
	sve_copy(base, result);

	// Square each element of `result` M number of times
	for (int i = 0; i < 12; i++)
	{
		sve_square(result);
	}

	sve_multiply_montgomery_form_felts(result, tail, result);
}

void sve_exp_acc_31(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
{
	sve_copy(base, result);

	// Square each element of `result` M number of times
	for (int i = 0; i < 31; i++)
	{
		sve_square(result);
	}

	sve_multiply_montgomery_form_felts(result, tail, result);
}

void sve_apply_inv_sbox(uint64_t state[STATE_WIDTH])
{
	uint64_t t1[STATE_WIDTH];
	sve_copy(state, t1);

	sve_square(t1);

	uint64_t t2[STATE_WIDTH];
	sve_copy(t1, t2);

	sve_square(t2);

	uint64_t t3[STATE_WIDTH];
	sve_exp_acc_3(t2, t2, t3);

	uint64_t t4[STATE_WIDTH];
	sve_exp_acc_6(t3, t3, t4);

	uint64_t t5[STATE_WIDTH];
	sve_exp_acc_12(t4, t4, t5);

	uint64_t t6[STATE_WIDTH];
	sve_exp_acc_6(t5, t3, t6);

	uint64_t t7[STATE_WIDTH];
	sve_exp_acc_31(t6, t6, t7);

	sve_square(t7);
	uint64_t a[STATE_WIDTH];
	sve_multiply_montgomery_form_felts(t7, t6, a);
	sve_square(a);
	sve_square(a);

	uint64_t b[STATE_WIDTH];
	sve_multiply_montgomery_form_felts(t1, t2, b);
	sve_multiply_montgomery_form_felts(b, state, b);

	sve_multiply_montgomery_form_felts(a, b, state);
}

// /// Montgomery reduction (constant time)
// #[inline(always)]
// const fn mont_red_cst(x: u128) ->u64
// {
//     // See reference above for a description of the following implementation.
//     let xl = x as u64;
//     let xh = (x >> 64) as u64;
//     let(a, e) = xl.overflowing_add(xl << 32);

//     let b = a.wrapping_sub(a >> 32).wrapping_sub(e as u64);

//     let(r, c) = xh.overflowing_sub(b);
//     r.wrapping_sub(0u32.wrapping_sub(c as u32)as u64)
// }
uint64_t mont_red_cst(__uint128_t x)
{
	uint64_t xl = (uint64_t)x;
	uint64_t xh = x >> 64;

	bool e = will_sum_overflow(xl, xl << 32);
	uint64_t a = xl + (xl << 32);

	uint64_t b = (a - (a >> 32)) - e;

	bool c = will_sub_overflow(xh, b);
	uint64_t r = xh - b;

	return r - (uint64_t)((uint32_t)0 - (uint32_t)c);
}

// #[inline]
// fn mul(self, rhs: Self) -> Self {
//     Self(mont_red_cst((self.0 as u128) * (rhs.0 as u128)))
// }
uint64_t multiply_montgomery_form_felts(uint64_t a, uint64_t b)
{
	__uint128_t a_casted = (__uint128_t)a;
	__uint128_t b_casted = (__uint128_t)b;

	return mont_red_cst(a_casted * b_casted);
}

uint64_t square(uint64_t a) { return multiply_montgomery_form_felts(a, a); }

// #[inline(always)]
// fn exp_acc<B: StarkField, const N: usize, const M: usize>(
//     base: [B; N],
//     tail: [B; N],
// ) -> [B; N] {
//     let mut result = base;
//     for _ in 0..M {
//         result.iter_mut().for_each(|r| *r = r.square());
//     }
//     result.iter_mut().zip(tail).for_each(|(r, t)| *r *= t);
//     result
// }
void exp_acc_3(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
{
	// Copy `base` into `result`
	for (int i = 0; i < STATE_WIDTH; i++)
	{
		result[i] = base[i];
	}

	// Square each element of `result` M number of times
	for (int i = 0; i < 3; i++)
	{
		for (int j = 0; j < STATE_WIDTH; j++)
		{
			result[j] = square(result[j]);
		}
	}

	// Multiply each element of result by its corresponding tail element.
	for (int i = 0; i < STATE_WIDTH; i++)
	{
		result[i] = multiply_montgomery_form_felts(result[i], tail[i]);
	}
}

void exp_acc_6(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
{
	// Copy `base` into `result`
	for (int i = 0; i < STATE_WIDTH; i++)
	{
		result[i] = base[i];
	}

	// Square each element of `result` M number of times
	for (int i = 0; i < 6; i++)
	{
		for (int j = 0; j < STATE_WIDTH; j++)
		{
			result[j] = square(result[j]);
		}
	}

	// Multiply each element of result by its corresponding tail element.
	for (int i = 0; i < STATE_WIDTH; i++)
	{
		result[i] = multiply_montgomery_form_felts(result[i], tail[i]);
	}
}

void exp_acc_12(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
{
	// Copy `base` into `result`
	for (int i = 0; i < STATE_WIDTH; i++)
	{
		result[i] = base[i];
	}

	// Square each element of `result` M number of times
	for (int i = 0; i < 12; i++)
	{
		for (int j = 0; j < STATE_WIDTH; j++)
		{
			result[j] = square(result[j]);
		}
	}

	// Multiply each element of result by its corresponding tail element.
	for (int i = 0; i < STATE_WIDTH; i++)
	{
		result[i] = multiply_montgomery_form_felts(result[i], tail[i]);
	}
}

void exp_acc_31(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
{
	// Copy `base` into `result`
	for (int i = 0; i < STATE_WIDTH; i++)
	{
		result[i] = base[i];
	}

	// Square each element of `result` M number of times
	for (int i = 0; i < 31; i++)
	{
		for (int j = 0; j < STATE_WIDTH; j++)
		{
			result[j] = square(result[j]);
		}
	}

	// Multiply each element of result by its corresponding tail element.
	for (int i = 0; i < STATE_WIDTH; i++)
	{
		result[i] = multiply_montgomery_form_felts(result[i], tail[i]);
	}
}

// #[inline(always)]
// fn apply_inv_sbox(state: &mut [Felt; STATE_WIDTH]) {
//     // compute base^10540996611094048183 using 72 multiplications per array element
//     // 10540996611094048183 = b1001001001001001001001001001000110110110110110110110110110110111
//     // compute base^10

//     let mut t1 = *state;

//     t1.iter_mut().for_each(|t| *t = t.square());

//     // compute base^100
//     let mut t2 = t1;

//     t2.iter_mut().for_each(|t| *t = t.square());
//     // compute base^100100

//     let t3 = Self::exp_acc::<Felt, STATE_WIDTH, 3>(t2, t2);
//     // compute base^100100100100

//     let t4 = Self::exp_acc::<Felt, STATE_WIDTH, 6>(t3, t3);
//     // compute base^100100100100100100100100

//     let t5 = Self::exp_acc::<Felt, STATE_WIDTH, 12>(t4, t4);
//     // compute base^100100100100100100100100100100

//     let t6 = Self::exp_acc::<Felt, STATE_WIDTH, 6>(t5, t3);
//     // compute base^1001001001001001001001001001000100100100100100100100100100100

//     let t7 = Self::exp_acc::<Felt, STATE_WIDTH, 31>(t6, t6);
//     // compute base^1001001001001001001001001001000110110110110110110110110110110111

//     for (i, s) in state.iter_mut().enumerate() {
//         let a = (t7[i].square() * t6[i]).square().square();
//         let b = t1[i] * t2[i] * *s;
//         *s = a * b;
//     }
// }
void apply_inv_sbox_c(uint64_t state[STATE_WIDTH])
{
	uint64_t t1[STATE_WIDTH];

	// Square each element of state, call it t1
	for (int j = 0; j < STATE_WIDTH; j++)
	{
		t1[j] = square(state[j]);
	}

	uint64_t t2[STATE_WIDTH];

	// Square each element of t1, call it t2
	for (int j = 0; j < STATE_WIDTH; j++)
	{
		t2[j] = square(t1[j]);
	}

	// Call exp_acc_3(t2, t2), call it t3
	uint64_t t3[STATE_WIDTH];
	exp_acc_3(t2, t2, t3);

	// Call exp_acc_6(t3, t3), call it t4
	uint64_t t4[STATE_WIDTH];
	exp_acc_6(t3, t3, t4);

	// Call exp_acc_12(t4, t4), call it t5
	uint64_t t5[STATE_WIDTH];
	exp_acc_12(t4, t4, t5);

	// Call exp_acc_6(t5, t3), call it t6
	uint64_t t6[STATE_WIDTH];
	exp_acc_6(t5, t3, t6);

	// Call exp_acc_31(t6, t6), call it t7
	uint64_t t7[STATE_WIDTH];
	exp_acc_31(t6, t6, t7);

	for (int i = 0; i < STATE_WIDTH; i++)
	{
		uint64_t a = square(square((multiply_montgomery_form_felts((square(t7[i])), t6[i]))));
		uint64_t b = multiply_montgomery_form_felts(multiply_montgomery_form_felts(t1[i], t2[i]), state[i]);

		state[i] = multiply_montgomery_form_felts(a, b);
	}
}

void print_array(size_t len, uint64_t arr[len])
{
	printf("[");
	for (size_t i = 0; i < len; i++)
	{
		printf("%lu ", arr[i]);
	}

	printf("]\n");
}

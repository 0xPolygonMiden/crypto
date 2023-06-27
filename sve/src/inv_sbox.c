#include "inv_sbox.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool will_sum_overflow(uint64_t a, uint64_t b)
{
	if ((UINT_MAX - a) < b)
	{
		return true;
	}

	return false;
}

bool will_sub_overflow(uint64_t a, uint64_t b) { return a < b; }

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

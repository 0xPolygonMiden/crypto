#include "sve_inv_sbox.h"
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

inline void sve_shift_left(uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));
inline void sve_shift_right(uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));
inline void sve_add(uint64_t x[STATE_WIDTH], uint64_t y[STATE_WIDTH], uint64_t *result, uint64_t *overflowed)
    __attribute__((always_inline));
inline void sve_substract(uint64_t x[STATE_WIDTH], uint64_t y[STATE_WIDTH], uint64_t *result, uint64_t *underflowed)
    __attribute__((always_inline));
inline void sve_substract_as_u32(const uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));
inline void sve_multiply_low(const uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));
inline void sve_multiply_high(const uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));
inline void sve_mont_red_cst(uint64_t x[STATE_WIDTH], uint64_t y[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));
inline void sve_multiply_montgomery_form_felts(const uint64_t a[STATE_WIDTH], const uint64_t b[STATE_WIDTH],
                                               uint64_t *result) __attribute__((always_inline));
inline void sve_copy(const uint64_t a[STATE_WIDTH], uint64_t *copy) __attribute__((always_inline));
inline void sve_exp_acc_3(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));
inline void sve_exp_acc_6(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));
inline void sve_exp_acc_12(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));
inline void sve_exp_acc_31(uint64_t base[STATE_WIDTH], uint64_t tail[STATE_WIDTH], uint64_t *result)
    __attribute__((always_inline));

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

void print_array(size_t len, uint64_t arr[len])
{
	printf("[");
	for (size_t i = 0; i < len; i++)
	{
		printf("%lu ", arr[i]);
	}

	printf("]\n");
}

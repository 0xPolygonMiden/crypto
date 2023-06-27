#include "sve_inv_sbox.h"
#include <assert.h>

int main()
{
	test_sve_shift_left();
	test_sve_shift_right();
	test_sve_add();
	test_sve_substract();

	return 0;
}

void test_sve_shift_left()
{
	uint64_t x[STATE_WIDTH] = {0, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};
	uint64_t y[STATE_WIDTH] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	uint64_t result[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_shift_left(x, y, result);
	print_array(STATE_WIDTH, result);

	uint64_t expected[STATE_WIDTH] = {
	    0, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096,
	};
	assert(result == expected);
}

void test_sve_shift_right()
{
	uint64_t x[STATE_WIDTH] = {0, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};
	uint64_t y[STATE_WIDTH] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	uint64_t result[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_shift_right(x, y, result);
	print_array(STATE_WIDTH, result);

	uint64_t expected[STATE_WIDTH] = {
	    0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
	};
	assert(result == expected);
}

void test_sve_add()
{
	uint64_t x[STATE_WIDTH] = {UINT64_MAX, UINT64_MAX, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	uint64_t y[STATE_WIDTH] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	uint64_t result[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint64_t overflowed[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_add(x, y, result, overflowed);
	print_array(STATE_WIDTH, result);
	print_array(STATE_WIDTH, overflowed);

	uint64_t expected_result[STATE_WIDTH] = {
	    0, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
	};
	uint64_t expected_overflowed[STATE_WIDTH] = {
	    1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};
	assert(result == expected_result);
	assert(overflowed == expected_overflowed);
}

void test_sve_substract()
{
	uint64_t x[STATE_WIDTH] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	uint64_t y[STATE_WIDTH] = {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
	                           UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX};
	uint64_t result[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint64_t unverflowed[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_substract(x, y, result, unverflowed);
	print_array(STATE_WIDTH, result);
	print_array(STATE_WIDTH, unverflowed);

	uint64_t expected_result[STATE_WIDTH] = {
	    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
	};
	uint64_t expected_unverflowed[STATE_WIDTH] = {
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	};
	assert(result == expected_result);
	assert(unverflowed == expected_unverflowed);
}

void test_sve_substract_as_u32()
{
	uint64_t x[STATE_WIDTH] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	uint64_t y[STATE_WIDTH] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
	uint64_t result[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_substract_as_u32(x, y, result);
	print_array(STATE_WIDTH, result);

	uint64_t expected_result[STATE_WIDTH] = {
	    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	};
	assert(result == expected_result);
}

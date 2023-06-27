#include "test_sve.h"

int main()
{
	// TEST SHIFT LEFT
	uint64_t x[STATE_WIDTH] = {0, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};
	uint64_t y[STATE_WIDTH] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	uint64_t result[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_shift_left(x, y, result);
	print_array(STATE_WIDTH, result);

	// TEST SHIFT RIGHT
	uint64_t x_1[STATE_WIDTH] = {0, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};
	uint64_t y_1[STATE_WIDTH] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	uint64_t result_1[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_shift_right(x_1, y_1, result_1);
	print_array(STATE_WIDTH, result_1);

	// TEST ADD
	uint64_t x_2[STATE_WIDTH] = {UINT64_MAX, UINT64_MAX, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	uint64_t y_2[STATE_WIDTH] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	uint64_t result_2[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint64_t overflowed_2[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_add(x_2, y_2, result_2, overflowed_2);
	print_array(STATE_WIDTH, result_2);
	print_array(STATE_WIDTH, overflowed_2);

	// TEST SUBSTRACT
	uint64_t x_3[STATE_WIDTH] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	uint64_t y_3[STATE_WIDTH] = {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX,
	                             UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX};
	uint64_t result_3[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint64_t overflowed_3[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_substract(x_3, y_3, result_3, overflowed_3);
	print_array(STATE_WIDTH, result_3);
	print_array(STATE_WIDTH, overflowed_3);

	// TEST SUBSTRACT AS u32
	uint64_t x_4[STATE_WIDTH] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	uint64_t y_4[STATE_WIDTH] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
	uint64_t result_4[STATE_WIDTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	sve_substract_as_u32(x_4, y_4, result_4);
	print_array(STATE_WIDTH, result_4);

	return 0;
}

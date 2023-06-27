#include <stddef.h>
#include <stdint.h>
#ifdef __ARM_FEATURE_SVE
#include <arm_sve.h>
#endif /* __ARM_FEATURE_SVE */

#define STATE_WIDTH 12

void print_array(size_t len, uint64_t arr[len]);
void sve_shift_left(uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result);
void sve_shift_right(uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result);
void sve_add(uint64_t x[STATE_WIDTH], uint64_t y[STATE_WIDTH], uint64_t *result, uint64_t *overflowed);
void sve_substract(uint64_t x[STATE_WIDTH], uint64_t y[STATE_WIDTH], uint64_t *result, uint64_t *overflowed);
void sve_substract_as_u32(const uint64_t x[STATE_WIDTH], const uint64_t y[STATE_WIDTH], uint64_t *result);
void sve_apply_inv_sbox(uint64_t state[STATE_WIDTH]);

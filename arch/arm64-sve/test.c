#include <stdio.h>
#include "library.h"

void print_array(size_t len, uint64_t arr[len]);

int main() {
    uint64_t C[STATE_WIDTH] = {1, 1, 1, 1 ,1, 1, 1, 1 ,1, 1, 1, 1};
    uint64_t T[STATE_WIDTH] = {1, 2, 3, 4, 1, 2, 3, 4,1, 2, 3, 4};

    add_constants_and_apply_sbox(T, C);
    add_constants_and_apply_inv_sbox(T, C);

    print_array(STATE_WIDTH, T);

    return 0;
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

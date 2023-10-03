#include <stdint.h>
#include <string.h>

/* ================================================================================================
 * RPO hashing algorithm related structs and methods.
 */

/*
 * RPO128 context.
 *
 * This structure is used by the hashing API. It is composed of an internal state that can be
 * viewed as either:
 * 1. 12 field elements in the Miden VM.
 * 2. 96 bytes.
 *
 * The first view is used for the internal state in the context of the RPO hashing algorithm. The
 * second view is used for the buffer used to absorb the data to be hashed.
 *
 * The pointer to the buffer is updated as the data is absorbed.
 *
 * 'rpo128_context' must be initialized with rpo128_init() before first use.
 */
typedef struct
{
    union
    {
        uint64_t A[12];
        uint8_t dbuf[96];
    } st;
    uint64_t dptr;
} rpo128_context;

/*
 * Initializes an RPO state
 */
void rpo128_init(rpo128_context *rc);

/*
 * Absorbs an array of bytes of length 'len' into the state.
 */
void rpo128_absorb(rpo128_context *rc, const uint8_t *in, size_t len);

/*
 * Squeezes an array of bytes of length 'len' from the state.
 */
void rpo128_squeeze(rpo128_context *rc, uint8_t *out, size_t len);

/*
 * Finalizes the state in preparation for squeezing.
 *
 * This function should be called after all the data has been absorbed.
 *
 * Note that the current implementation does not perform any sort of padding for domain separation
 * purposes. The reason being that, for our purposes, we always perform the following sequence:
 * 1. Absorb a Nonce (which is always 40 bytes packed as 8 field elements).
 * 2. Absorb the message (which is always 4 field elements).
 * 3. Call finalize.
 * 4. Squeeze the output.
 * 5. Call release.
 */
void rpo128_finalize(rpo128_context *rc);

/*
 * Releases the state.
 *
 * This function should be called after the squeeze operation is finished.
 */
void rpo128_release(rpo128_context *rc);

/* ================================================================================================
 * Hash-to-Point algorithm for signature generation and signature verification.
 */

/*
 * Hash-to-Point algorithm.
 *
 * This function generates a point in Z_q[x]/(phi) from a given message.
 *
 * It takes a finalized rpo128_context as input and it generates the coefficients of the polynomial
 * representing the point. The coefficients are stored in the array 'x'. The number of coefficients
 * is given by 'logn', which must in our case is 512.
 */
void PQCLEAN_FALCON512_CLEAN_hash_to_point_rpo(rpo128_context *rc, uint16_t *x, unsigned logn);

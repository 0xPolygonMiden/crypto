/*
 * Wrapper for implementing the PQClean API.
 */

#include <string.h>
#include "randombytes.h"
#include "falcon.h"
#include "inner.h"
#include "rpo.h"

#define NONCELEN 40

/*
 * Encoding formats (nnnn = log of degree, 9 for Falcon-512, 10 for Falcon-1024)
 *
 *   private key:
 *      header byte: 0101nnnn
 *      private f  (6 or 5 bits by element, depending on degree)
 *      private g  (6 or 5 bits by element, depending on degree)
 *      private F  (8 bits by element)
 *
 *   public key:
 *      header byte: 0000nnnn
 *      public h   (14 bits by element)
 *
 *   signature:
 *      header byte: 0011nnnn
 *      nonce     40 bytes
 *      value     (12 bits by element)
 *
 *   message + signature:
 *      signature length   (2 bytes, big-endian)
 *      nonce              40 bytes
 *      message
 *      header byte:       0010nnnn
 *      value              (12 bits by element)
 *      (signature length is 1+len(value), not counting the nonce)
 */

/* see falcon.h */
int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_from_seed_rpo(
    uint8_t *pk,
    uint8_t *sk,
    unsigned char *seed
) {
    union
    {
        uint8_t b[FALCON_KEYGEN_TEMP_9];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[512], g[512], F[512];
    uint16_t h[512];
    inner_shake256_context rng;
    size_t u, v;

    /*
     * Generate key pair.
     */
    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, sizeof seed);
    inner_shake256_flip(&rng);
    PQCLEAN_FALCON512_CLEAN_keygen(&rng, f, g, F, NULL, h, 9, tmp.b);
    inner_shake256_ctx_release(&rng);

    /*
     * Encode private key.
     */
    sk[0] = 0x50 + 9;
    u = 1;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u,
        f, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9]);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u,
        g, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9]);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u,
        F, 9, PQCLEAN_FALCON512_CLEAN_max_FG_bits[9]);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES)
    {
        return -1;
    }

    /*
     * Encode public key.
     */
    pk[0] = 0x00 + 9;
    v = PQCLEAN_FALCON512_CLEAN_modq_encode(
        pk + 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1,
        h, 9);
    if (v != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1)
    {
        return -1;
    }

    return 0;
}

int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_rpo(
    uint8_t *pk,
    uint8_t *sk
) {
    unsigned char seed[48];

    /*
     * Generate a random seed.
     */
    randombytes(seed, sizeof seed);

    return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_from_seed_rpo(pk, sk, seed);
}

/*
 * Compute the signature. nonce[] receives the nonce and must have length
 * NONCELEN bytes. sigbuf[] receives the signature value (without nonce
 * or header byte), with *sigbuflen providing the maximum value length and
 * receiving the actual value length.
 *
 * If a signature could be computed but not encoded because it would
 * exceed the output buffer size, then a new signature is computed. If
 * the provided buffer size is too low, this could loop indefinitely, so
 * the caller must provide a size that can accommodate signatures with a
 * large enough probability.
 *
 * Return value: 0 on success, -1 on error.
 */
static int do_sign(
    uint8_t *nonce,
    uint8_t *sigbuf,
    size_t *sigbuflen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
) {
    union
    {
        uint8_t b[72 * 512];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[512], g[512], F[512], G[512];
    struct
    {
        int16_t sig[512];
        uint16_t hm[512];
    } r;
    unsigned char seed[48];
    inner_shake256_context sc;
    rpo128_context rc;
    size_t u, v;

    /*
     * Decode the private key.
     */
    if (sk[0] != 0x50 + 9)
    {
        return -1;
    }
    u = 1;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        f, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9],
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        g, 9, PQCLEAN_FALCON512_CLEAN_max_fg_bits[9],
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON512_CLEAN_trim_i8_decode(
        F, 9, PQCLEAN_FALCON512_CLEAN_max_FG_bits[9],
        sk + u, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES - u);
    if (v == 0)
    {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES)
    {
        return -1;
    }
    if (!PQCLEAN_FALCON512_CLEAN_complete_private(G, f, g, F, 9, tmp.b))
    {
        return -1;
    }

    /*
     * Create a random nonce (40 bytes).
     */
    randombytes(nonce, NONCELEN);

    /* ==== Start: Deviation from the reference implementation ================================= */

    // Transform the nonce into 8 chunks each of size 5 bytes. We do this in order to be sure that
    // the conversion to field elements succeeds
    uint8_t buffer[64];
    memset(buffer, 0, 64);
    for (size_t i = 0; i < 8; i++)
    {
        buffer[8 * i] = nonce[5 * i];
        buffer[8 * i + 1] = nonce[5 * i + 1];
        buffer[8 * i + 2] = nonce[5 * i + 2];
        buffer[8 * i + 3] = nonce[5 * i + 3];
        buffer[8 * i + 4] = nonce[5 * i + 4];
    }

    /*
     * Hash message nonce + message into a vector.
     */
    rpo128_init(&rc);
    rpo128_absorb(&rc, buffer, NONCELEN + 24);
    rpo128_absorb(&rc, m, mlen);
    rpo128_finalize(&rc);
    PQCLEAN_FALCON512_CLEAN_hash_to_point_rpo(&rc, r.hm, 9);
    rpo128_release(&rc);

    /* ==== End: Deviation from the reference implementation =================================== */

    /*
     * Initialize a RNG.
     */
    randombytes(seed, sizeof seed);
    inner_shake256_init(&sc);
    inner_shake256_inject(&sc, seed, sizeof seed);
    inner_shake256_flip(&sc);

    /*
     * Compute and return the signature. This loops until a signature
     * value is found that fits in the provided buffer.
     */
    for (;;)
    {
        PQCLEAN_FALCON512_CLEAN_sign_dyn(r.sig, &sc, f, g, F, G, r.hm, 9, tmp.b);
        v = PQCLEAN_FALCON512_CLEAN_comp_encode(sigbuf, *sigbuflen, r.sig, 9);
        if (v != 0)
        {
            inner_shake256_ctx_release(&sc);
            *sigbuflen = v;
            return 0;
        }
    }
}

/*
 * Verify a signature. The nonce has size NONCELEN bytes. sigbuf[]
 * (of size sigbuflen) contains the signature value, not including the
 * header byte or nonce. Return value is 0 on success, -1 on error.
 */
static int do_verify(
    const uint8_t *nonce,
    const uint8_t *sigbuf,
    size_t sigbuflen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
) {
    union
    {
        uint8_t b[2 * 512];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    uint16_t h[512], hm[512];
    int16_t sig[512];
    rpo128_context rc;

    /*
     * Decode public key.
     */
    if (pk[0] != 0x00 + 9)
    {
        return -1;
    }
    if (PQCLEAN_FALCON512_CLEAN_modq_decode(h, 9,
                                            pk + 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1)
            != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1)
    {
        return -1;
    }
    PQCLEAN_FALCON512_CLEAN_to_ntt_monty(h, 9);

    /*
     * Decode signature.
     */
    if (sigbuflen == 0)
    {
        return -1;
    }
    if (PQCLEAN_FALCON512_CLEAN_comp_decode(sig, 9, sigbuf, sigbuflen) != sigbuflen)
    {
        return -1;
    }

    /* ==== Start: Deviation from the reference implementation ================================= */

    /*
     * Hash nonce + message into a vector.
     */

    // Transform the nonce into 8 chunks each of size 5 bytes. We do this in order to be sure that
    // the conversion to field elements succeeds
    uint8_t buffer[64];
    memset(buffer, 0, 64);
    for (size_t i = 0; i < 8; i++)
    {
        buffer[8 * i] = nonce[5 * i];
        buffer[8 * i + 1] = nonce[5 * i + 1];
        buffer[8 * i + 2] = nonce[5 * i + 2];
        buffer[8 * i + 3] = nonce[5 * i + 3];
        buffer[8 * i + 4] = nonce[5 * i + 4];
    }

    rpo128_init(&rc);
    rpo128_absorb(&rc, buffer, NONCELEN + 24);
    rpo128_absorb(&rc, m, mlen);
    rpo128_finalize(&rc);
    PQCLEAN_FALCON512_CLEAN_hash_to_point_rpo(&rc, hm, 9);
    rpo128_release(&rc);

    /* === End: Deviation from the reference implementation ==================================== */

    /*
     * Verify signature.
     */
    if (!PQCLEAN_FALCON512_CLEAN_verify_raw(hm, sig, h, 9, tmp.b))
    {
        return -1;
    }
    return 0;
}

/* see falcon.h */
int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature_rpo(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
) {
    /*
     * The PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES constant is used for
     * the signed message object (as produced by crypto_sign())
     * and includes a two-byte length value, so we take care here
     * to only generate signatures that are two bytes shorter than
     * the maximum. This is done to ensure that crypto_sign()
     * and crypto_sign_signature() produce the exact same signature
     * value, if used on the same message, with the same private key,
     * and using the same output from randombytes() (this is for
     * reproducibility of tests).
     */
    size_t vlen;

    vlen = PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES - NONCELEN - 3;
    if (do_sign(sig + 1, sig + 1 + NONCELEN, &vlen, m, mlen, sk) < 0)
    {
        return -1;
    }
    sig[0] = 0x30 + 9;
    *siglen = 1 + NONCELEN + vlen;
    return 0;
}

/* see falcon.h */
int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify_rpo(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
) {
    if (siglen < 1 + NONCELEN)
    {
        return -1;
    }
    if (sig[0] != 0x30 + 9)
    {
        return -1;
    }
    return do_verify(sig + 1, sig + 1 + NONCELEN, siglen - 1 - NONCELEN, m, mlen, pk);
}

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES 1281
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES 897
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES 666

/*
 * Generate a new key pair. Public key goes into pk[], private key in sk[].
 * Key sizes are exact (in bytes):
 *   public (pk): PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
 *   private (sk): PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES
 *
 * Return value: 0 on success, -1 on error.
 *
 * Note: This implementation follows the reference implementation in PQClean
 * https://github.com/PQClean/PQClean/tree/master/crypto_sign/falcon-512
 * verbatim except for the sections that are marked otherwise.
 */
int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_rpo(
    uint8_t *pk, uint8_t *sk);

/*
 * Generate a new key pair from  seed. Public key goes into pk[], private key in sk[].
 * Key sizes are exact (in bytes):
 *   public (pk): PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
 *   private (sk): PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES
 *
 * Return value: 0 on success, -1 on error.
 */
int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_from_seed_rpo(
    uint8_t *pk, uint8_t *sk, unsigned char *seed);

/*
 * Generate the public key from the secret key (sk). Public key goes into pk[].
 *
 * Return value: 0 on success, -1 on error.
 */
int PQCLEAN_FALCON512_CLEAN_crypto_pk_from_sk_rpo(const uint8_t *sk, uint8_t *pk);

/*
 * Compute a signature on a provided message (m, mlen), with a given
 * private key (sk). Signature is written in sig[], with length written
 * into *siglen. Signature length is variable; maximum signature length
 * (in bytes) is PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES.
 *
 * sig[], m[] and sk[] may overlap each other arbitrarily.
 *
 * Return value: 0 on success, -1 on error.
 *
 * Note: This implementation follows the reference implementation in PQClean
 * https://github.com/PQClean/PQClean/tree/master/crypto_sign/falcon-512
 * verbatim except for the sections that are marked otherwise.
 */
int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature_rpo(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk);

/*
 * Verify a signature (sig, siglen) on a message (m, mlen) with a given
 * public key (pk).
 *
 * sig[], m[] and pk[] may overlap each other arbitrarily.
 *
 * Return value: 0 on success, -1 on error.
 *
 * Note: This implementation follows the reference implementation in PQClean
 * https://github.com/PQClean/PQClean/tree/master/crypto_sign/falcon-512
 * verbatim except for the sections that are marked otherwise.
 */
int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify_rpo(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

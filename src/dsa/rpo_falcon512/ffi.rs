use libc::c_int;

// C IMPLEMENTATION INTERFACE
// ================================================================================================

extern "C" {
    /// Generate a new key pair. Public key goes into pk[], private key in sk[].
    /// Key sizes are exact (in bytes):
    /// - public (pk): 897
    /// - private (sk): 1281
    ///
    /// Return value: 0 on success, -1 on error.
    pub fn PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_rpo(pk: *mut u8, sk: *mut u8) -> c_int;

    /// Generate a new key pair from  seed. Public key goes into pk[], private key in sk[].
    /// Key sizes are exact (in bytes):
    /// - public (pk): 897
    /// - private (sk): 1281
    ///
    /// Return value: 0 on success, -1 on error.
    pub fn PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_from_seed_rpo(
        pk: *mut u8,
        sk: *mut u8,
        seed: *const u8,
    ) -> c_int;

    /// Compute a signature on a provided message (m, mlen), with a given private key (sk).
    /// Signature is written in sig[], with length written into *siglen. Signature length is
    /// variable; maximum signature length (in bytes) is 666.
    ///
    /// sig[], m[] and sk[] may overlap each other arbitrarily.
    ///
    /// Return value: 0 on success, -1 on error.
    pub fn PQCLEAN_FALCON512_CLEAN_crypto_sign_signature_rpo(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> c_int;

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Verify a signature (sig, siglen) on a message (m, mlen) with a given public key (pk).
    ///
    /// sig[], m[] and pk[] may overlap each other arbitrarily.
    ///
    /// Return value: 0 on success, -1 on error.
    #[cfg(test)]
    pub fn PQCLEAN_FALCON512_CLEAN_crypto_sign_verify_rpo(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> c_int;

    /// Hash-to-Point algorithm.
    ///
    /// This function generates a point in Z_q[x]/(phi) from a given message.
    ///
    /// It takes a finalized rpo128_context as input and it generates the coefficients of the polynomial
    /// representing the point. The coefficients are stored in the array 'x'. The number of coefficients
    /// is given by 'logn', which must in our case is 512.
    #[cfg(test)]
    pub fn PQCLEAN_FALCON512_CLEAN_hash_to_point_rpo(
        rc: *mut Rpo128Context,
        x: *mut u16,
        logn: usize,
    );

    #[cfg(test)]
    pub fn rpo128_init(sc: *mut Rpo128Context);

    #[cfg(test)]
    pub fn rpo128_absorb(
        sc: *mut Rpo128Context,
        data: *const ::std::os::raw::c_void,
        len: libc::size_t,
    );

    #[cfg(test)]
    pub fn rpo128_finalize(sc: *mut Rpo128Context);
}

#[repr(C)]
#[cfg(test)]
pub struct Rpo128Context {
    pub content: [u64; 13usize],
}

// TESTS
// ================================================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::dsa::rpo_falcon512::{NONCE_LEN, PK_LEN, SIG_LEN, SK_LEN};
    use rand::Rng;

    #[test]
    fn falcon_ffi() {
        unsafe {
            let mut rng = rand::thread_rng();

            // --- generate a key pair from a seed ----------------------------

            let mut pk = [0u8; PK_LEN];
            let mut sk = [0u8; SK_LEN];
            let seed: [u8; NONCE_LEN] =
                (0..NONCE_LEN).map(|_| rng.gen()).collect::<Vec<u8>>().try_into().unwrap();

            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_from_seed_rpo(
                    pk.as_mut_ptr(),
                    sk.as_mut_ptr(),
                    seed.as_ptr()
                )
            );

            // --- sign a message and make sure it verifies -------------------

            let mlen: usize = rng.gen::<u16>() as usize;
            let msg: Vec<u8> = (0..mlen).map(|_| rng.gen()).collect();
            let mut detached_sig = [0u8; NONCE_LEN + SIG_LEN];
            let mut siglen = 0;

            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_signature_rpo(
                    detached_sig.as_mut_ptr(),
                    &mut siglen as *mut usize,
                    msg.as_ptr(),
                    msg.len(),
                    sk.as_ptr()
                )
            );

            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_verify_rpo(
                    detached_sig.as_ptr(),
                    siglen,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr()
                )
            );

            // --- check verification of different signature ------------------

            assert_eq!(
                -1,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_verify_rpo(
                    detached_sig.as_ptr(),
                    siglen,
                    msg.as_ptr(),
                    msg.len() - 1,
                    pk.as_ptr()
                )
            );

            // --- check verification against a different pub key -------------

            let mut pk_alt = [0u8; PK_LEN];
            let mut sk_alt = [0u8; SK_LEN];
            assert_eq!(
                0,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_rpo(
                    pk_alt.as_mut_ptr(),
                    sk_alt.as_mut_ptr()
                )
            );

            assert_eq!(
                -1,
                PQCLEAN_FALCON512_CLEAN_crypto_sign_verify_rpo(
                    detached_sig.as_ptr(),
                    siglen,
                    msg.as_ptr(),
                    msg.len(),
                    pk_alt.as_ptr()
                )
            );
        }
    }
}

#[cfg(target_feature = "sve")]
pub mod optimized {
    use crate::{Felt, hash::rescue::STATE_WIDTH};

    mod ffi {
        #[link(name = "rpo_sve", kind = "static")]
        extern "C" {
            pub fn add_constants_and_apply_sbox(
                state: *mut std::ffi::c_ulong,
                constants: *const std::ffi::c_ulong,
            ) -> bool;
            pub fn add_constants_and_apply_inv_sbox(
                state: *mut std::ffi::c_ulong,
                constants: *const std::ffi::c_ulong,
            ) -> bool;
        }
    }

    #[inline(always)]
    pub fn add_constants_and_apply_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        unsafe {
            ffi::add_constants_and_apply_sbox(
                state.as_mut_ptr() as *mut u64,
                ark.as_ptr() as *const u64,
            )
        }
    }

    #[inline(always)]
    pub fn add_constants_and_apply_inv_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        unsafe {
            ffi::add_constants_and_apply_inv_sbox(
                state.as_mut_ptr() as *mut u64,
                ark.as_ptr() as *const u64,
            )
        }
    }
}

#[cfg(target_feature = "avx2")]
mod x86_64_avx2;

#[cfg(target_feature = "avx2")]
pub mod optimized {
    use super::x86_64_avx2::{apply_inv_sbox, apply_sbox};
    use crate::{
        Felt,
        hash::rescue::{STATE_WIDTH, add_constants},
    };

    #[inline(always)]
    pub fn add_constants_and_apply_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        add_constants(state, ark);
        unsafe {
            apply_sbox(std::mem::transmute(state));
        }
        true
    }

    #[inline(always)]
    pub fn add_constants_and_apply_inv_sbox(
        state: &mut [Felt; STATE_WIDTH],
        ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        add_constants(state, ark);
        unsafe {
            apply_inv_sbox(std::mem::transmute(state));
        }
        true
    }
}

#[cfg(not(any(target_feature = "avx2", target_feature = "sve")))]
pub mod optimized {
    use crate::{Felt, hash::rescue::STATE_WIDTH};

    #[inline(always)]
    pub fn add_constants_and_apply_sbox(
        _state: &mut [Felt; STATE_WIDTH],
        _ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        false
    }

    #[inline(always)]
    pub fn add_constants_and_apply_inv_sbox(
        _state: &mut [Felt; STATE_WIDTH],
        _ark: &[Felt; STATE_WIDTH],
    ) -> bool {
        false
    }
}

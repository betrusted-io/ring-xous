#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub type size_t = core::ffi::c_uint;
pub type __uint64_t = u64;
pub type uint64_t = __uint64_t;
#[no_mangle]
pub unsafe extern "C" fn bn_neg_inv_mod_r_u64(mut n: uint64_t) -> uint64_t {
    static mut alpha: uint64_t =
        (1 as u64) << 2 as core::ffi::c_int * 32 as core::ffi::c_int - 1 as core::ffi::c_int;
    let beta: uint64_t = n;
    let mut u: uint64_t = 1 as core::ffi::c_int as uint64_t;
    let mut v: uint64_t = 0 as core::ffi::c_int as uint64_t;
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < (2 as core::ffi::c_int * 32 as core::ffi::c_int) as core::ffi::c_uint {
        let mut u_is_odd: uint64_t = (0 as u64).wrapping_sub(u & 1 as core::ffi::c_int as u64);
        let mut beta_if_u_is_odd: uint64_t = beta & u_is_odd;
        u = ((u ^ beta_if_u_is_odd) >> 1 as core::ffi::c_int).wrapping_add(u & beta_if_u_is_odd);
        let mut alpha_if_u_is_odd: uint64_t = alpha & u_is_odd;
        v = (v >> 1 as core::ffi::c_int).wrapping_add(alpha_if_u_is_odd);
        i = i.wrapping_add(1);
    }
    return v;
}

#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![register_tool(c2rust)]
#![feature(register_tool)]
pub type size_t = libc::c_uint;
pub type __uint64_t = libc::c_ulonglong;
pub type uint64_t = __uint64_t;
#[no_mangle]
pub unsafe extern "C" fn bn_neg_inv_mod_r_u64(mut n: uint64_t) -> uint64_t {
    static mut alpha: uint64_t = (1 as libc::c_ulonglong)
        << 2 as libc::c_int * 32 as libc::c_int - 1 as libc::c_int;
    let beta: uint64_t = n;
    let mut u: uint64_t = 1 as libc::c_int as uint64_t;
    let mut v: uint64_t = 0 as libc::c_int as uint64_t;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < (2 as libc::c_int * 32 as libc::c_int) as libc::c_uint {
        let mut u_is_odd: uint64_t = (0 as libc::c_ulonglong)
            .wrapping_sub(u & 1 as libc::c_int as libc::c_ulonglong);
        let mut beta_if_u_is_odd: uint64_t = beta & u_is_odd;
        u = ((u ^ beta_if_u_is_odd) >> 1 as libc::c_int)
            .wrapping_add(u & beta_if_u_is_odd);
        let mut alpha_if_u_is_odd: uint64_t = alpha & u_is_odd;
        v = (v >> 1 as libc::c_int).wrapping_add(alpha_if_u_is_odd);
        i = i.wrapping_add(1);
    }
    return v;
}

#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![register_tool(c2rust)]
#![feature(register_tool)]
extern "C" {
    fn bn_mul_mont(
        rp: *mut BN_ULONG,
        ap: *const BN_ULONG,
        bp: *const BN_ULONG,
        np: *const BN_ULONG,
        n0: *const BN_ULONG,
        num: size_t,
    );
}
pub type size_t = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type uint32_t = __uint32_t;
pub type crypto_word_t = uint32_t;
pub type BN_ULONG = crypto_word_t;
pub type Limb = crypto_word_t;
static mut N: [BN_ULONG; 8] = [
    0xfc632551 as libc::c_uint,
    0xf3b9cac2 as libc::c_uint,
    0xa7179e84 as libc::c_uint,
    0xbce6faad as libc::c_uint,
    0xffffffff as libc::c_uint,
    0xffffffff as libc::c_uint,
    0 as libc::c_int as BN_ULONG,
    0xffffffff as libc::c_uint,
];
static mut N_N0: [BN_ULONG; 2] = [
    0xee00bc4f as libc::c_uint,
    0xccd1c8aa as libc::c_uint,
];
#[no_mangle]
pub unsafe extern "C" fn p256_scalar_mul_mont(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut b: *const Limb,
) {
    bn_mul_mont(
        r,
        a,
        b,
        N.as_ptr(),
        N_N0.as_ptr(),
        (256 as libc::c_int / 32 as libc::c_int) as size_t,
    );
}
#[no_mangle]
pub unsafe extern "C" fn p256_scalar_sqr_rep_mont(
    mut r: *mut Limb,
    mut a: *const Limb,
    mut rep: Limb,
) {
    p256_scalar_mul_mont(r, a, a);
    let mut i: Limb = 1 as libc::c_int as Limb;
    while i < rep {
        p256_scalar_mul_mont(r, r as *const Limb, r as *const Limb);
        i = i.wrapping_add(1);
    }
}

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern "C" {
    fn __assert_fail(
        __assertion: *const core::ffi::c_char,
        __file: *const core::ffi::c_char,
        __line: core::ffi::c_uint,
        __function: *const core::ffi::c_char,
    ) -> !;
    fn limbs_mul_add_limb(r: *mut Limb, a: *const Limb, b: Limb, num_limbs: size_t) -> Limb;
}
pub type size_t = core::ffi::c_uint;
pub type __uint32_t = core::ffi::c_uint;
pub type __uint64_t = u64;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type crypto_word_t = uint32_t;
pub type BN_ULONG = crypto_word_t;
pub type Limb = crypto_word_t;
pub type Carry = Limb;
pub type DoubleLimb = uint64_t;
#[inline]
unsafe extern "C" fn value_barrier_w(a: crypto_word_t) -> crypto_word_t {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_select_w(
    mut mask: crypto_word_t,
    a: crypto_word_t,
    b: crypto_word_t,
) -> crypto_word_t {
    mask = value_barrier_w(mask);
    return mask & a | !mask & b;
}
#[inline]
unsafe extern "C" fn limb_sbb(
    r: *mut Limb,
    a: Limb,
    b: Limb,
    borrow_in: Carry,
) -> Carry {
    let ret: Carry;
    let x: DoubleLimb = (a as DoubleLimb)
        .wrapping_sub(b as u64)
        .wrapping_sub(borrow_in as u64);
    *r = x as Limb;
    ret = (x >> 32 as core::ffi::c_uint & 1 as core::ffi::c_int as u64) as Carry;
    return ret;
}
#[inline]
unsafe extern "C" fn limb_sub(r: *mut Limb, a: Limb, b: Limb) -> Carry {
    let ret: Carry;
    let x: DoubleLimb = (a as DoubleLimb).wrapping_sub(b as u64);
    *r = x as Limb;
    ret = (x >> 32 as core::ffi::c_uint & 1 as core::ffi::c_int as u64) as Carry;
    return ret;
}
#[inline]
unsafe extern "C" fn limbs_sub(
    r: *mut Limb,
    a: *const Limb,
    b: *const Limb,
    num_limbs: size_t,
) -> Carry {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/fipsmodule/bn/../../limbs/limbs.inl\0" as *const u8
                as *const core::ffi::c_char,
            129 as core::ffi::c_int as core::ffi::c_uint,
            (*core::mem::transmute::<&[u8; 60], &[core::ffi::c_char; 60]>(
                b"Carry limbs_sub(Limb *, const Limb *, const Limb *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    let mut borrow: Carry = limb_sub(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *a.offset(0 as core::ffi::c_int as isize),
        *b.offset(0 as core::ffi::c_int as isize),
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        borrow = limb_sbb(
            &mut *r.offset(i as isize),
            *a.offset(i as isize),
            *b.offset(i as isize),
            borrow,
        );
        i = i.wrapping_add(1);
    }
    return borrow;
}
#[no_mangle]
pub unsafe extern "C" fn bn_from_montgomery_in_place(
    r: *mut BN_ULONG,
    num_r: size_t,
    mut a: *mut BN_ULONG,
    num_a: size_t,
    n: *const BN_ULONG,
    num_n: size_t,
    n0_: *const BN_ULONG,
) -> core::ffi::c_int {
    if num_n == 0 as core::ffi::c_int as core::ffi::c_uint
        || num_r != num_n
        || num_a != (2 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(num_n)
    {
        return 0 as core::ffi::c_int;
    }
    let n0: BN_ULONG = *n0_.offset(0 as core::ffi::c_int as isize);
    let mut carry: BN_ULONG = 0 as core::ffi::c_int as BN_ULONG;
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_n {
        let mut v: BN_ULONG = limbs_mul_add_limb(
            a.offset(i as isize),
            n,
            (*a.offset(i as isize)).wrapping_mul(n0),
            num_n,
        );
        v = (v as core::ffi::c_uint)
            .wrapping_add(carry.wrapping_add(*a.offset(i.wrapping_add(num_n) as isize)))
            as BN_ULONG as BN_ULONG;
        carry |= (v != *a.offset(i.wrapping_add(num_n) as isize)) as core::ffi::c_int
            as core::ffi::c_uint;
        carry &= (v <= *a.offset(i.wrapping_add(num_n) as isize)) as core::ffi::c_int
            as core::ffi::c_uint;
        *a.offset(i.wrapping_add(num_n) as isize) = v;
        i = i.wrapping_add(1);
    }
    a = a.offset(num_n as isize);
    let mut v_0: BN_ULONG = (limbs_sub(r, a as *const Limb, n, num_n)).wrapping_sub(carry);
    v_0 = (0 as core::ffi::c_uint).wrapping_sub(v_0);
    let mut i_0: size_t = 0 as core::ffi::c_int as size_t;
    while i_0 < num_n {
        *r.offset(i_0 as isize) =
            constant_time_select_w(v_0, *a.offset(i_0 as isize), *r.offset(i_0 as isize));
        *a.offset(i_0 as isize) = 0 as core::ffi::c_int as BN_ULONG;
        i_0 = i_0.wrapping_add(1);
    }
    return 1 as core::ffi::c_int;
}

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
}
pub type size_t = core::ffi::c_uint;
pub type __uint32_t = core::ffi::c_uint;
pub type __uint64_t = u64;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type crypto_word_t = uint32_t;
pub type Limb = crypto_word_t;
pub type Carry = Limb;
pub type DoubleLimb = uint64_t;
pub type BN_ULONG = crypto_word_t;
#[inline]
unsafe extern "C" fn value_barrier_w(a: crypto_word_t) -> crypto_word_t {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    return a;
}
#[inline]
unsafe extern "C" fn constant_time_msb_w(a: crypto_word_t) -> crypto_word_t {
    return (0 as core::ffi::c_uint).wrapping_sub(
        a >> (core::mem::size_of::<crypto_word_t>() as u32)
            .wrapping_mul(8 as core::ffi::c_int as core::ffi::c_uint)
            .wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint),
    );
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(a: crypto_word_t) -> crypto_word_t {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint));
}
#[inline]
unsafe extern "C" fn constant_time_is_nonzero_w(a: crypto_word_t) -> crypto_word_t {
    return !constant_time_is_zero_w(a);
}
#[inline]
unsafe extern "C" fn constant_time_eq_w(
    a: crypto_word_t,
    b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_is_zero_w(a ^ b);
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
unsafe extern "C" fn bn_umult_lohi(
    low_out: *mut BN_ULONG,
    high_out: *mut BN_ULONG,
    a: BN_ULONG,
    b: BN_ULONG,
) {
    let result: uint64_t = (a as uint64_t).wrapping_mul(b as u64);
    *low_out = result as BN_ULONG;
    *high_out = (result >> 32 as core::ffi::c_int) as BN_ULONG;
}
#[inline]
unsafe extern "C" fn limb_adc(
    r: *mut Limb,
    a: Limb,
    b: Limb,
    carry_in: Carry,
) -> Carry {
    let ret: Carry;
    let x: DoubleLimb = (a as DoubleLimb)
        .wrapping_add(b as u64)
        .wrapping_add(carry_in as u64);
    *r = x as Limb;
    ret = (x >> 32 as core::ffi::c_uint) as Carry;
    return ret;
}
#[inline]
unsafe extern "C" fn limb_add(r: *mut Limb, a: Limb, b: Limb) -> Carry {
    let ret: Carry;
    let x: DoubleLimb = (a as DoubleLimb).wrapping_add(b as u64);
    *r = x as Limb;
    ret = (x >> 32 as core::ffi::c_uint) as Carry;
    return ret;
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
unsafe extern "C" fn limbs_add(
    r: *mut Limb,
    a: *const Limb,
    b: *const Limb,
    num_limbs: size_t,
) -> Carry {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.inl\0" as *const u8 as *const core::ffi::c_char,
            118 as core::ffi::c_int as core::ffi::c_uint,
            (*core::mem::transmute::<&[u8; 60], &[core::ffi::c_char; 60]>(
                b"Carry limbs_add(Limb *, const Limb *, const Limb *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    let mut carry: Carry = limb_add(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *a.offset(0 as core::ffi::c_int as isize),
        *b.offset(0 as core::ffi::c_int as isize),
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        carry = limb_adc(
            &mut *r.offset(i as isize),
            *a.offset(i as isize),
            *b.offset(i as isize),
            carry,
        );
        i = i.wrapping_add(1);
    }
    return carry;
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
            b"crypto/limbs/limbs.inl\0" as *const u8 as *const core::ffi::c_char,
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
#[inline]
unsafe extern "C" fn limbs_select(
    r: *mut Limb,
    table: *const Limb,
    num_limbs: size_t,
    num_entries: size_t,
    index: crypto_word_t,
) {
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        *r.offset(i as isize) = 0 as core::ffi::c_int as Limb;
        i = i.wrapping_add(1);
    }
    let mut e: size_t = 0 as core::ffi::c_int as size_t;
    while e < num_entries {
        let equal: Limb = constant_time_eq_w(index, e);
        let mut i_0: size_t = 0 as core::ffi::c_int as size_t;
        while i_0 < num_limbs {
            *r.offset(i_0 as isize) = constant_time_select_w(
                equal,
                *table.offset(e.wrapping_mul(num_limbs).wrapping_add(i_0) as isize),
                *r.offset(i_0 as isize),
            );
            i_0 = i_0.wrapping_add(1);
        }
        e = e.wrapping_add(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_are_zero(a: *const Limb, num_limbs: size_t) -> Limb {
    let mut is_zero: Limb = !(0 as core::ffi::c_int as crypto_word_t);
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        is_zero = constant_time_select_w(
            is_zero,
            constant_time_is_zero_w(*a.offset(i as isize)),
            is_zero,
        );
        i = i.wrapping_add(1);
    }
    return is_zero;
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_equal(
    a: *const Limb,
    b: *const Limb,
    num_limbs: size_t,
) -> Limb {
    let mut eq: Limb = !(0 as core::ffi::c_int as crypto_word_t);
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        eq = constant_time_select_w(
            eq,
            constant_time_eq_w(*a.offset(i as isize), *b.offset(i as isize)),
            eq,
        );
        i = i.wrapping_add(1);
    }
    return eq;
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_equal_limb(
    a: *const Limb,
    b: Limb,
    num_limbs: size_t,
) -> Limb {
    if num_limbs == 0 as core::ffi::c_int as core::ffi::c_uint {
        return constant_time_is_zero_w(b);
    }
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
            51 as core::ffi::c_int as core::ffi::c_uint,
            (*core::mem::transmute::<&[u8; 50], &[core::ffi::c_char; 50]>(
                b"Limb LIMBS_equal_limb(const Limb *, Limb, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    let lo_equal: Limb = constant_time_eq_w(*a.offset(0 as core::ffi::c_int as isize), b);
    let hi_zero: Limb = LIMBS_are_zero(
        &*a.offset(1 as core::ffi::c_int as isize),
        num_limbs.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint),
    );
    return constant_time_select_w(lo_equal, hi_zero, 0 as core::ffi::c_int as crypto_word_t);
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_are_even(a: *const Limb, num_limbs: size_t) -> Limb {
    let lo: Limb;
    if num_limbs == 0 as core::ffi::c_int as core::ffi::c_uint {
        lo = 0 as core::ffi::c_int as Limb;
    } else {
        lo = *a.offset(0 as core::ffi::c_int as isize);
    }
    return constant_time_is_zero_w(lo & 1 as core::ffi::c_int as core::ffi::c_uint);
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_less_than(
    a: *const Limb,
    b: *const Limb,
    num_limbs: size_t,
) -> Limb {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
            71 as core::ffi::c_int as core::ffi::c_uint,
            (*core::mem::transmute::<&[u8; 57], &[core::ffi::c_char; 57]>(
                b"Limb LIMBS_less_than(const Limb *, const Limb *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    let mut dummy: Limb = 0;
    let mut borrow: Carry = limb_sub(
        &mut dummy,
        *a.offset(0 as core::ffi::c_int as isize),
        *b.offset(0 as core::ffi::c_int as isize),
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        borrow = limb_sbb(
            &mut dummy,
            *a.offset(i as isize),
            *b.offset(i as isize),
            borrow,
        );
        i = i.wrapping_add(1);
    }
    return constant_time_is_nonzero_w(borrow);
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_less_than_limb(
    a: *const Limb,
    b: Limb,
    num_limbs: size_t,
) -> Limb {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
            84 as core::ffi::c_int as core::ffi::c_uint,
            (*core::mem::transmute::<&[u8; 54], &[core::ffi::c_char; 54]>(
                b"Limb LIMBS_less_than_limb(const Limb *, Limb, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    let mut dummy: Limb = 0;
    let lo: Limb = constant_time_is_nonzero_w(limb_sub(
        &mut dummy,
        *a.offset(0 as core::ffi::c_int as isize),
        b,
    ));
    let hi: Limb = LIMBS_are_zero(
        &*a.offset(1 as core::ffi::c_int as isize),
        num_limbs.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint),
    );
    return constant_time_select_w(lo, hi, lo);
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_reduce_once(
    r: *mut Limb,
    m: *const Limb,
    num_limbs: size_t,
) {
    if num_limbs >= 1 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_limbs >= 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/limbs/limbs.c\0" as *const u8 as *const core::ffi::c_char,
            94 as core::ffi::c_int as core::ffi::c_uint,
            (*core::mem::transmute::<&[u8; 53], &[core::ffi::c_char; 53]>(
                b"void LIMBS_reduce_once(Limb *, const Limb *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    let lt: Limb = LIMBS_less_than(r as *const Limb, m, num_limbs);
    let mut borrow: Carry = limb_sub(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *r.offset(0 as core::ffi::c_int as isize),
        constant_time_select_w(
            lt,
            0 as core::ffi::c_int as crypto_word_t,
            *m.offset(0 as core::ffi::c_int as isize),
        ),
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        borrow = limb_sbb(
            &mut *r.offset(i as isize),
            *r.offset(i as isize),
            constant_time_select_w(
                lt,
                0 as core::ffi::c_int as crypto_word_t,
                *m.offset(i as isize),
            ),
            borrow,
        );
        i = i.wrapping_add(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_add_mod(
    r: *mut Limb,
    a: *const Limb,
    b: *const Limb,
    m: *const Limb,
    num_limbs: size_t,
) {
    let overflow1: Limb = constant_time_is_nonzero_w(limbs_add(r, a, b, num_limbs));
    let overflow2: Limb = !LIMBS_less_than(r as *const Limb, m, num_limbs);
    let overflow: Limb = overflow1 | overflow2;
    let mut borrow: Carry = limb_sub(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *r.offset(0 as core::ffi::c_int as isize),
        *m.offset(0 as core::ffi::c_int as isize) & overflow,
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        borrow = limb_sbb(
            &mut *r.offset(i as isize),
            *r.offset(i as isize),
            *m.offset(i as isize) & overflow,
            borrow,
        );
        i = i.wrapping_add(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_sub_mod(
    r: *mut Limb,
    a: *const Limb,
    b: *const Limb,
    m: *const Limb,
    num_limbs: size_t,
) {
    let underflow: Limb = constant_time_is_nonzero_w(limbs_sub(r, a, b, num_limbs));
    let mut carry: Carry = limb_add(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *r.offset(0 as core::ffi::c_int as isize),
        *m.offset(0 as core::ffi::c_int as isize) & underflow,
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i < num_limbs {
        carry = limb_adc(
            &mut *r.offset(i as isize),
            *r.offset(i as isize),
            *m.offset(i as isize) & underflow,
            carry,
        );
        i = i.wrapping_add(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_shl_mod(
    r: *mut Limb,
    a: *const Limb,
    m: *const Limb,
    num_limbs: size_t,
) {
    let overflow1: Limb = constant_time_is_nonzero_w(
        *a.offset(num_limbs.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint) as isize)
            & (1 as core::ffi::c_int as Limb)
                << (32 as core::ffi::c_uint)
                    .wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint),
    );
    let mut carry: Limb = 0 as core::ffi::c_int as Limb;
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        let limb: Limb = *a.offset(i as isize);
        let new_carry: Limb = limb
            >> (32 as core::ffi::c_uint).wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint);
        *r.offset(i as isize) = limb << 1 as core::ffi::c_int | carry;
        carry = new_carry;
        i = i.wrapping_add(1);
    }
    let overflow2: Limb = !LIMBS_less_than(r as *const Limb, m, num_limbs);
    let overflow: Limb = overflow1 | overflow2;
    let mut borrow: Carry = limb_sub(
        &mut *r.offset(0 as core::ffi::c_int as isize),
        *r.offset(0 as core::ffi::c_int as isize),
        *m.offset(0 as core::ffi::c_int as isize) & overflow,
    );
    let mut i_0: size_t = 1 as core::ffi::c_int as size_t;
    while i_0 < num_limbs {
        borrow = limb_sbb(
            &mut *r.offset(i_0 as isize),
            *r.offset(i_0 as isize),
            *m.offset(i_0 as isize) & overflow,
            borrow,
        );
        i_0 = i_0.wrapping_add(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_select_512_32(
    r: *mut Limb,
    table: *const Limb,
    num_limbs: size_t,
    index: crypto_word_t,
) -> core::ffi::c_int {
    if num_limbs.wrapping_rem(
        (512 as core::ffi::c_int as core::ffi::c_uint).wrapping_div(32 as core::ffi::c_uint),
    ) != 0 as core::ffi::c_int as core::ffi::c_uint
    {
        return 0 as core::ffi::c_int;
    }
    limbs_select(r, table, num_limbs, 32 as core::ffi::c_int as size_t, index);
    return 1 as core::ffi::c_int;
}
static mut FIVE_BITS_MASK: Limb = 0x1f as core::ffi::c_int as Limb;
#[no_mangle]
pub unsafe extern "C" fn LIMBS_window5_split_window(
    lower_limb: Limb,
    higher_limb: Limb,
    index_within_word: size_t,
) -> crypto_word_t {
    let high_bits: Limb =
        higher_limb << (32 as core::ffi::c_uint).wrapping_sub(index_within_word) & FIVE_BITS_MASK;
    let low_bits: Limb = lower_limb >> index_within_word;
    return low_bits | high_bits;
}
#[no_mangle]
pub unsafe extern "C" fn LIMBS_window5_unsplit_window(
    limb: Limb,
    index_within_word: size_t,
) -> crypto_word_t {
    return limb >> index_within_word & FIVE_BITS_MASK;
}
#[no_mangle]
pub unsafe extern "C" fn LIMB_shr(a: Limb, shift: size_t) -> Limb {
    return a >> shift;
}
#[no_mangle]
pub unsafe extern "C" fn limbs_mul_add_limb(
    r: *mut Limb,
    a: *const Limb,
    b: Limb,
    num_limbs: size_t,
) -> Limb {
    let mut carried: Limb = 0 as core::ffi::c_int as Limb;
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_limbs {
        let mut lo: Limb = 0;
        let mut hi: Limb = 0;
        bn_umult_lohi(&mut lo, &mut hi, *a.offset(i as isize), b);
        let mut tmp: Limb = 0;
        let mut c: Carry = limb_add(&mut tmp, lo, carried);
        let _c = limb_adc(&mut carried, hi, 0 as core::ffi::c_int as Limb, c);
        c = limb_add(&mut *r.offset(i as isize), *r.offset(i as isize), tmp);
        let _c = limb_adc(&mut carried, carried, 0 as core::ffi::c_int as Limb, c);
        i = i.wrapping_add(1);
    }
    return carried;
}

#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![register_tool(c2rust)]
#![feature(label_break_value, register_tool)]
extern "C" {
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_uint,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_uint,
    ) -> *mut libc::c_void;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
}
pub type size_t = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: libc::c_uint,
}
pub type AES_KEY = aes_key_st;
pub type aes_word_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct AES_NOHW_BATCH {
    pub w: [aes_word_t; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct AES_NOHW_SCHEDULE {
    pub keys: [AES_NOHW_BATCH; 15],
}
#[inline]
unsafe extern "C" fn CRYPTO_bswap4(mut x: uint32_t) -> uint32_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u32_be(mut out: *mut libc::c_void, mut v: uint32_t) {
    v = CRYPTO_bswap4(v);
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const libc::c_void,
        ::std::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_load_u32_be(mut in_0: *const libc::c_void) -> uint32_t {
    let mut v: uint32_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint32_t as *mut libc::c_void,
        in_0,
        ::std::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    return CRYPTO_bswap4(v);
}
#[inline]
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut libc::c_void,
    mut src: *const libc::c_void,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as libc::c_uint {
        return dst;
    }
    return memcpy(dst, src, n);
}
#[inline]
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut libc::c_void,
    mut c: libc::c_int,
    mut n: size_t,
) -> *mut libc::c_void {
    if n == 0 as libc::c_int as libc::c_uint {
        return dst;
    }
    return memset(dst, c, n);
}
#[inline]
unsafe extern "C" fn aes_nohw_and(mut a: aes_word_t, mut b: aes_word_t) -> aes_word_t {
    return a & b;
}
#[inline]
unsafe extern "C" fn aes_nohw_or(mut a: aes_word_t, mut b: aes_word_t) -> aes_word_t {
    return a | b;
}
#[inline]
unsafe extern "C" fn aes_nohw_xor(mut a: aes_word_t, mut b: aes_word_t) -> aes_word_t {
    return a ^ b;
}
#[inline]
unsafe extern "C" fn aes_nohw_not(mut a: aes_word_t) -> aes_word_t {
    return !a;
}
#[inline]
unsafe extern "C" fn aes_nohw_shift_left(
    mut a: aes_word_t,
    mut i: aes_word_t,
) -> aes_word_t {
    return a << i.wrapping_mul(2 as libc::c_int as libc::c_uint);
}
#[inline]
unsafe extern "C" fn aes_nohw_shift_right(
    mut a: aes_word_t,
    mut i: aes_word_t,
) -> aes_word_t {
    return a >> i.wrapping_mul(2 as libc::c_int as libc::c_uint);
}
#[inline]
unsafe extern "C" fn aes_nohw_batch_set(
    mut batch: *mut AES_NOHW_BATCH,
    mut in_0: *const aes_word_t,
    mut i: size_t,
) {
    (*batch).w[i as usize] = *in_0.offset(0 as libc::c_int as isize);
    (*batch)
        .w[i.wrapping_add(2 as libc::c_int as libc::c_uint)
        as usize] = *in_0.offset(1 as libc::c_int as isize);
    (*batch)
        .w[i.wrapping_add(4 as libc::c_int as libc::c_uint)
        as usize] = *in_0.offset(2 as libc::c_int as isize);
    (*batch)
        .w[i.wrapping_add(6 as libc::c_int as libc::c_uint)
        as usize] = *in_0.offset(3 as libc::c_int as isize);
}
#[inline]
unsafe extern "C" fn aes_nohw_batch_get(
    mut batch: *const AES_NOHW_BATCH,
    mut out: *mut aes_word_t,
    mut i: size_t,
) {
    *out.offset(0 as libc::c_int as isize) = (*batch).w[i as usize];
    *out
        .offset(
            1 as libc::c_int as isize,
        ) = (*batch).w[i.wrapping_add(2 as libc::c_int as libc::c_uint) as usize];
    *out
        .offset(
            2 as libc::c_int as isize,
        ) = (*batch).w[i.wrapping_add(4 as libc::c_int as libc::c_uint) as usize];
    *out
        .offset(
            3 as libc::c_int as isize,
        ) = (*batch).w[i.wrapping_add(6 as libc::c_int as libc::c_uint) as usize];
}
#[inline]
unsafe extern "C" fn aes_nohw_delta_swap(
    mut a: aes_word_t,
    mut mask: aes_word_t,
    mut shift: aes_word_t,
) -> aes_word_t {
    let mut b: aes_word_t = (a ^ a >> shift) & mask;
    return a ^ b ^ b << shift;
}
#[inline]
unsafe extern "C" fn aes_nohw_compact_word(mut a: uint32_t) -> uint32_t {
    a = aes_nohw_delta_swap(
        a,
        0xcc00cc as libc::c_int as aes_word_t,
        6 as libc::c_int as aes_word_t,
    );
    a = aes_nohw_delta_swap(
        a,
        0xf0f0 as libc::c_int as aes_word_t,
        12 as libc::c_int as aes_word_t,
    );
    return a;
}
#[inline]
unsafe extern "C" fn aes_nohw_uncompact_word(mut a: uint32_t) -> uint32_t {
    a = aes_nohw_delta_swap(
        a,
        0xf0f0 as libc::c_int as aes_word_t,
        12 as libc::c_int as aes_word_t,
    );
    a = aes_nohw_delta_swap(
        a,
        0xcc00cc as libc::c_int as aes_word_t,
        6 as libc::c_int as aes_word_t,
    );
    return a;
}
#[inline]
unsafe extern "C" fn aes_nohw_word_from_bytes(
    mut a0: uint8_t,
    mut a1: uint8_t,
    mut a2: uint8_t,
    mut a3: uint8_t,
) -> uint32_t {
    return a0 as uint32_t | (a1 as uint32_t) << 8 as libc::c_int
        | (a2 as uint32_t) << 16 as libc::c_int | (a3 as uint32_t) << 24 as libc::c_int;
}
#[inline]
unsafe extern "C" fn lo(mut a: uint32_t) -> uint8_t {
    return a as uint8_t;
}
#[inline]
unsafe extern "C" fn aes_nohw_compact_block(
    mut out: *mut aes_word_t,
    mut in_0: *const uint8_t,
) {
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        in_0 as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    let mut a0: uint32_t = aes_nohw_compact_word(*out.offset(0 as libc::c_int as isize));
    let mut a1: uint32_t = aes_nohw_compact_word(*out.offset(1 as libc::c_int as isize));
    let mut a2: uint32_t = aes_nohw_compact_word(*out.offset(2 as libc::c_int as isize));
    let mut a3: uint32_t = aes_nohw_compact_word(*out.offset(3 as libc::c_int as isize));
    *out
        .offset(
            0 as libc::c_int as isize,
        ) = aes_nohw_word_from_bytes(lo(a0), lo(a1), lo(a2), lo(a3));
    *out
        .offset(
            1 as libc::c_int as isize,
        ) = aes_nohw_word_from_bytes(
        lo(a0 >> 8 as libc::c_int),
        lo(a1 >> 8 as libc::c_int),
        lo(a2 >> 8 as libc::c_int),
        lo(a3 >> 8 as libc::c_int),
    );
    *out
        .offset(
            2 as libc::c_int as isize,
        ) = aes_nohw_word_from_bytes(
        lo(a0 >> 16 as libc::c_int),
        lo(a1 >> 16 as libc::c_int),
        lo(a2 >> 16 as libc::c_int),
        lo(a3 >> 16 as libc::c_int),
    );
    *out
        .offset(
            3 as libc::c_int as isize,
        ) = aes_nohw_word_from_bytes(
        lo(a0 >> 24 as libc::c_int),
        lo(a1 >> 24 as libc::c_int),
        lo(a2 >> 24 as libc::c_int),
        lo(a3 >> 24 as libc::c_int),
    );
}
#[inline]
unsafe extern "C" fn aes_nohw_uncompact_block(
    mut out: *mut uint8_t,
    mut in_0: *const aes_word_t,
) {
    let mut a0: uint32_t = *in_0.offset(0 as libc::c_int as isize);
    let mut a1: uint32_t = *in_0.offset(1 as libc::c_int as isize);
    let mut a2: uint32_t = *in_0.offset(2 as libc::c_int as isize);
    let mut a3: uint32_t = *in_0.offset(3 as libc::c_int as isize);
    let mut b0: uint32_t = aes_nohw_word_from_bytes(lo(a0), lo(a1), lo(a2), lo(a3));
    let mut b1: uint32_t = aes_nohw_word_from_bytes(
        lo(a0 >> 8 as libc::c_int),
        lo(a1 >> 8 as libc::c_int),
        lo(a2 >> 8 as libc::c_int),
        lo(a3 >> 8 as libc::c_int),
    );
    let mut b2: uint32_t = aes_nohw_word_from_bytes(
        lo(a0 >> 16 as libc::c_int),
        lo(a1 >> 16 as libc::c_int),
        lo(a2 >> 16 as libc::c_int),
        lo(a3 >> 16 as libc::c_int),
    );
    let mut b3: uint32_t = aes_nohw_word_from_bytes(
        lo(a0 >> 24 as libc::c_int),
        lo(a1 >> 24 as libc::c_int),
        lo(a2 >> 24 as libc::c_int),
        lo(a3 >> 24 as libc::c_int),
    );
    b0 = aes_nohw_uncompact_word(b0);
    b1 = aes_nohw_uncompact_word(b1);
    b2 = aes_nohw_uncompact_word(b2);
    b3 = aes_nohw_uncompact_word(b3);
    OPENSSL_memcpy(
        out as *mut libc::c_void,
        &mut b0 as *mut uint32_t as *const libc::c_void,
        4 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        out.offset(4 as libc::c_int as isize) as *mut libc::c_void,
        &mut b1 as *mut uint32_t as *const libc::c_void,
        4 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        out.offset(8 as libc::c_int as isize) as *mut libc::c_void,
        &mut b2 as *mut uint32_t as *const libc::c_void,
        4 as libc::c_int as size_t,
    );
    OPENSSL_memcpy(
        out.offset(12 as libc::c_int as isize) as *mut libc::c_void,
        &mut b3 as *mut uint32_t as *const libc::c_void,
        4 as libc::c_int as size_t,
    );
}
#[inline]
unsafe extern "C" fn aes_nohw_swap_bits(
    mut a: *mut aes_word_t,
    mut b: *mut aes_word_t,
    mut mask: uint32_t,
    mut shift: aes_word_t,
) {
    let mut mask_w: aes_word_t = mask;
    let mut swap: aes_word_t = (*a >> shift ^ *b) & mask_w;
    *a ^= swap << shift;
    *b ^= swap;
}
unsafe extern "C" fn aes_nohw_transpose(mut batch: *mut AES_NOHW_BATCH) {
    aes_nohw_swap_bits(
        &mut *((*batch).w).as_mut_ptr().offset(0 as libc::c_int as isize),
        &mut *((*batch).w).as_mut_ptr().offset(1 as libc::c_int as isize),
        0x55555555 as libc::c_int as uint32_t,
        1 as libc::c_int as aes_word_t,
    );
    aes_nohw_swap_bits(
        &mut *((*batch).w).as_mut_ptr().offset(2 as libc::c_int as isize),
        &mut *((*batch).w).as_mut_ptr().offset(3 as libc::c_int as isize),
        0x55555555 as libc::c_int as uint32_t,
        1 as libc::c_int as aes_word_t,
    );
    aes_nohw_swap_bits(
        &mut *((*batch).w).as_mut_ptr().offset(4 as libc::c_int as isize),
        &mut *((*batch).w).as_mut_ptr().offset(5 as libc::c_int as isize),
        0x55555555 as libc::c_int as uint32_t,
        1 as libc::c_int as aes_word_t,
    );
    aes_nohw_swap_bits(
        &mut *((*batch).w).as_mut_ptr().offset(6 as libc::c_int as isize),
        &mut *((*batch).w).as_mut_ptr().offset(7 as libc::c_int as isize),
        0x55555555 as libc::c_int as uint32_t,
        1 as libc::c_int as aes_word_t,
    );
}
unsafe extern "C" fn aes_nohw_to_batch(
    mut out: *mut AES_NOHW_BATCH,
    mut in_0: *const uint8_t,
    mut num_blocks: size_t,
) {
    OPENSSL_memset(
        out as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<AES_NOHW_BATCH>() as libc::c_ulong,
    );
    if num_blocks <= 2 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"num_blocks <= 2\0" as *const u8 as *const libc::c_char,
            b"crypto/fipsmodule/aes/aes_nohw.c\0" as *const u8 as *const libc::c_char,
            479 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 66],
                &[libc::c_char; 66],
            >(b"void aes_nohw_to_batch(AES_NOHW_BATCH *, const uint8_t *, size_t)\0"))
                .as_ptr(),
        );
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num_blocks {
        let mut block: [aes_word_t; 4] = [0; 4];
        aes_nohw_compact_block(
            block.as_mut_ptr(),
            in_0.offset((16 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
        );
        aes_nohw_batch_set(out, block.as_mut_ptr() as *const aes_word_t, i);
        i = i.wrapping_add(1);
    }
    aes_nohw_transpose(out);
}
unsafe extern "C" fn aes_nohw_from_batch(
    mut out: *mut uint8_t,
    mut num_blocks: size_t,
    mut batch: *const AES_NOHW_BATCH,
) {
    let mut copy: AES_NOHW_BATCH = *batch;
    aes_nohw_transpose(&mut copy);
    if num_blocks <= 2 as libc::c_int as libc::c_uint {} else {
        __assert_fail(
            b"num_blocks <= 2\0" as *const u8 as *const libc::c_char,
            b"crypto/fipsmodule/aes/aes_nohw.c\0" as *const u8 as *const libc::c_char,
            496 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 68],
                &[libc::c_char; 68],
            >(b"void aes_nohw_from_batch(uint8_t *, size_t, const AES_NOHW_BATCH *)\0"))
                .as_ptr(),
        );
    }
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < num_blocks {
        let mut block: [aes_word_t; 4] = [0; 4];
        aes_nohw_batch_get(&mut copy, block.as_mut_ptr(), i);
        aes_nohw_uncompact_block(
            out.offset((16 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
            block.as_mut_ptr() as *const aes_word_t,
        );
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn aes_nohw_add_round_key(
    mut batch: *mut AES_NOHW_BATCH,
    mut key: *const AES_NOHW_BATCH,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 8 as libc::c_int as libc::c_uint {
        (*batch)
            .w[i as usize] = aes_nohw_xor((*batch).w[i as usize], (*key).w[i as usize]);
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn aes_nohw_sub_bytes(mut batch: *mut AES_NOHW_BATCH) {
    let mut x0: aes_word_t = (*batch).w[7 as libc::c_int as usize];
    let mut x1: aes_word_t = (*batch).w[6 as libc::c_int as usize];
    let mut x2: aes_word_t = (*batch).w[5 as libc::c_int as usize];
    let mut x3: aes_word_t = (*batch).w[4 as libc::c_int as usize];
    let mut x4: aes_word_t = (*batch).w[3 as libc::c_int as usize];
    let mut x5: aes_word_t = (*batch).w[2 as libc::c_int as usize];
    let mut x6: aes_word_t = (*batch).w[1 as libc::c_int as usize];
    let mut x7: aes_word_t = (*batch).w[0 as libc::c_int as usize];
    let mut y14: aes_word_t = aes_nohw_xor(x3, x5);
    let mut y13: aes_word_t = aes_nohw_xor(x0, x6);
    let mut y9: aes_word_t = aes_nohw_xor(x0, x3);
    let mut y8: aes_word_t = aes_nohw_xor(x0, x5);
    let mut t0: aes_word_t = aes_nohw_xor(x1, x2);
    let mut y1: aes_word_t = aes_nohw_xor(t0, x7);
    let mut y4: aes_word_t = aes_nohw_xor(y1, x3);
    let mut y12: aes_word_t = aes_nohw_xor(y13, y14);
    let mut y2: aes_word_t = aes_nohw_xor(y1, x0);
    let mut y5: aes_word_t = aes_nohw_xor(y1, x6);
    let mut y3: aes_word_t = aes_nohw_xor(y5, y8);
    let mut t1: aes_word_t = aes_nohw_xor(x4, y12);
    let mut y15: aes_word_t = aes_nohw_xor(t1, x5);
    let mut y20: aes_word_t = aes_nohw_xor(t1, x1);
    let mut y6: aes_word_t = aes_nohw_xor(y15, x7);
    let mut y10: aes_word_t = aes_nohw_xor(y15, t0);
    let mut y11: aes_word_t = aes_nohw_xor(y20, y9);
    let mut y7: aes_word_t = aes_nohw_xor(x7, y11);
    let mut y17: aes_word_t = aes_nohw_xor(y10, y11);
    let mut y19: aes_word_t = aes_nohw_xor(y10, y8);
    let mut y16: aes_word_t = aes_nohw_xor(t0, y11);
    let mut y21: aes_word_t = aes_nohw_xor(y13, y16);
    let mut y18: aes_word_t = aes_nohw_xor(x0, y16);
    let mut t2: aes_word_t = aes_nohw_and(y12, y15);
    let mut t3: aes_word_t = aes_nohw_and(y3, y6);
    let mut t4: aes_word_t = aes_nohw_xor(t3, t2);
    let mut t5: aes_word_t = aes_nohw_and(y4, x7);
    let mut t6: aes_word_t = aes_nohw_xor(t5, t2);
    let mut t7: aes_word_t = aes_nohw_and(y13, y16);
    let mut t8: aes_word_t = aes_nohw_and(y5, y1);
    let mut t9: aes_word_t = aes_nohw_xor(t8, t7);
    let mut t10: aes_word_t = aes_nohw_and(y2, y7);
    let mut t11: aes_word_t = aes_nohw_xor(t10, t7);
    let mut t12: aes_word_t = aes_nohw_and(y9, y11);
    let mut t13: aes_word_t = aes_nohw_and(y14, y17);
    let mut t14: aes_word_t = aes_nohw_xor(t13, t12);
    let mut t15: aes_word_t = aes_nohw_and(y8, y10);
    let mut t16: aes_word_t = aes_nohw_xor(t15, t12);
    let mut t17: aes_word_t = aes_nohw_xor(t4, t14);
    let mut t18: aes_word_t = aes_nohw_xor(t6, t16);
    let mut t19: aes_word_t = aes_nohw_xor(t9, t14);
    let mut t20: aes_word_t = aes_nohw_xor(t11, t16);
    let mut t21: aes_word_t = aes_nohw_xor(t17, y20);
    let mut t22: aes_word_t = aes_nohw_xor(t18, y19);
    let mut t23: aes_word_t = aes_nohw_xor(t19, y21);
    let mut t24: aes_word_t = aes_nohw_xor(t20, y18);
    let mut t25: aes_word_t = aes_nohw_xor(t21, t22);
    let mut t26: aes_word_t = aes_nohw_and(t21, t23);
    let mut t27: aes_word_t = aes_nohw_xor(t24, t26);
    let mut t28: aes_word_t = aes_nohw_and(t25, t27);
    let mut t29: aes_word_t = aes_nohw_xor(t28, t22);
    let mut t30: aes_word_t = aes_nohw_xor(t23, t24);
    let mut t31: aes_word_t = aes_nohw_xor(t22, t26);
    let mut t32: aes_word_t = aes_nohw_and(t31, t30);
    let mut t33: aes_word_t = aes_nohw_xor(t32, t24);
    let mut t34: aes_word_t = aes_nohw_xor(t23, t33);
    let mut t35: aes_word_t = aes_nohw_xor(t27, t33);
    let mut t36: aes_word_t = aes_nohw_and(t24, t35);
    let mut t37: aes_word_t = aes_nohw_xor(t36, t34);
    let mut t38: aes_word_t = aes_nohw_xor(t27, t36);
    let mut t39: aes_word_t = aes_nohw_and(t29, t38);
    let mut t40: aes_word_t = aes_nohw_xor(t25, t39);
    let mut t41: aes_word_t = aes_nohw_xor(t40, t37);
    let mut t42: aes_word_t = aes_nohw_xor(t29, t33);
    let mut t43: aes_word_t = aes_nohw_xor(t29, t40);
    let mut t44: aes_word_t = aes_nohw_xor(t33, t37);
    let mut t45: aes_word_t = aes_nohw_xor(t42, t41);
    let mut z0: aes_word_t = aes_nohw_and(t44, y15);
    let mut z1: aes_word_t = aes_nohw_and(t37, y6);
    let mut z2: aes_word_t = aes_nohw_and(t33, x7);
    let mut z3: aes_word_t = aes_nohw_and(t43, y16);
    let mut z4: aes_word_t = aes_nohw_and(t40, y1);
    let mut z5: aes_word_t = aes_nohw_and(t29, y7);
    let mut z6: aes_word_t = aes_nohw_and(t42, y11);
    let mut z7: aes_word_t = aes_nohw_and(t45, y17);
    let mut z8: aes_word_t = aes_nohw_and(t41, y10);
    let mut z9: aes_word_t = aes_nohw_and(t44, y12);
    let mut z10: aes_word_t = aes_nohw_and(t37, y3);
    let mut z11: aes_word_t = aes_nohw_and(t33, y4);
    let mut z12: aes_word_t = aes_nohw_and(t43, y13);
    let mut z13: aes_word_t = aes_nohw_and(t40, y5);
    let mut z14: aes_word_t = aes_nohw_and(t29, y2);
    let mut z15: aes_word_t = aes_nohw_and(t42, y9);
    let mut z16: aes_word_t = aes_nohw_and(t45, y14);
    let mut z17: aes_word_t = aes_nohw_and(t41, y8);
    let mut t46: aes_word_t = aes_nohw_xor(z15, z16);
    let mut t47: aes_word_t = aes_nohw_xor(z10, z11);
    let mut t48: aes_word_t = aes_nohw_xor(z5, z13);
    let mut t49: aes_word_t = aes_nohw_xor(z9, z10);
    let mut t50: aes_word_t = aes_nohw_xor(z2, z12);
    let mut t51: aes_word_t = aes_nohw_xor(z2, z5);
    let mut t52: aes_word_t = aes_nohw_xor(z7, z8);
    let mut t53: aes_word_t = aes_nohw_xor(z0, z3);
    let mut t54: aes_word_t = aes_nohw_xor(z6, z7);
    let mut t55: aes_word_t = aes_nohw_xor(z16, z17);
    let mut t56: aes_word_t = aes_nohw_xor(z12, t48);
    let mut t57: aes_word_t = aes_nohw_xor(t50, t53);
    let mut t58: aes_word_t = aes_nohw_xor(z4, t46);
    let mut t59: aes_word_t = aes_nohw_xor(z3, t54);
    let mut t60: aes_word_t = aes_nohw_xor(t46, t57);
    let mut t61: aes_word_t = aes_nohw_xor(z14, t57);
    let mut t62: aes_word_t = aes_nohw_xor(t52, t58);
    let mut t63: aes_word_t = aes_nohw_xor(t49, t58);
    let mut t64: aes_word_t = aes_nohw_xor(z4, t59);
    let mut t65: aes_word_t = aes_nohw_xor(t61, t62);
    let mut t66: aes_word_t = aes_nohw_xor(z1, t63);
    let mut s0: aes_word_t = aes_nohw_xor(t59, t63);
    let mut s6: aes_word_t = aes_nohw_xor(t56, aes_nohw_not(t62));
    let mut s7: aes_word_t = aes_nohw_xor(t48, aes_nohw_not(t60));
    let mut t67: aes_word_t = aes_nohw_xor(t64, t65);
    let mut s3: aes_word_t = aes_nohw_xor(t53, t66);
    let mut s4: aes_word_t = aes_nohw_xor(t51, t66);
    let mut s5: aes_word_t = aes_nohw_xor(t47, t65);
    let mut s1: aes_word_t = aes_nohw_xor(t64, aes_nohw_not(s3));
    let mut s2: aes_word_t = aes_nohw_xor(t55, aes_nohw_not(t67));
    (*batch).w[0 as libc::c_int as usize] = s7;
    (*batch).w[1 as libc::c_int as usize] = s6;
    (*batch).w[2 as libc::c_int as usize] = s5;
    (*batch).w[3 as libc::c_int as usize] = s4;
    (*batch).w[4 as libc::c_int as usize] = s3;
    (*batch).w[5 as libc::c_int as usize] = s2;
    (*batch).w[6 as libc::c_int as usize] = s1;
    (*batch).w[7 as libc::c_int as usize] = s0;
}
unsafe extern "C" fn aes_nohw_shift_rows(mut batch: *mut AES_NOHW_BATCH) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 8 as libc::c_int as libc::c_uint {
        let mut row0: aes_word_t = aes_nohw_and(
            (*batch).w[i as usize],
            0x3030303 as libc::c_int as aes_word_t,
        );
        let mut row1: aes_word_t = aes_nohw_and(
            (*batch).w[i as usize],
            0xc0c0c0c as libc::c_int as aes_word_t,
        );
        let mut row2: aes_word_t = aes_nohw_and(
            (*batch).w[i as usize],
            0x30303030 as libc::c_int as aes_word_t,
        );
        let mut row3: aes_word_t = aes_nohw_and(
            (*batch).w[i as usize],
            0xc0c0c0c0 as libc::c_uint,
        );
        row1 = aes_nohw_or(
            aes_nohw_shift_right(
                row1,
                (1 as libc::c_int * 4 as libc::c_int) as aes_word_t,
            ),
            aes_nohw_shift_left(
                row1,
                (16 as libc::c_int - 1 as libc::c_int * 4 as libc::c_int) as aes_word_t,
            ),
        );
        row2 = aes_nohw_or(
            aes_nohw_shift_right(
                row2,
                (2 as libc::c_int * 4 as libc::c_int) as aes_word_t,
            ),
            aes_nohw_shift_left(
                row2,
                (16 as libc::c_int - 2 as libc::c_int * 4 as libc::c_int) as aes_word_t,
            ),
        );
        row3 = aes_nohw_or(
            aes_nohw_shift_right(
                row3,
                (3 as libc::c_int * 4 as libc::c_int) as aes_word_t,
            ),
            aes_nohw_shift_left(
                row3,
                (16 as libc::c_int - 3 as libc::c_int * 4 as libc::c_int) as aes_word_t,
            ),
        );
        (*batch)
            .w[i
            as usize] = aes_nohw_or(aes_nohw_or(row0, row1), aes_nohw_or(row2, row3));
        i = i.wrapping_add(1);
    }
}
#[inline]
unsafe extern "C" fn aes_nohw_rotate_rows_down(mut v: aes_word_t) -> aes_word_t {
    return v >> 2 as libc::c_int & 0x3f3f3f3f as libc::c_int as libc::c_uint
        | v << 6 as libc::c_int & 0xc0c0c0c0 as libc::c_uint;
}
#[inline]
unsafe extern "C" fn aes_nohw_rotate_rows_twice(mut v: aes_word_t) -> aes_word_t {
    return v >> 4 as libc::c_int & 0xf0f0f0f as libc::c_int as libc::c_uint
        | v << 4 as libc::c_int & 0xf0f0f0f0 as libc::c_uint;
}
unsafe extern "C" fn aes_nohw_mix_columns(mut batch: *mut AES_NOHW_BATCH) {
    let mut a0: aes_word_t = (*batch).w[0 as libc::c_int as usize];
    let mut a1: aes_word_t = (*batch).w[1 as libc::c_int as usize];
    let mut a2: aes_word_t = (*batch).w[2 as libc::c_int as usize];
    let mut a3: aes_word_t = (*batch).w[3 as libc::c_int as usize];
    let mut a4: aes_word_t = (*batch).w[4 as libc::c_int as usize];
    let mut a5: aes_word_t = (*batch).w[5 as libc::c_int as usize];
    let mut a6: aes_word_t = (*batch).w[6 as libc::c_int as usize];
    let mut a7: aes_word_t = (*batch).w[7 as libc::c_int as usize];
    let mut r0: aes_word_t = aes_nohw_rotate_rows_down(a0);
    let mut a0_r0: aes_word_t = aes_nohw_xor(a0, r0);
    let mut r1: aes_word_t = aes_nohw_rotate_rows_down(a1);
    let mut a1_r1: aes_word_t = aes_nohw_xor(a1, r1);
    let mut r2: aes_word_t = aes_nohw_rotate_rows_down(a2);
    let mut a2_r2: aes_word_t = aes_nohw_xor(a2, r2);
    let mut r3: aes_word_t = aes_nohw_rotate_rows_down(a3);
    let mut a3_r3: aes_word_t = aes_nohw_xor(a3, r3);
    let mut r4: aes_word_t = aes_nohw_rotate_rows_down(a4);
    let mut a4_r4: aes_word_t = aes_nohw_xor(a4, r4);
    let mut r5: aes_word_t = aes_nohw_rotate_rows_down(a5);
    let mut a5_r5: aes_word_t = aes_nohw_xor(a5, r5);
    let mut r6: aes_word_t = aes_nohw_rotate_rows_down(a6);
    let mut a6_r6: aes_word_t = aes_nohw_xor(a6, r6);
    let mut r7: aes_word_t = aes_nohw_rotate_rows_down(a7);
    let mut a7_r7: aes_word_t = aes_nohw_xor(a7, r7);
    (*batch)
        .w[0 as libc::c_int
        as usize] = aes_nohw_xor(
        aes_nohw_xor(a7_r7, r0),
        aes_nohw_rotate_rows_twice(a0_r0),
    );
    (*batch)
        .w[1 as libc::c_int
        as usize] = aes_nohw_xor(
        aes_nohw_xor(a0_r0, a7_r7),
        aes_nohw_xor(r1, aes_nohw_rotate_rows_twice(a1_r1)),
    );
    (*batch)
        .w[2 as libc::c_int
        as usize] = aes_nohw_xor(
        aes_nohw_xor(a1_r1, r2),
        aes_nohw_rotate_rows_twice(a2_r2),
    );
    (*batch)
        .w[3 as libc::c_int
        as usize] = aes_nohw_xor(
        aes_nohw_xor(a2_r2, a7_r7),
        aes_nohw_xor(r3, aes_nohw_rotate_rows_twice(a3_r3)),
    );
    (*batch)
        .w[4 as libc::c_int
        as usize] = aes_nohw_xor(
        aes_nohw_xor(a3_r3, a7_r7),
        aes_nohw_xor(r4, aes_nohw_rotate_rows_twice(a4_r4)),
    );
    (*batch)
        .w[5 as libc::c_int
        as usize] = aes_nohw_xor(
        aes_nohw_xor(a4_r4, r5),
        aes_nohw_rotate_rows_twice(a5_r5),
    );
    (*batch)
        .w[6 as libc::c_int
        as usize] = aes_nohw_xor(
        aes_nohw_xor(a5_r5, r6),
        aes_nohw_rotate_rows_twice(a6_r6),
    );
    (*batch)
        .w[7 as libc::c_int
        as usize] = aes_nohw_xor(
        aes_nohw_xor(a6_r6, r7),
        aes_nohw_rotate_rows_twice(a7_r7),
    );
}
unsafe extern "C" fn aes_nohw_encrypt_batch(
    mut key: *const AES_NOHW_SCHEDULE,
    mut num_rounds: size_t,
    mut batch: *mut AES_NOHW_BATCH,
) {
    aes_nohw_add_round_key(
        batch,
        &*((*key).keys).as_ptr().offset(0 as libc::c_int as isize),
    );
    let mut i: size_t = 1 as libc::c_int as size_t;
    while i < num_rounds {
        aes_nohw_sub_bytes(batch);
        aes_nohw_shift_rows(batch);
        aes_nohw_mix_columns(batch);
        aes_nohw_add_round_key(batch, &*((*key).keys).as_ptr().offset(i as isize));
        i = i.wrapping_add(1);
    }
    aes_nohw_sub_bytes(batch);
    aes_nohw_shift_rows(batch);
    aes_nohw_add_round_key(batch, &*((*key).keys).as_ptr().offset(num_rounds as isize));
}
unsafe extern "C" fn aes_nohw_expand_round_keys(
    mut out: *mut AES_NOHW_SCHEDULE,
    mut key: *const AES_KEY,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i <= (*key).rounds {
        let mut j: size_t = 0 as libc::c_int as size_t;
        while j < 2 as libc::c_int as libc::c_uint {
            let mut tmp: [aes_word_t; 4] = [0; 4];
            OPENSSL_memcpy(
                tmp.as_mut_ptr() as *mut libc::c_void,
                ((*key).rd_key)
                    .as_ptr()
                    .offset((4 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize)
                    as *const libc::c_void,
                16 as libc::c_int as size_t,
            );
            aes_nohw_batch_set(
                &mut *((*out).keys).as_mut_ptr().offset(i as isize),
                tmp.as_mut_ptr() as *const aes_word_t,
                j,
            );
            j = j.wrapping_add(1);
        }
        aes_nohw_transpose(&mut *((*out).keys).as_mut_ptr().offset(i as isize));
        i = i.wrapping_add(1);
    }
}
static mut aes_nohw_rcon: [uint8_t; 10] = [
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x40 as libc::c_int as uint8_t,
    0x80 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x36 as libc::c_int as uint8_t,
];
#[inline]
unsafe extern "C" fn aes_nohw_rcon_slice(
    mut rcon: uint8_t,
    mut i: size_t,
) -> aes_word_t {
    rcon = (rcon as libc::c_int >> i.wrapping_mul(2 as libc::c_int as libc::c_uint)
        & ((1 as libc::c_int) << 2 as libc::c_int) - 1 as libc::c_int) as uint8_t;
    return rcon as aes_word_t;
}
unsafe extern "C" fn aes_nohw_sub_block(
    mut out: *mut aes_word_t,
    mut in_0: *const aes_word_t,
) {
    let mut batch: AES_NOHW_BATCH = AES_NOHW_BATCH { w: [0; 8] };
    OPENSSL_memset(
        &mut batch as *mut AES_NOHW_BATCH as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<AES_NOHW_BATCH>() as libc::c_ulong,
    );
    aes_nohw_batch_set(&mut batch, in_0, 0 as libc::c_int as size_t);
    aes_nohw_transpose(&mut batch);
    aes_nohw_sub_bytes(&mut batch);
    aes_nohw_transpose(&mut batch);
    aes_nohw_batch_get(&mut batch, out, 0 as libc::c_int as size_t);
}
unsafe extern "C" fn aes_nohw_setup_key_128(
    mut key: *mut AES_KEY,
    mut in_0: *const uint8_t,
) {
    (*key).rounds = 10 as libc::c_int as libc::c_uint;
    let mut block: [aes_word_t; 4] = [0; 4];
    aes_nohw_compact_block(block.as_mut_ptr(), in_0);
    OPENSSL_memcpy(
        ((*key).rd_key).as_mut_ptr() as *mut libc::c_void,
        block.as_mut_ptr() as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    let mut i: size_t = 1 as libc::c_int as size_t;
    while i <= 10 as libc::c_int as libc::c_uint {
        let mut sub: [aes_word_t; 4] = [0; 4];
        aes_nohw_sub_block(sub.as_mut_ptr(), block.as_mut_ptr() as *const aes_word_t);
        let mut rcon: uint8_t = aes_nohw_rcon[i
            .wrapping_sub(1 as libc::c_int as libc::c_uint) as usize];
        let mut j: size_t = 0 as libc::c_int as size_t;
        while j
            < (16 as libc::c_int as libc::c_uint)
                .wrapping_div(::std::mem::size_of::<aes_word_t>() as libc::c_ulong)
        {
            block[j
                as usize] = aes_nohw_xor(
                block[j as usize],
                aes_nohw_rcon_slice(rcon, j),
            );
            block[j
                as usize] = aes_nohw_xor(
                block[j as usize],
                aes_nohw_shift_right(
                    aes_nohw_rotate_rows_down(sub[j as usize]),
                    12 as libc::c_int as aes_word_t,
                ),
            );
            let mut v: aes_word_t = block[j as usize];
            block[j
                as usize] = aes_nohw_xor(
                block[j as usize],
                aes_nohw_shift_left(v, 4 as libc::c_int as aes_word_t),
            );
            block[j
                as usize] = aes_nohw_xor(
                block[j as usize],
                aes_nohw_shift_left(v, 8 as libc::c_int as aes_word_t),
            );
            block[j
                as usize] = aes_nohw_xor(
                block[j as usize],
                aes_nohw_shift_left(v, 12 as libc::c_int as aes_word_t),
            );
            j = j.wrapping_add(1);
        }
        OPENSSL_memcpy(
            ((*key).rd_key)
                .as_mut_ptr()
                .offset((4 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize)
                as *mut libc::c_void,
            block.as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn aes_nohw_setup_key_256(
    mut key: *mut AES_KEY,
    mut in_0: *const uint8_t,
) {
    (*key).rounds = 14 as libc::c_int as libc::c_uint;
    let mut block1: [aes_word_t; 4] = [0; 4];
    let mut block2: [aes_word_t; 4] = [0; 4];
    aes_nohw_compact_block(block1.as_mut_ptr(), in_0);
    OPENSSL_memcpy(
        ((*key).rd_key).as_mut_ptr() as *mut libc::c_void,
        block1.as_mut_ptr() as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    aes_nohw_compact_block(block2.as_mut_ptr(), in_0.offset(16 as libc::c_int as isize));
    OPENSSL_memcpy(
        ((*key).rd_key).as_mut_ptr().offset(4 as libc::c_int as isize)
            as *mut libc::c_void,
        block2.as_mut_ptr() as *const libc::c_void,
        16 as libc::c_int as size_t,
    );
    let mut i: size_t = 2 as libc::c_int as size_t;
    while i <= 14 as libc::c_int as libc::c_uint {
        let mut sub: [aes_word_t; 4] = [0; 4];
        aes_nohw_sub_block(sub.as_mut_ptr(), block2.as_mut_ptr() as *const aes_word_t);
        let mut rcon: uint8_t = aes_nohw_rcon[i
            .wrapping_div(2 as libc::c_int as libc::c_uint)
            .wrapping_sub(1 as libc::c_int as libc::c_uint) as usize];
        let mut j: size_t = 0 as libc::c_int as size_t;
        while j
            < (16 as libc::c_int as libc::c_uint)
                .wrapping_div(::std::mem::size_of::<aes_word_t>() as libc::c_ulong)
        {
            block1[j
                as usize] = aes_nohw_xor(
                block1[j as usize],
                aes_nohw_rcon_slice(rcon, j),
            );
            block1[j
                as usize] = aes_nohw_xor(
                block1[j as usize],
                aes_nohw_shift_right(
                    aes_nohw_rotate_rows_down(sub[j as usize]),
                    12 as libc::c_int as aes_word_t,
                ),
            );
            let mut v: aes_word_t = block1[j as usize];
            block1[j
                as usize] = aes_nohw_xor(
                block1[j as usize],
                aes_nohw_shift_left(v, 4 as libc::c_int as aes_word_t),
            );
            block1[j
                as usize] = aes_nohw_xor(
                block1[j as usize],
                aes_nohw_shift_left(v, 8 as libc::c_int as aes_word_t),
            );
            block1[j
                as usize] = aes_nohw_xor(
                block1[j as usize],
                aes_nohw_shift_left(v, 12 as libc::c_int as aes_word_t),
            );
            j = j.wrapping_add(1);
        }
        OPENSSL_memcpy(
            ((*key).rd_key)
                .as_mut_ptr()
                .offset((4 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize)
                as *mut libc::c_void,
            block1.as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
        if i == 14 as libc::c_int as libc::c_uint {
            break;
        }
        aes_nohw_sub_block(sub.as_mut_ptr(), block1.as_mut_ptr() as *const aes_word_t);
        let mut j_0: size_t = 0 as libc::c_int as size_t;
        while j_0
            < (16 as libc::c_int as libc::c_uint)
                .wrapping_div(::std::mem::size_of::<aes_word_t>() as libc::c_ulong)
        {
            block2[j_0
                as usize] = aes_nohw_xor(
                block2[j_0 as usize],
                aes_nohw_shift_right(sub[j_0 as usize], 12 as libc::c_int as aes_word_t),
            );
            let mut v_0: aes_word_t = block2[j_0 as usize];
            block2[j_0
                as usize] = aes_nohw_xor(
                block2[j_0 as usize],
                aes_nohw_shift_left(v_0, 4 as libc::c_int as aes_word_t),
            );
            block2[j_0
                as usize] = aes_nohw_xor(
                block2[j_0 as usize],
                aes_nohw_shift_left(v_0, 8 as libc::c_int as aes_word_t),
            );
            block2[j_0
                as usize] = aes_nohw_xor(
                block2[j_0 as usize],
                aes_nohw_shift_left(v_0, 12 as libc::c_int as aes_word_t),
            );
            j_0 = j_0.wrapping_add(1);
        }
        OPENSSL_memcpy(
            ((*key).rd_key)
                .as_mut_ptr()
                .offset(
                    (4 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i.wrapping_add(1 as libc::c_int as libc::c_uint))
                        as isize,
                ) as *mut libc::c_void,
            block2.as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
        i = (i as libc::c_uint).wrapping_add(2 as libc::c_int as libc::c_uint) as size_t
            as size_t;
    }
}
#[no_mangle]
pub unsafe extern "C" fn aes_nohw_set_encrypt_key(
    mut key: *const uint8_t,
    mut bits: libc::c_uint,
    mut aeskey: *mut AES_KEY,
) -> libc::c_int {
    match bits {
        128 => {
            aes_nohw_setup_key_128(aeskey, key);
            return 0 as libc::c_int;
        }
        256 => {
            aes_nohw_setup_key_256(aeskey, key);
            return 0 as libc::c_int;
        }
        _ => {}
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn aes_nohw_encrypt(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut key: *const AES_KEY,
) {
    let mut sched: AES_NOHW_SCHEDULE = AES_NOHW_SCHEDULE {
        keys: [AES_NOHW_BATCH { w: [0; 8] }; 15],
    };
    aes_nohw_expand_round_keys(&mut sched, key);
    let mut batch: AES_NOHW_BATCH = AES_NOHW_BATCH { w: [0; 8] };
    aes_nohw_to_batch(&mut batch, in_0, 1 as libc::c_int as size_t);
    aes_nohw_encrypt_batch(&mut sched, (*key).rounds, &mut batch);
    aes_nohw_from_batch(out, 1 as libc::c_int as size_t, &mut batch);
}
#[inline]
unsafe extern "C" fn aes_nohw_xor_block(
    mut out: *mut uint8_t,
    mut a: *const uint8_t,
    mut b: *const uint8_t,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as libc::c_uint {
        let mut x: aes_word_t = 0;
        let mut y: aes_word_t = 0;
        OPENSSL_memcpy(
            &mut x as *mut aes_word_t as *mut libc::c_void,
            a.offset(i as isize) as *const libc::c_void,
            ::std::mem::size_of::<aes_word_t>() as libc::c_ulong,
        );
        OPENSSL_memcpy(
            &mut y as *mut aes_word_t as *mut libc::c_void,
            b.offset(i as isize) as *const libc::c_void,
            ::std::mem::size_of::<aes_word_t>() as libc::c_ulong,
        );
        x = aes_nohw_xor(x, y);
        OPENSSL_memcpy(
            out.offset(i as isize) as *mut libc::c_void,
            &mut x as *mut aes_word_t as *const libc::c_void,
            ::std::mem::size_of::<aes_word_t>() as libc::c_ulong,
        );
        i = (i as libc::c_uint)
            .wrapping_add(::std::mem::size_of::<aes_word_t>() as libc::c_ulong) as size_t
            as size_t;
    }
}
#[no_mangle]
pub unsafe extern "C" fn aes_nohw_ctr32_encrypt_blocks(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut blocks: size_t,
    mut key: *const AES_KEY,
    mut ivec: *const uint8_t,
) {
    if blocks == 0 as libc::c_int as libc::c_uint {
        return;
    }
    let mut sched: AES_NOHW_SCHEDULE = AES_NOHW_SCHEDULE {
        keys: [AES_NOHW_BATCH { w: [0; 8] }; 15],
    };
    aes_nohw_expand_round_keys(&mut sched, key);
    let mut ivs: [uint8_t; 32] = [0; 32];
    let mut enc_ivs: [uint8_t; 32] = [0; 32];
    let mut i: size_t = 0 as libc::c_int as size_t;
    while i < 2 as libc::c_int as libc::c_uint {
        OPENSSL_memcpy(
            ivs
                .as_mut_ptr()
                .offset((16 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize)
                as *mut libc::c_void,
            ivec as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
        i = i.wrapping_add(1);
    }
    let mut ctr: uint32_t = CRYPTO_load_u32_be(
        ivs.as_mut_ptr().offset(12 as libc::c_int as isize) as *const libc::c_void,
    );
    loop {
        let mut i_0: size_t = 0 as libc::c_int as size_t;
        while i_0 < 2 as libc::c_int as libc::c_uint {
            CRYPTO_store_u32_be(
                ivs
                    .as_mut_ptr()
                    .offset(
                        (16 as libc::c_int as libc::c_uint).wrapping_mul(i_0) as isize,
                    )
                    .offset(12 as libc::c_int as isize) as *mut libc::c_void,
                ctr.wrapping_add(i_0),
            );
            i_0 = i_0.wrapping_add(1);
        }
        let mut todo: size_t = if blocks >= 2 as libc::c_int as libc::c_uint {
            2 as libc::c_int as libc::c_uint
        } else {
            blocks
        };
        let mut batch: AES_NOHW_BATCH = AES_NOHW_BATCH { w: [0; 8] };
        aes_nohw_to_batch(&mut batch, ivs.as_mut_ptr(), todo);
        aes_nohw_encrypt_batch(&mut sched, (*key).rounds, &mut batch);
        aes_nohw_from_batch(enc_ivs.as_mut_ptr(), todo, &mut batch);
        let mut i_1: size_t = 0 as libc::c_int as size_t;
        while i_1 < todo {
            aes_nohw_xor_block(
                out
                    .offset(
                        (16 as libc::c_int as libc::c_uint).wrapping_mul(i_1) as isize,
                    ),
                in_0
                    .offset(
                        (16 as libc::c_int as libc::c_uint).wrapping_mul(i_1) as isize,
                    ),
                enc_ivs
                    .as_mut_ptr()
                    .offset(
                        (16 as libc::c_int as libc::c_uint).wrapping_mul(i_1) as isize,
                    ) as *const uint8_t,
            );
            i_1 = i_1.wrapping_add(1);
        }
        blocks = (blocks as libc::c_uint).wrapping_sub(todo) as size_t as size_t;
        if blocks == 0 as libc::c_int as libc::c_uint {
            break;
        }
        in_0 = in_0.offset((16 as libc::c_int * 2 as libc::c_int) as isize);
        out = out.offset((16 as libc::c_int * 2 as libc::c_int) as isize);
        ctr = (ctr as libc::c_uint).wrapping_add(2 as libc::c_int as libc::c_uint)
            as uint32_t as uint32_t;
    };
}

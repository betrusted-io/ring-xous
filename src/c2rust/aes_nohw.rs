#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern "C" {
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: core::ffi::c_uint,
    ) -> *mut core::ffi::c_void;
    fn memset(
        _: *mut core::ffi::c_void,
        _: core::ffi::c_int,
        _: core::ffi::c_uint,
    ) -> *mut core::ffi::c_void;
    fn __assert_fail(
        __assertion: *const core::ffi::c_char,
        __file: *const core::ffi::c_char,
        __line: core::ffi::c_uint,
        __function: *const core::ffi::c_char,
    ) -> !;
}
pub type size_t = core::ffi::c_uint;
pub type __uint8_t = core::ffi::c_uchar;
pub type __uint32_t = core::ffi::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [uint32_t; 60],
    pub rounds: core::ffi::c_uint,
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
unsafe extern "C" fn CRYPTO_bswap4(x: uint32_t) -> uint32_t {
    return x.swap_bytes();
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u32_be(out: *mut core::ffi::c_void, mut v: uint32_t) {
    v = CRYPTO_bswap4(v);
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const core::ffi::c_void,
        core::mem::size_of::<uint32_t>() as u32,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_load_u32_be(in_0: *const core::ffi::c_void) -> uint32_t {
    let mut v: uint32_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint32_t as *mut core::ffi::c_void,
        in_0,
        core::mem::size_of::<uint32_t>() as u32,
    );
    return CRYPTO_bswap4(v);
}
#[inline]
unsafe extern "C" fn OPENSSL_memcpy(
    dst: *mut core::ffi::c_void,
    src: *const core::ffi::c_void,
    n: size_t,
) -> *mut core::ffi::c_void {
    if n == 0 as core::ffi::c_int as core::ffi::c_uint {
        return dst;
    }
    return memcpy(dst, src, n);
}
#[inline]
unsafe extern "C" fn OPENSSL_memset(
    dst: *mut core::ffi::c_void,
    c: core::ffi::c_int,
    n: size_t,
) -> *mut core::ffi::c_void {
    if n == 0 as core::ffi::c_int as core::ffi::c_uint {
        return dst;
    }
    return memset(dst, c, n);
}
#[inline]
unsafe extern "C" fn aes_nohw_and(a: aes_word_t, b: aes_word_t) -> aes_word_t {
    return a & b;
}
#[inline]
unsafe extern "C" fn aes_nohw_or(a: aes_word_t, b: aes_word_t) -> aes_word_t {
    return a | b;
}
#[inline]
unsafe extern "C" fn aes_nohw_xor(a: aes_word_t, b: aes_word_t) -> aes_word_t {
    return a ^ b;
}
#[inline]
unsafe extern "C" fn aes_nohw_not(a: aes_word_t) -> aes_word_t {
    return !a;
}
#[inline]
unsafe extern "C" fn aes_nohw_shift_left(a: aes_word_t, i: aes_word_t) -> aes_word_t {
    return a << i.wrapping_mul(2 as core::ffi::c_int as core::ffi::c_uint);
}
#[inline]
unsafe extern "C" fn aes_nohw_shift_right(a: aes_word_t, i: aes_word_t) -> aes_word_t {
    return a >> i.wrapping_mul(2 as core::ffi::c_int as core::ffi::c_uint);
}
#[inline]
unsafe extern "C" fn aes_nohw_batch_set(
    batch: *mut AES_NOHW_BATCH,
    in_0: *const aes_word_t,
    i: size_t,
) {
    (*batch).w[i as usize] = *in_0.offset(0 as core::ffi::c_int as isize);
    (*batch).w[i.wrapping_add(2 as core::ffi::c_int as core::ffi::c_uint) as usize] =
        *in_0.offset(1 as core::ffi::c_int as isize);
    (*batch).w[i.wrapping_add(4 as core::ffi::c_int as core::ffi::c_uint) as usize] =
        *in_0.offset(2 as core::ffi::c_int as isize);
    (*batch).w[i.wrapping_add(6 as core::ffi::c_int as core::ffi::c_uint) as usize] =
        *in_0.offset(3 as core::ffi::c_int as isize);
}
#[inline]
unsafe extern "C" fn aes_nohw_batch_get(
    batch: *const AES_NOHW_BATCH,
    out: *mut aes_word_t,
    i: size_t,
) {
    *out.offset(0 as core::ffi::c_int as isize) = (*batch).w[i as usize];
    *out.offset(1 as core::ffi::c_int as isize) =
        (*batch).w[i.wrapping_add(2 as core::ffi::c_int as core::ffi::c_uint) as usize];
    *out.offset(2 as core::ffi::c_int as isize) =
        (*batch).w[i.wrapping_add(4 as core::ffi::c_int as core::ffi::c_uint) as usize];
    *out.offset(3 as core::ffi::c_int as isize) =
        (*batch).w[i.wrapping_add(6 as core::ffi::c_int as core::ffi::c_uint) as usize];
}
#[inline]
unsafe extern "C" fn aes_nohw_delta_swap(
    a: aes_word_t,
    mask: aes_word_t,
    shift: aes_word_t,
) -> aes_word_t {
    let b: aes_word_t = (a ^ a >> shift) & mask;
    return a ^ b ^ b << shift;
}
#[inline]
unsafe extern "C" fn aes_nohw_compact_word(mut a: uint32_t) -> uint32_t {
    a = aes_nohw_delta_swap(
        a,
        0xcc00cc as core::ffi::c_int as aes_word_t,
        6 as core::ffi::c_int as aes_word_t,
    );
    a = aes_nohw_delta_swap(
        a,
        0xf0f0 as core::ffi::c_int as aes_word_t,
        12 as core::ffi::c_int as aes_word_t,
    );
    return a;
}
#[inline]
unsafe extern "C" fn aes_nohw_uncompact_word(mut a: uint32_t) -> uint32_t {
    a = aes_nohw_delta_swap(
        a,
        0xf0f0 as core::ffi::c_int as aes_word_t,
        12 as core::ffi::c_int as aes_word_t,
    );
    a = aes_nohw_delta_swap(
        a,
        0xcc00cc as core::ffi::c_int as aes_word_t,
        6 as core::ffi::c_int as aes_word_t,
    );
    return a;
}
#[inline]
unsafe extern "C" fn aes_nohw_word_from_bytes(
    a0: uint8_t,
    a1: uint8_t,
    a2: uint8_t,
    a3: uint8_t,
) -> uint32_t {
    return a0 as uint32_t
        | (a1 as uint32_t) << 8 as core::ffi::c_int
        | (a2 as uint32_t) << 16 as core::ffi::c_int
        | (a3 as uint32_t) << 24 as core::ffi::c_int;
}
#[inline]
unsafe extern "C" fn lo(a: uint32_t) -> uint8_t {
    return a as uint8_t;
}
#[inline]
unsafe extern "C" fn aes_nohw_compact_block(out: *mut aes_word_t, in_0: *const uint8_t) {
    OPENSSL_memcpy(
        out as *mut core::ffi::c_void,
        in_0 as *const core::ffi::c_void,
        16 as core::ffi::c_int as size_t,
    );
    let a0: uint32_t = aes_nohw_compact_word(*out.offset(0 as core::ffi::c_int as isize));
    let a1: uint32_t = aes_nohw_compact_word(*out.offset(1 as core::ffi::c_int as isize));
    let a2: uint32_t = aes_nohw_compact_word(*out.offset(2 as core::ffi::c_int as isize));
    let a3: uint32_t = aes_nohw_compact_word(*out.offset(3 as core::ffi::c_int as isize));
    *out.offset(0 as core::ffi::c_int as isize) =
        aes_nohw_word_from_bytes(lo(a0), lo(a1), lo(a2), lo(a3));
    *out.offset(1 as core::ffi::c_int as isize) = aes_nohw_word_from_bytes(
        lo(a0 >> 8 as core::ffi::c_int),
        lo(a1 >> 8 as core::ffi::c_int),
        lo(a2 >> 8 as core::ffi::c_int),
        lo(a3 >> 8 as core::ffi::c_int),
    );
    *out.offset(2 as core::ffi::c_int as isize) = aes_nohw_word_from_bytes(
        lo(a0 >> 16 as core::ffi::c_int),
        lo(a1 >> 16 as core::ffi::c_int),
        lo(a2 >> 16 as core::ffi::c_int),
        lo(a3 >> 16 as core::ffi::c_int),
    );
    *out.offset(3 as core::ffi::c_int as isize) = aes_nohw_word_from_bytes(
        lo(a0 >> 24 as core::ffi::c_int),
        lo(a1 >> 24 as core::ffi::c_int),
        lo(a2 >> 24 as core::ffi::c_int),
        lo(a3 >> 24 as core::ffi::c_int),
    );
}
#[inline]
unsafe extern "C" fn aes_nohw_uncompact_block(out: *mut uint8_t, in_0: *const aes_word_t) {
    let a0: uint32_t = *in_0.offset(0 as core::ffi::c_int as isize);
    let a1: uint32_t = *in_0.offset(1 as core::ffi::c_int as isize);
    let a2: uint32_t = *in_0.offset(2 as core::ffi::c_int as isize);
    let a3: uint32_t = *in_0.offset(3 as core::ffi::c_int as isize);
    let mut b0: uint32_t = aes_nohw_word_from_bytes(lo(a0), lo(a1), lo(a2), lo(a3));
    let mut b1: uint32_t = aes_nohw_word_from_bytes(
        lo(a0 >> 8 as core::ffi::c_int),
        lo(a1 >> 8 as core::ffi::c_int),
        lo(a2 >> 8 as core::ffi::c_int),
        lo(a3 >> 8 as core::ffi::c_int),
    );
    let mut b2: uint32_t = aes_nohw_word_from_bytes(
        lo(a0 >> 16 as core::ffi::c_int),
        lo(a1 >> 16 as core::ffi::c_int),
        lo(a2 >> 16 as core::ffi::c_int),
        lo(a3 >> 16 as core::ffi::c_int),
    );
    let mut b3: uint32_t = aes_nohw_word_from_bytes(
        lo(a0 >> 24 as core::ffi::c_int),
        lo(a1 >> 24 as core::ffi::c_int),
        lo(a2 >> 24 as core::ffi::c_int),
        lo(a3 >> 24 as core::ffi::c_int),
    );
    b0 = aes_nohw_uncompact_word(b0);
    b1 = aes_nohw_uncompact_word(b1);
    b2 = aes_nohw_uncompact_word(b2);
    b3 = aes_nohw_uncompact_word(b3);
    OPENSSL_memcpy(
        out as *mut core::ffi::c_void,
        &mut b0 as *mut uint32_t as *const core::ffi::c_void,
        4 as core::ffi::c_int as size_t,
    );
    OPENSSL_memcpy(
        out.offset(4 as core::ffi::c_int as isize) as *mut core::ffi::c_void,
        &mut b1 as *mut uint32_t as *const core::ffi::c_void,
        4 as core::ffi::c_int as size_t,
    );
    OPENSSL_memcpy(
        out.offset(8 as core::ffi::c_int as isize) as *mut core::ffi::c_void,
        &mut b2 as *mut uint32_t as *const core::ffi::c_void,
        4 as core::ffi::c_int as size_t,
    );
    OPENSSL_memcpy(
        out.offset(12 as core::ffi::c_int as isize) as *mut core::ffi::c_void,
        &mut b3 as *mut uint32_t as *const core::ffi::c_void,
        4 as core::ffi::c_int as size_t,
    );
}
#[inline]
unsafe extern "C" fn aes_nohw_swap_bits(
    a: *mut aes_word_t,
    b: *mut aes_word_t,
    mask: uint32_t,
    shift: aes_word_t,
) {
    let mask_w: aes_word_t = mask;
    let swap: aes_word_t = (*a >> shift ^ *b) & mask_w;
    *a ^= swap << shift;
    *b ^= swap;
}
unsafe extern "C" fn aes_nohw_transpose(batch: *mut AES_NOHW_BATCH) {
    aes_nohw_swap_bits(
        &mut *((*batch).w)
            .as_mut_ptr()
            .offset(0 as core::ffi::c_int as isize),
        &mut *((*batch).w)
            .as_mut_ptr()
            .offset(1 as core::ffi::c_int as isize),
        0x55555555 as core::ffi::c_int as uint32_t,
        1 as core::ffi::c_int as aes_word_t,
    );
    aes_nohw_swap_bits(
        &mut *((*batch).w)
            .as_mut_ptr()
            .offset(2 as core::ffi::c_int as isize),
        &mut *((*batch).w)
            .as_mut_ptr()
            .offset(3 as core::ffi::c_int as isize),
        0x55555555 as core::ffi::c_int as uint32_t,
        1 as core::ffi::c_int as aes_word_t,
    );
    aes_nohw_swap_bits(
        &mut *((*batch).w)
            .as_mut_ptr()
            .offset(4 as core::ffi::c_int as isize),
        &mut *((*batch).w)
            .as_mut_ptr()
            .offset(5 as core::ffi::c_int as isize),
        0x55555555 as core::ffi::c_int as uint32_t,
        1 as core::ffi::c_int as aes_word_t,
    );
    aes_nohw_swap_bits(
        &mut *((*batch).w)
            .as_mut_ptr()
            .offset(6 as core::ffi::c_int as isize),
        &mut *((*batch).w)
            .as_mut_ptr()
            .offset(7 as core::ffi::c_int as isize),
        0x55555555 as core::ffi::c_int as uint32_t,
        1 as core::ffi::c_int as aes_word_t,
    );
}
unsafe extern "C" fn aes_nohw_to_batch(
    out: *mut AES_NOHW_BATCH,
    in_0: *const uint8_t,
    num_blocks: size_t,
) {
    OPENSSL_memset(
        out as *mut core::ffi::c_void,
        0 as core::ffi::c_int,
        core::mem::size_of::<AES_NOHW_BATCH>() as u32,
    );
    if num_blocks <= 2 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_blocks <= 2\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/fipsmodule/aes/aes_nohw.c\0" as *const u8 as *const core::ffi::c_char,
            479 as core::ffi::c_int as core::ffi::c_uint,
            (*core::mem::transmute::<&[u8; 66], &[core::ffi::c_char; 66]>(
                b"void aes_nohw_to_batch(AES_NOHW_BATCH *, const uint8_t *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_blocks {
        let mut block: [aes_word_t; 4] = [0; 4];
        aes_nohw_compact_block(
            block.as_mut_ptr(),
            in_0.offset((16 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i) as isize),
        );
        aes_nohw_batch_set(out, block.as_mut_ptr() as *const aes_word_t, i);
        i = i.wrapping_add(1);
    }
    aes_nohw_transpose(out);
}
unsafe extern "C" fn aes_nohw_from_batch(
    out: *mut uint8_t,
    num_blocks: size_t,
    batch: *const AES_NOHW_BATCH,
) {
    let mut copy: AES_NOHW_BATCH = *batch;
    aes_nohw_transpose(&mut copy);
    if num_blocks <= 2 as core::ffi::c_int as core::ffi::c_uint {
    } else {
        __assert_fail(
            b"num_blocks <= 2\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/fipsmodule/aes/aes_nohw.c\0" as *const u8 as *const core::ffi::c_char,
            496 as core::ffi::c_int as core::ffi::c_uint,
            (*core::mem::transmute::<&[u8; 68], &[core::ffi::c_char; 68]>(
                b"void aes_nohw_from_batch(uint8_t *, size_t, const AES_NOHW_BATCH *)\0",
            ))
            .as_ptr(),
        );
    }
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < num_blocks {
        let mut block: [aes_word_t; 4] = [0; 4];
        aes_nohw_batch_get(&mut copy, block.as_mut_ptr(), i);
        aes_nohw_uncompact_block(
            out.offset((16 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i) as isize),
            block.as_mut_ptr() as *const aes_word_t,
        );
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn aes_nohw_add_round_key(
    batch: *mut AES_NOHW_BATCH,
    key: *const AES_NOHW_BATCH,
) {
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < 8 as core::ffi::c_int as core::ffi::c_uint {
        (*batch).w[i as usize] = aes_nohw_xor((*batch).w[i as usize], (*key).w[i as usize]);
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn aes_nohw_sub_bytes(batch: *mut AES_NOHW_BATCH) {
    let x0: aes_word_t = (*batch).w[7 as core::ffi::c_int as usize];
    let x1: aes_word_t = (*batch).w[6 as core::ffi::c_int as usize];
    let x2: aes_word_t = (*batch).w[5 as core::ffi::c_int as usize];
    let x3: aes_word_t = (*batch).w[4 as core::ffi::c_int as usize];
    let x4: aes_word_t = (*batch).w[3 as core::ffi::c_int as usize];
    let x5: aes_word_t = (*batch).w[2 as core::ffi::c_int as usize];
    let x6: aes_word_t = (*batch).w[1 as core::ffi::c_int as usize];
    let x7: aes_word_t = (*batch).w[0 as core::ffi::c_int as usize];
    let y14: aes_word_t = aes_nohw_xor(x3, x5);
    let y13: aes_word_t = aes_nohw_xor(x0, x6);
    let y9: aes_word_t = aes_nohw_xor(x0, x3);
    let y8: aes_word_t = aes_nohw_xor(x0, x5);
    let t0: aes_word_t = aes_nohw_xor(x1, x2);
    let y1: aes_word_t = aes_nohw_xor(t0, x7);
    let y4: aes_word_t = aes_nohw_xor(y1, x3);
    let y12: aes_word_t = aes_nohw_xor(y13, y14);
    let y2: aes_word_t = aes_nohw_xor(y1, x0);
    let y5: aes_word_t = aes_nohw_xor(y1, x6);
    let y3: aes_word_t = aes_nohw_xor(y5, y8);
    let t1: aes_word_t = aes_nohw_xor(x4, y12);
    let y15: aes_word_t = aes_nohw_xor(t1, x5);
    let y20: aes_word_t = aes_nohw_xor(t1, x1);
    let y6: aes_word_t = aes_nohw_xor(y15, x7);
    let y10: aes_word_t = aes_nohw_xor(y15, t0);
    let y11: aes_word_t = aes_nohw_xor(y20, y9);
    let y7: aes_word_t = aes_nohw_xor(x7, y11);
    let y17: aes_word_t = aes_nohw_xor(y10, y11);
    let y19: aes_word_t = aes_nohw_xor(y10, y8);
    let y16: aes_word_t = aes_nohw_xor(t0, y11);
    let y21: aes_word_t = aes_nohw_xor(y13, y16);
    let y18: aes_word_t = aes_nohw_xor(x0, y16);
    let t2: aes_word_t = aes_nohw_and(y12, y15);
    let t3: aes_word_t = aes_nohw_and(y3, y6);
    let t4: aes_word_t = aes_nohw_xor(t3, t2);
    let t5: aes_word_t = aes_nohw_and(y4, x7);
    let t6: aes_word_t = aes_nohw_xor(t5, t2);
    let t7: aes_word_t = aes_nohw_and(y13, y16);
    let t8: aes_word_t = aes_nohw_and(y5, y1);
    let t9: aes_word_t = aes_nohw_xor(t8, t7);
    let t10: aes_word_t = aes_nohw_and(y2, y7);
    let t11: aes_word_t = aes_nohw_xor(t10, t7);
    let t12: aes_word_t = aes_nohw_and(y9, y11);
    let t13: aes_word_t = aes_nohw_and(y14, y17);
    let t14: aes_word_t = aes_nohw_xor(t13, t12);
    let t15: aes_word_t = aes_nohw_and(y8, y10);
    let t16: aes_word_t = aes_nohw_xor(t15, t12);
    let t17: aes_word_t = aes_nohw_xor(t4, t14);
    let t18: aes_word_t = aes_nohw_xor(t6, t16);
    let t19: aes_word_t = aes_nohw_xor(t9, t14);
    let t20: aes_word_t = aes_nohw_xor(t11, t16);
    let t21: aes_word_t = aes_nohw_xor(t17, y20);
    let t22: aes_word_t = aes_nohw_xor(t18, y19);
    let t23: aes_word_t = aes_nohw_xor(t19, y21);
    let t24: aes_word_t = aes_nohw_xor(t20, y18);
    let t25: aes_word_t = aes_nohw_xor(t21, t22);
    let t26: aes_word_t = aes_nohw_and(t21, t23);
    let t27: aes_word_t = aes_nohw_xor(t24, t26);
    let t28: aes_word_t = aes_nohw_and(t25, t27);
    let t29: aes_word_t = aes_nohw_xor(t28, t22);
    let t30: aes_word_t = aes_nohw_xor(t23, t24);
    let t31: aes_word_t = aes_nohw_xor(t22, t26);
    let t32: aes_word_t = aes_nohw_and(t31, t30);
    let t33: aes_word_t = aes_nohw_xor(t32, t24);
    let t34: aes_word_t = aes_nohw_xor(t23, t33);
    let t35: aes_word_t = aes_nohw_xor(t27, t33);
    let t36: aes_word_t = aes_nohw_and(t24, t35);
    let t37: aes_word_t = aes_nohw_xor(t36, t34);
    let t38: aes_word_t = aes_nohw_xor(t27, t36);
    let t39: aes_word_t = aes_nohw_and(t29, t38);
    let t40: aes_word_t = aes_nohw_xor(t25, t39);
    let t41: aes_word_t = aes_nohw_xor(t40, t37);
    let t42: aes_word_t = aes_nohw_xor(t29, t33);
    let t43: aes_word_t = aes_nohw_xor(t29, t40);
    let t44: aes_word_t = aes_nohw_xor(t33, t37);
    let t45: aes_word_t = aes_nohw_xor(t42, t41);
    let z0: aes_word_t = aes_nohw_and(t44, y15);
    let z1: aes_word_t = aes_nohw_and(t37, y6);
    let z2: aes_word_t = aes_nohw_and(t33, x7);
    let z3: aes_word_t = aes_nohw_and(t43, y16);
    let z4: aes_word_t = aes_nohw_and(t40, y1);
    let z5: aes_word_t = aes_nohw_and(t29, y7);
    let z6: aes_word_t = aes_nohw_and(t42, y11);
    let z7: aes_word_t = aes_nohw_and(t45, y17);
    let z8: aes_word_t = aes_nohw_and(t41, y10);
    let z9: aes_word_t = aes_nohw_and(t44, y12);
    let z10: aes_word_t = aes_nohw_and(t37, y3);
    let z11: aes_word_t = aes_nohw_and(t33, y4);
    let z12: aes_word_t = aes_nohw_and(t43, y13);
    let z13: aes_word_t = aes_nohw_and(t40, y5);
    let z14: aes_word_t = aes_nohw_and(t29, y2);
    let z15: aes_word_t = aes_nohw_and(t42, y9);
    let z16: aes_word_t = aes_nohw_and(t45, y14);
    let z17: aes_word_t = aes_nohw_and(t41, y8);
    let t46: aes_word_t = aes_nohw_xor(z15, z16);
    let t47: aes_word_t = aes_nohw_xor(z10, z11);
    let t48: aes_word_t = aes_nohw_xor(z5, z13);
    let t49: aes_word_t = aes_nohw_xor(z9, z10);
    let t50: aes_word_t = aes_nohw_xor(z2, z12);
    let t51: aes_word_t = aes_nohw_xor(z2, z5);
    let t52: aes_word_t = aes_nohw_xor(z7, z8);
    let t53: aes_word_t = aes_nohw_xor(z0, z3);
    let t54: aes_word_t = aes_nohw_xor(z6, z7);
    let t55: aes_word_t = aes_nohw_xor(z16, z17);
    let t56: aes_word_t = aes_nohw_xor(z12, t48);
    let t57: aes_word_t = aes_nohw_xor(t50, t53);
    let t58: aes_word_t = aes_nohw_xor(z4, t46);
    let t59: aes_word_t = aes_nohw_xor(z3, t54);
    let t60: aes_word_t = aes_nohw_xor(t46, t57);
    let t61: aes_word_t = aes_nohw_xor(z14, t57);
    let t62: aes_word_t = aes_nohw_xor(t52, t58);
    let t63: aes_word_t = aes_nohw_xor(t49, t58);
    let t64: aes_word_t = aes_nohw_xor(z4, t59);
    let t65: aes_word_t = aes_nohw_xor(t61, t62);
    let t66: aes_word_t = aes_nohw_xor(z1, t63);
    let s0: aes_word_t = aes_nohw_xor(t59, t63);
    let s6: aes_word_t = aes_nohw_xor(t56, aes_nohw_not(t62));
    let s7: aes_word_t = aes_nohw_xor(t48, aes_nohw_not(t60));
    let t67: aes_word_t = aes_nohw_xor(t64, t65);
    let s3: aes_word_t = aes_nohw_xor(t53, t66);
    let s4: aes_word_t = aes_nohw_xor(t51, t66);
    let s5: aes_word_t = aes_nohw_xor(t47, t65);
    let s1: aes_word_t = aes_nohw_xor(t64, aes_nohw_not(s3));
    let s2: aes_word_t = aes_nohw_xor(t55, aes_nohw_not(t67));
    (*batch).w[0 as core::ffi::c_int as usize] = s7;
    (*batch).w[1 as core::ffi::c_int as usize] = s6;
    (*batch).w[2 as core::ffi::c_int as usize] = s5;
    (*batch).w[3 as core::ffi::c_int as usize] = s4;
    (*batch).w[4 as core::ffi::c_int as usize] = s3;
    (*batch).w[5 as core::ffi::c_int as usize] = s2;
    (*batch).w[6 as core::ffi::c_int as usize] = s1;
    (*batch).w[7 as core::ffi::c_int as usize] = s0;
}
unsafe extern "C" fn aes_nohw_shift_rows(batch: *mut AES_NOHW_BATCH) {
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < 8 as core::ffi::c_int as core::ffi::c_uint {
        let row0: aes_word_t = aes_nohw_and(
            (*batch).w[i as usize],
            0x3030303 as core::ffi::c_int as aes_word_t,
        );
        let mut row1: aes_word_t = aes_nohw_and(
            (*batch).w[i as usize],
            0xc0c0c0c as core::ffi::c_int as aes_word_t,
        );
        let mut row2: aes_word_t = aes_nohw_and(
            (*batch).w[i as usize],
            0x30303030 as core::ffi::c_int as aes_word_t,
        );
        let mut row3: aes_word_t =
            aes_nohw_and((*batch).w[i as usize], 0xc0c0c0c0 as core::ffi::c_uint);
        row1 = aes_nohw_or(
            aes_nohw_shift_right(
                row1,
                (1 as core::ffi::c_int * 4 as core::ffi::c_int) as aes_word_t,
            ),
            aes_nohw_shift_left(
                row1,
                (16 as core::ffi::c_int - 1 as core::ffi::c_int * 4 as core::ffi::c_int)
                    as aes_word_t,
            ),
        );
        row2 = aes_nohw_or(
            aes_nohw_shift_right(
                row2,
                (2 as core::ffi::c_int * 4 as core::ffi::c_int) as aes_word_t,
            ),
            aes_nohw_shift_left(
                row2,
                (16 as core::ffi::c_int - 2 as core::ffi::c_int * 4 as core::ffi::c_int)
                    as aes_word_t,
            ),
        );
        row3 = aes_nohw_or(
            aes_nohw_shift_right(
                row3,
                (3 as core::ffi::c_int * 4 as core::ffi::c_int) as aes_word_t,
            ),
            aes_nohw_shift_left(
                row3,
                (16 as core::ffi::c_int - 3 as core::ffi::c_int * 4 as core::ffi::c_int)
                    as aes_word_t,
            ),
        );
        (*batch).w[i as usize] = aes_nohw_or(aes_nohw_or(row0, row1), aes_nohw_or(row2, row3));
        i = i.wrapping_add(1);
    }
}
#[inline]
unsafe extern "C" fn aes_nohw_rotate_rows_down(v: aes_word_t) -> aes_word_t {
    return v >> 2 as core::ffi::c_int & 0x3f3f3f3f as core::ffi::c_int as core::ffi::c_uint
        | v << 6 as core::ffi::c_int & 0xc0c0c0c0 as core::ffi::c_uint;
}
#[inline]
unsafe extern "C" fn aes_nohw_rotate_rows_twice(v: aes_word_t) -> aes_word_t {
    return v >> 4 as core::ffi::c_int & 0xf0f0f0f as core::ffi::c_int as core::ffi::c_uint
        | v << 4 as core::ffi::c_int & 0xf0f0f0f0 as core::ffi::c_uint;
}
unsafe extern "C" fn aes_nohw_mix_columns(batch: *mut AES_NOHW_BATCH) {
    let a0: aes_word_t = (*batch).w[0 as core::ffi::c_int as usize];
    let a1: aes_word_t = (*batch).w[1 as core::ffi::c_int as usize];
    let a2: aes_word_t = (*batch).w[2 as core::ffi::c_int as usize];
    let a3: aes_word_t = (*batch).w[3 as core::ffi::c_int as usize];
    let a4: aes_word_t = (*batch).w[4 as core::ffi::c_int as usize];
    let a5: aes_word_t = (*batch).w[5 as core::ffi::c_int as usize];
    let a6: aes_word_t = (*batch).w[6 as core::ffi::c_int as usize];
    let a7: aes_word_t = (*batch).w[7 as core::ffi::c_int as usize];
    let r0: aes_word_t = aes_nohw_rotate_rows_down(a0);
    let a0_r0: aes_word_t = aes_nohw_xor(a0, r0);
    let r1: aes_word_t = aes_nohw_rotate_rows_down(a1);
    let a1_r1: aes_word_t = aes_nohw_xor(a1, r1);
    let r2: aes_word_t = aes_nohw_rotate_rows_down(a2);
    let a2_r2: aes_word_t = aes_nohw_xor(a2, r2);
    let r3: aes_word_t = aes_nohw_rotate_rows_down(a3);
    let a3_r3: aes_word_t = aes_nohw_xor(a3, r3);
    let r4: aes_word_t = aes_nohw_rotate_rows_down(a4);
    let a4_r4: aes_word_t = aes_nohw_xor(a4, r4);
    let r5: aes_word_t = aes_nohw_rotate_rows_down(a5);
    let a5_r5: aes_word_t = aes_nohw_xor(a5, r5);
    let r6: aes_word_t = aes_nohw_rotate_rows_down(a6);
    let a6_r6: aes_word_t = aes_nohw_xor(a6, r6);
    let r7: aes_word_t = aes_nohw_rotate_rows_down(a7);
    let a7_r7: aes_word_t = aes_nohw_xor(a7, r7);
    (*batch).w[0 as core::ffi::c_int as usize] =
        aes_nohw_xor(aes_nohw_xor(a7_r7, r0), aes_nohw_rotate_rows_twice(a0_r0));
    (*batch).w[1 as core::ffi::c_int as usize] = aes_nohw_xor(
        aes_nohw_xor(a0_r0, a7_r7),
        aes_nohw_xor(r1, aes_nohw_rotate_rows_twice(a1_r1)),
    );
    (*batch).w[2 as core::ffi::c_int as usize] =
        aes_nohw_xor(aes_nohw_xor(a1_r1, r2), aes_nohw_rotate_rows_twice(a2_r2));
    (*batch).w[3 as core::ffi::c_int as usize] = aes_nohw_xor(
        aes_nohw_xor(a2_r2, a7_r7),
        aes_nohw_xor(r3, aes_nohw_rotate_rows_twice(a3_r3)),
    );
    (*batch).w[4 as core::ffi::c_int as usize] = aes_nohw_xor(
        aes_nohw_xor(a3_r3, a7_r7),
        aes_nohw_xor(r4, aes_nohw_rotate_rows_twice(a4_r4)),
    );
    (*batch).w[5 as core::ffi::c_int as usize] =
        aes_nohw_xor(aes_nohw_xor(a4_r4, r5), aes_nohw_rotate_rows_twice(a5_r5));
    (*batch).w[6 as core::ffi::c_int as usize] =
        aes_nohw_xor(aes_nohw_xor(a5_r5, r6), aes_nohw_rotate_rows_twice(a6_r6));
    (*batch).w[7 as core::ffi::c_int as usize] =
        aes_nohw_xor(aes_nohw_xor(a6_r6, r7), aes_nohw_rotate_rows_twice(a7_r7));
}
unsafe extern "C" fn aes_nohw_encrypt_batch(
    key: *const AES_NOHW_SCHEDULE,
    num_rounds: size_t,
    batch: *mut AES_NOHW_BATCH,
) {
    aes_nohw_add_round_key(
        batch,
        &*((*key).keys)
            .as_ptr()
            .offset(0 as core::ffi::c_int as isize),
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
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
    out: *mut AES_NOHW_SCHEDULE,
    key: *const AES_KEY,
) {
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i <= (*key).rounds {
        let mut j: size_t = 0 as core::ffi::c_int as size_t;
        while j < 2 as core::ffi::c_int as core::ffi::c_uint {
            let mut tmp: [aes_word_t; 4] = [0; 4];
            OPENSSL_memcpy(
                tmp.as_mut_ptr() as *mut core::ffi::c_void,
                ((*key).rd_key)
                    .as_ptr()
                    .offset((4 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i) as isize)
                    as *const core::ffi::c_void,
                16 as core::ffi::c_int as size_t,
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
    0x1 as core::ffi::c_int as uint8_t,
    0x2 as core::ffi::c_int as uint8_t,
    0x4 as core::ffi::c_int as uint8_t,
    0x8 as core::ffi::c_int as uint8_t,
    0x10 as core::ffi::c_int as uint8_t,
    0x20 as core::ffi::c_int as uint8_t,
    0x40 as core::ffi::c_int as uint8_t,
    0x80 as core::ffi::c_int as uint8_t,
    0x1b as core::ffi::c_int as uint8_t,
    0x36 as core::ffi::c_int as uint8_t,
];
#[inline]
unsafe extern "C" fn aes_nohw_rcon_slice(mut rcon: uint8_t, i: size_t) -> aes_word_t {
    rcon = (rcon as core::ffi::c_int >> i.wrapping_mul(2 as core::ffi::c_int as core::ffi::c_uint)
        & ((1 as core::ffi::c_int) << 2 as core::ffi::c_int) - 1 as core::ffi::c_int)
        as uint8_t;
    return rcon as aes_word_t;
}
unsafe extern "C" fn aes_nohw_sub_block(out: *mut aes_word_t, in_0: *const aes_word_t) {
    let mut batch: AES_NOHW_BATCH = AES_NOHW_BATCH { w: [0; 8] };
    OPENSSL_memset(
        &mut batch as *mut AES_NOHW_BATCH as *mut core::ffi::c_void,
        0 as core::ffi::c_int,
        core::mem::size_of::<AES_NOHW_BATCH>() as u32,
    );
    aes_nohw_batch_set(&mut batch, in_0, 0 as core::ffi::c_int as size_t);
    aes_nohw_transpose(&mut batch);
    aes_nohw_sub_bytes(&mut batch);
    aes_nohw_transpose(&mut batch);
    aes_nohw_batch_get(&mut batch, out, 0 as core::ffi::c_int as size_t);
}
unsafe extern "C" fn aes_nohw_setup_key_128(key: *mut AES_KEY, in_0: *const uint8_t) {
    (*key).rounds = 10 as core::ffi::c_int as core::ffi::c_uint;
    let mut block: [aes_word_t; 4] = [0; 4];
    aes_nohw_compact_block(block.as_mut_ptr(), in_0);
    OPENSSL_memcpy(
        ((*key).rd_key).as_mut_ptr() as *mut core::ffi::c_void,
        block.as_mut_ptr() as *const core::ffi::c_void,
        16 as core::ffi::c_int as size_t,
    );
    let mut i: size_t = 1 as core::ffi::c_int as size_t;
    while i <= 10 as core::ffi::c_int as core::ffi::c_uint {
        let mut sub: [aes_word_t; 4] = [0; 4];
        aes_nohw_sub_block(sub.as_mut_ptr(), block.as_mut_ptr() as *const aes_word_t);
        let rcon: uint8_t =
            aes_nohw_rcon[i.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint) as usize];
        let mut j: size_t = 0 as core::ffi::c_int as size_t;
        while j
            < (16 as core::ffi::c_int as core::ffi::c_uint)
                .wrapping_div(core::mem::size_of::<aes_word_t>() as u32)
        {
            block[j as usize] = aes_nohw_xor(block[j as usize], aes_nohw_rcon_slice(rcon, j));
            block[j as usize] = aes_nohw_xor(
                block[j as usize],
                aes_nohw_shift_right(
                    aes_nohw_rotate_rows_down(sub[j as usize]),
                    12 as core::ffi::c_int as aes_word_t,
                ),
            );
            let v: aes_word_t = block[j as usize];
            block[j as usize] = aes_nohw_xor(
                block[j as usize],
                aes_nohw_shift_left(v, 4 as core::ffi::c_int as aes_word_t),
            );
            block[j as usize] = aes_nohw_xor(
                block[j as usize],
                aes_nohw_shift_left(v, 8 as core::ffi::c_int as aes_word_t),
            );
            block[j as usize] = aes_nohw_xor(
                block[j as usize],
                aes_nohw_shift_left(v, 12 as core::ffi::c_int as aes_word_t),
            );
            j = j.wrapping_add(1);
        }
        OPENSSL_memcpy(
            ((*key).rd_key)
                .as_mut_ptr()
                .offset((4 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i) as isize)
                as *mut core::ffi::c_void,
            block.as_mut_ptr() as *const core::ffi::c_void,
            16 as core::ffi::c_int as size_t,
        );
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn aes_nohw_setup_key_256(key: *mut AES_KEY, in_0: *const uint8_t) {
    (*key).rounds = 14 as core::ffi::c_int as core::ffi::c_uint;
    let mut block1: [aes_word_t; 4] = [0; 4];
    let mut block2: [aes_word_t; 4] = [0; 4];
    aes_nohw_compact_block(block1.as_mut_ptr(), in_0);
    OPENSSL_memcpy(
        ((*key).rd_key).as_mut_ptr() as *mut core::ffi::c_void,
        block1.as_mut_ptr() as *const core::ffi::c_void,
        16 as core::ffi::c_int as size_t,
    );
    aes_nohw_compact_block(
        block2.as_mut_ptr(),
        in_0.offset(16 as core::ffi::c_int as isize),
    );
    OPENSSL_memcpy(
        ((*key).rd_key)
            .as_mut_ptr()
            .offset(4 as core::ffi::c_int as isize) as *mut core::ffi::c_void,
        block2.as_mut_ptr() as *const core::ffi::c_void,
        16 as core::ffi::c_int as size_t,
    );
    let mut i: size_t = 2 as core::ffi::c_int as size_t;
    while i <= 14 as core::ffi::c_int as core::ffi::c_uint {
        let mut sub: [aes_word_t; 4] = [0; 4];
        aes_nohw_sub_block(sub.as_mut_ptr(), block2.as_mut_ptr() as *const aes_word_t);
        let rcon: uint8_t = aes_nohw_rcon[i
            .wrapping_div(2 as core::ffi::c_int as core::ffi::c_uint)
            .wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint)
            as usize];
        let mut j: size_t = 0 as core::ffi::c_int as size_t;
        while j
            < (16 as core::ffi::c_int as core::ffi::c_uint)
                .wrapping_div(core::mem::size_of::<aes_word_t>() as u32)
        {
            block1[j as usize] = aes_nohw_xor(block1[j as usize], aes_nohw_rcon_slice(rcon, j));
            block1[j as usize] = aes_nohw_xor(
                block1[j as usize],
                aes_nohw_shift_right(
                    aes_nohw_rotate_rows_down(sub[j as usize]),
                    12 as core::ffi::c_int as aes_word_t,
                ),
            );
            let v: aes_word_t = block1[j as usize];
            block1[j as usize] = aes_nohw_xor(
                block1[j as usize],
                aes_nohw_shift_left(v, 4 as core::ffi::c_int as aes_word_t),
            );
            block1[j as usize] = aes_nohw_xor(
                block1[j as usize],
                aes_nohw_shift_left(v, 8 as core::ffi::c_int as aes_word_t),
            );
            block1[j as usize] = aes_nohw_xor(
                block1[j as usize],
                aes_nohw_shift_left(v, 12 as core::ffi::c_int as aes_word_t),
            );
            j = j.wrapping_add(1);
        }
        OPENSSL_memcpy(
            ((*key).rd_key)
                .as_mut_ptr()
                .offset((4 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i) as isize)
                as *mut core::ffi::c_void,
            block1.as_mut_ptr() as *const core::ffi::c_void,
            16 as core::ffi::c_int as size_t,
        );
        if i == 14 as core::ffi::c_int as core::ffi::c_uint {
            break;
        }
        aes_nohw_sub_block(sub.as_mut_ptr(), block1.as_mut_ptr() as *const aes_word_t);
        let mut j_0: size_t = 0 as core::ffi::c_int as size_t;
        while j_0
            < (16 as core::ffi::c_int as core::ffi::c_uint)
                .wrapping_div(core::mem::size_of::<aes_word_t>() as u32)
        {
            block2[j_0 as usize] = aes_nohw_xor(
                block2[j_0 as usize],
                aes_nohw_shift_right(sub[j_0 as usize], 12 as core::ffi::c_int as aes_word_t),
            );
            let v_0: aes_word_t = block2[j_0 as usize];
            block2[j_0 as usize] = aes_nohw_xor(
                block2[j_0 as usize],
                aes_nohw_shift_left(v_0, 4 as core::ffi::c_int as aes_word_t),
            );
            block2[j_0 as usize] = aes_nohw_xor(
                block2[j_0 as usize],
                aes_nohw_shift_left(v_0, 8 as core::ffi::c_int as aes_word_t),
            );
            block2[j_0 as usize] = aes_nohw_xor(
                block2[j_0 as usize],
                aes_nohw_shift_left(v_0, 12 as core::ffi::c_int as aes_word_t),
            );
            j_0 = j_0.wrapping_add(1);
        }
        OPENSSL_memcpy(
            ((*key).rd_key).as_mut_ptr().offset(
                (4 as core::ffi::c_int as core::ffi::c_uint)
                    .wrapping_mul(i.wrapping_add(1 as core::ffi::c_int as core::ffi::c_uint))
                    as isize,
            ) as *mut core::ffi::c_void,
            block2.as_mut_ptr() as *const core::ffi::c_void,
            16 as core::ffi::c_int as size_t,
        );
        i = (i as core::ffi::c_uint).wrapping_add(2 as core::ffi::c_int as core::ffi::c_uint)
            as size_t as size_t;
    }
}
#[no_mangle]
pub unsafe extern "C" fn aes_nohw_set_encrypt_key(
    key: *const uint8_t,
    bits: core::ffi::c_uint,
    aeskey: *mut AES_KEY,
) -> core::ffi::c_int {
    match bits {
        128 => {
            aes_nohw_setup_key_128(aeskey, key);
            return 0 as core::ffi::c_int;
        }
        256 => {
            aes_nohw_setup_key_256(aeskey, key);
            return 0 as core::ffi::c_int;
        }
        _ => {}
    }
    return 1 as core::ffi::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn aes_nohw_encrypt(
    in_0: *const uint8_t,
    out: *mut uint8_t,
    key: *const AES_KEY,
) {
    let mut sched: AES_NOHW_SCHEDULE = AES_NOHW_SCHEDULE {
        keys: [AES_NOHW_BATCH { w: [0; 8] }; 15],
    };
    aes_nohw_expand_round_keys(&mut sched, key);
    let mut batch: AES_NOHW_BATCH = AES_NOHW_BATCH { w: [0; 8] };
    aes_nohw_to_batch(&mut batch, in_0, 1 as core::ffi::c_int as size_t);
    aes_nohw_encrypt_batch(&mut sched, (*key).rounds, &mut batch);
    aes_nohw_from_batch(out, 1 as core::ffi::c_int as size_t, &mut batch);
}
#[inline]
unsafe extern "C" fn aes_nohw_xor_block(
    out: *mut uint8_t,
    a: *const uint8_t,
    b: *const uint8_t,
) {
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < 16 as core::ffi::c_int as core::ffi::c_uint {
        let mut x: aes_word_t = 0;
        let mut y: aes_word_t = 0;
        OPENSSL_memcpy(
            &mut x as *mut aes_word_t as *mut core::ffi::c_void,
            a.offset(i as isize) as *const core::ffi::c_void,
            core::mem::size_of::<aes_word_t>() as u32,
        );
        OPENSSL_memcpy(
            &mut y as *mut aes_word_t as *mut core::ffi::c_void,
            b.offset(i as isize) as *const core::ffi::c_void,
            core::mem::size_of::<aes_word_t>() as u32,
        );
        x = aes_nohw_xor(x, y);
        OPENSSL_memcpy(
            out.offset(i as isize) as *mut core::ffi::c_void,
            &mut x as *mut aes_word_t as *const core::ffi::c_void,
            core::mem::size_of::<aes_word_t>() as u32,
        );
        i = (i as core::ffi::c_uint).wrapping_add(core::mem::size_of::<aes_word_t>() as u32)
            as size_t as size_t;
    }
}
#[no_mangle]
pub unsafe extern "C" fn aes_nohw_ctr32_encrypt_blocks(
    mut in_0: *const uint8_t,
    mut out: *mut uint8_t,
    mut blocks: size_t,
    key: *const AES_KEY,
    ivec: *const uint8_t,
) {
    if blocks == 0 as core::ffi::c_int as core::ffi::c_uint {
        return;
    }
    let mut sched: AES_NOHW_SCHEDULE = AES_NOHW_SCHEDULE {
        keys: [AES_NOHW_BATCH { w: [0; 8] }; 15],
    };
    aes_nohw_expand_round_keys(&mut sched, key);
    let mut ivs: [uint8_t; 32] = [0; 32];
    let mut enc_ivs: [uint8_t; 32] = [0; 32];
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < 2 as core::ffi::c_int as core::ffi::c_uint {
        OPENSSL_memcpy(
            ivs.as_mut_ptr()
                .offset((16 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i) as isize)
                as *mut core::ffi::c_void,
            ivec as *const core::ffi::c_void,
            16 as core::ffi::c_int as size_t,
        );
        i = i.wrapping_add(1);
    }
    let mut ctr: uint32_t = CRYPTO_load_u32_be(
        ivs.as_mut_ptr().offset(12 as core::ffi::c_int as isize) as *const core::ffi::c_void,
    );
    loop {
        let mut i_0: size_t = 0 as core::ffi::c_int as size_t;
        while i_0 < 2 as core::ffi::c_int as core::ffi::c_uint {
            CRYPTO_store_u32_be(
                ivs.as_mut_ptr()
                    .offset(
                        (16 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i_0) as isize,
                    )
                    .offset(12 as core::ffi::c_int as isize)
                    as *mut core::ffi::c_void,
                ctr.wrapping_add(i_0),
            );
            i_0 = i_0.wrapping_add(1);
        }
        let todo: size_t = if blocks >= 2 as core::ffi::c_int as core::ffi::c_uint {
            2 as core::ffi::c_int as core::ffi::c_uint
        } else {
            blocks
        };
        let mut batch: AES_NOHW_BATCH = AES_NOHW_BATCH { w: [0; 8] };
        aes_nohw_to_batch(&mut batch, ivs.as_mut_ptr(), todo);
        aes_nohw_encrypt_batch(&mut sched, (*key).rounds, &mut batch);
        aes_nohw_from_batch(enc_ivs.as_mut_ptr(), todo, &mut batch);
        let mut i_1: size_t = 0 as core::ffi::c_int as size_t;
        while i_1 < todo {
            aes_nohw_xor_block(
                out.offset(
                    (16 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i_1) as isize,
                ),
                in_0.offset(
                    (16 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i_1) as isize,
                ),
                enc_ivs.as_mut_ptr().offset(
                    (16 as core::ffi::c_int as core::ffi::c_uint).wrapping_mul(i_1) as isize,
                ) as *const uint8_t,
            );
            i_1 = i_1.wrapping_add(1);
        }
        blocks = (blocks as core::ffi::c_uint).wrapping_sub(todo) as size_t as size_t;
        if blocks == 0 as core::ffi::c_int as core::ffi::c_uint {
            break;
        }
        in_0 = in_0.offset((16 as core::ffi::c_int * 2 as core::ffi::c_int) as isize);
        out = out.offset((16 as core::ffi::c_int * 2 as core::ffi::c_int) as isize);
        ctr = (ctr as core::ffi::c_uint).wrapping_add(2 as core::ffi::c_int as core::ffi::c_uint)
            as uint32_t as uint32_t;
    }
}

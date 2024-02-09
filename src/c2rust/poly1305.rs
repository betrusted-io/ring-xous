#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern "C" {
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: core::ffi::c_uint,
    ) -> *mut core::ffi::c_void;
}
pub type size_t = core::ffi::c_uint;
pub type __uint8_t = core::ffi::c_uchar;
pub type __uint32_t = core::ffi::c_uint;
pub type __uint64_t = u64;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = core::ffi::c_uint;
pub type poly1305_state = [uint8_t; 512];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct poly1305_state_st {
    pub r0: uint32_t,
    pub r1: uint32_t,
    pub r2: uint32_t,
    pub r3: uint32_t,
    pub r4: uint32_t,
    pub s1: uint32_t,
    pub s2: uint32_t,
    pub s3: uint32_t,
    pub s4: uint32_t,
    pub h0: uint32_t,
    pub h1: uint32_t,
    pub h2: uint32_t,
    pub h3: uint32_t,
    pub h4: uint32_t,
    pub buf: [uint8_t; 16],
    pub buf_used: size_t,
    pub key: [uint8_t; 16],
}
#[inline]
unsafe extern "C" fn CRYPTO_store_u32_le(mut out: *mut core::ffi::c_void, mut v: uint32_t) {
    OPENSSL_memcpy(
        out,
        &mut v as *mut uint32_t as *const core::ffi::c_void,
        core::mem::size_of::<uint32_t>() as u32,
    );
}
#[inline]
unsafe extern "C" fn CRYPTO_load_u32_le(mut in_0: *const core::ffi::c_void) -> uint32_t {
    let mut v: uint32_t = 0;
    OPENSSL_memcpy(
        &mut v as *mut uint32_t as *mut core::ffi::c_void,
        in_0,
        core::mem::size_of::<uint32_t>() as u32,
    );
    return v;
}
#[inline]
unsafe extern "C" fn OPENSSL_memcpy(
    mut dst: *mut core::ffi::c_void,
    mut src: *const core::ffi::c_void,
    mut n: size_t,
) -> *mut core::ffi::c_void {
    if n == 0 as core::ffi::c_int as core::ffi::c_uint {
        return dst;
    }
    return memcpy(dst, src, n);
}
unsafe extern "C" fn mul32x32_64(mut a: uint32_t, mut b: uint32_t) -> uint64_t {
    return (a as uint64_t).wrapping_mul(b as u64);
}
#[inline]
unsafe extern "C" fn poly1305_aligned_state(
    mut state: *mut poly1305_state,
) -> *mut poly1305_state_st {
    return ((state as uintptr_t).wrapping_add(63 as core::ffi::c_int as core::ffi::c_uint)
        & !(63 as core::ffi::c_int) as core::ffi::c_uint) as *mut poly1305_state_st;
}
unsafe extern "C" fn poly1305_update(
    mut state: *mut poly1305_state_st,
    mut in_0: *const uint8_t,
    mut len: size_t,
) {
    let mut current_block: u64;
    let mut t0: uint32_t = 0;
    let mut t1: uint32_t = 0;
    let mut t2: uint32_t = 0;
    let mut t3: uint32_t = 0;
    let mut t: [uint64_t; 5] = [0; 5];
    let mut b: uint32_t = 0;
    let mut c: uint64_t = 0;
    let mut j: size_t = 0;
    let mut mp: [uint8_t; 16] = [0; 16];
    if len < 16 as core::ffi::c_int as core::ffi::c_uint {
        current_block = 13995579333348105930;
    } else {
        current_block = 17160205090870801376;
    }
    loop {
        match current_block {
            17160205090870801376 => {
                t0 = CRYPTO_load_u32_le(in_0 as *const core::ffi::c_void);
                t1 = CRYPTO_load_u32_le(
                    in_0.offset(4 as core::ffi::c_int as isize) as *const core::ffi::c_void
                );
                t2 = CRYPTO_load_u32_le(
                    in_0.offset(8 as core::ffi::c_int as isize) as *const core::ffi::c_void
                );
                t3 = CRYPTO_load_u32_le(
                    in_0.offset(12 as core::ffi::c_int as isize) as *const core::ffi::c_void
                );
                in_0 = in_0.offset(16 as core::ffi::c_int as isize);
                len = (len as core::ffi::c_uint)
                    .wrapping_sub(16 as core::ffi::c_int as core::ffi::c_uint)
                    as size_t as size_t;
                let ref mut fresh0 = (*state).h0;
                *fresh0 = (*fresh0 as core::ffi::c_uint)
                    .wrapping_add(t0 & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint)
                    as uint32_t as uint32_t;
                let ref mut fresh1 = (*state).h1;
                *fresh1 = (*fresh1 as u64).wrapping_add(
                    ((t1 as uint64_t) << 32 as core::ffi::c_int | t0 as u64)
                        >> 26 as core::ffi::c_int
                        & 0x3ffffff as core::ffi::c_int as u64,
                ) as uint32_t as uint32_t;
                let ref mut fresh2 = (*state).h2;
                *fresh2 = (*fresh2 as u64).wrapping_add(
                    ((t2 as uint64_t) << 32 as core::ffi::c_int | t1 as u64)
                        >> 20 as core::ffi::c_int
                        & 0x3ffffff as core::ffi::c_int as u64,
                ) as uint32_t as uint32_t;
                let ref mut fresh3 = (*state).h3;
                *fresh3 = (*fresh3 as u64).wrapping_add(
                    ((t3 as uint64_t) << 32 as core::ffi::c_int | t2 as u64)
                        >> 14 as core::ffi::c_int
                        & 0x3ffffff as core::ffi::c_int as u64,
                ) as uint32_t as uint32_t;
                let ref mut fresh4 = (*state).h4;
                *fresh4 = (*fresh4 as core::ffi::c_uint).wrapping_add(
                    t3 >> 8 as core::ffi::c_int
                        | ((1 as core::ffi::c_int) << 24 as core::ffi::c_int) as core::ffi::c_uint,
                ) as uint32_t as uint32_t;
            }
            _ => {
                if len == 0 {
                    return;
                }
                j = 0 as core::ffi::c_int as size_t;
                while j < len {
                    mp[j as usize] = *in_0.offset(j as isize);
                    j = j.wrapping_add(1);
                }
                let fresh6 = j;
                j = j.wrapping_add(1);
                mp[fresh6 as usize] = 1 as core::ffi::c_int as uint8_t;
                while j < 16 as core::ffi::c_int as core::ffi::c_uint {
                    mp[j as usize] = 0 as core::ffi::c_int as uint8_t;
                    j = j.wrapping_add(1);
                }
                len = 0 as core::ffi::c_int as size_t;
                t0 = CRYPTO_load_u32_le(mp.as_mut_ptr().offset(0 as core::ffi::c_int as isize)
                    as *const core::ffi::c_void);
                t1 = CRYPTO_load_u32_le(mp.as_mut_ptr().offset(4 as core::ffi::c_int as isize)
                    as *const core::ffi::c_void);
                t2 = CRYPTO_load_u32_le(mp.as_mut_ptr().offset(8 as core::ffi::c_int as isize)
                    as *const core::ffi::c_void);
                t3 = CRYPTO_load_u32_le(mp.as_mut_ptr().offset(12 as core::ffi::c_int as isize)
                    as *const core::ffi::c_void);
                let ref mut fresh7 = (*state).h0;
                *fresh7 = (*fresh7 as core::ffi::c_uint)
                    .wrapping_add(t0 & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint)
                    as uint32_t as uint32_t;
                let ref mut fresh8 = (*state).h1;
                *fresh8 = (*fresh8 as u64).wrapping_add(
                    ((t1 as uint64_t) << 32 as core::ffi::c_int | t0 as u64)
                        >> 26 as core::ffi::c_int
                        & 0x3ffffff as core::ffi::c_int as u64,
                ) as uint32_t as uint32_t;
                let ref mut fresh9 = (*state).h2;
                *fresh9 = (*fresh9 as u64).wrapping_add(
                    ((t2 as uint64_t) << 32 as core::ffi::c_int | t1 as u64)
                        >> 20 as core::ffi::c_int
                        & 0x3ffffff as core::ffi::c_int as u64,
                ) as uint32_t as uint32_t;
                let ref mut fresh10 = (*state).h3;
                *fresh10 = (*fresh10 as u64).wrapping_add(
                    ((t3 as uint64_t) << 32 as core::ffi::c_int | t2 as u64)
                        >> 14 as core::ffi::c_int
                        & 0x3ffffff as core::ffi::c_int as u64,
                ) as uint32_t as uint32_t;
                let ref mut fresh11 = (*state).h4;
                *fresh11 = (*fresh11 as core::ffi::c_uint).wrapping_add(t3 >> 8 as core::ffi::c_int)
                    as uint32_t as uint32_t;
            }
        }
        t[0 as core::ffi::c_int as usize] = (mul32x32_64((*state).h0, (*state).r0))
            .wrapping_add(mul32x32_64((*state).h1, (*state).s4))
            .wrapping_add(mul32x32_64((*state).h2, (*state).s3))
            .wrapping_add(mul32x32_64((*state).h3, (*state).s2))
            .wrapping_add(mul32x32_64((*state).h4, (*state).s1));
        t[1 as core::ffi::c_int as usize] = (mul32x32_64((*state).h0, (*state).r1))
            .wrapping_add(mul32x32_64((*state).h1, (*state).r0))
            .wrapping_add(mul32x32_64((*state).h2, (*state).s4))
            .wrapping_add(mul32x32_64((*state).h3, (*state).s3))
            .wrapping_add(mul32x32_64((*state).h4, (*state).s2));
        t[2 as core::ffi::c_int as usize] = (mul32x32_64((*state).h0, (*state).r2))
            .wrapping_add(mul32x32_64((*state).h1, (*state).r1))
            .wrapping_add(mul32x32_64((*state).h2, (*state).r0))
            .wrapping_add(mul32x32_64((*state).h3, (*state).s4))
            .wrapping_add(mul32x32_64((*state).h4, (*state).s3));
        t[3 as core::ffi::c_int as usize] = (mul32x32_64((*state).h0, (*state).r3))
            .wrapping_add(mul32x32_64((*state).h1, (*state).r2))
            .wrapping_add(mul32x32_64((*state).h2, (*state).r1))
            .wrapping_add(mul32x32_64((*state).h3, (*state).r0))
            .wrapping_add(mul32x32_64((*state).h4, (*state).s4));
        t[4 as core::ffi::c_int as usize] = (mul32x32_64((*state).h0, (*state).r4))
            .wrapping_add(mul32x32_64((*state).h1, (*state).r3))
            .wrapping_add(mul32x32_64((*state).h2, (*state).r2))
            .wrapping_add(mul32x32_64((*state).h3, (*state).r1))
            .wrapping_add(mul32x32_64((*state).h4, (*state).r0));
        (*state).h0 = t[0 as core::ffi::c_int as usize] as uint32_t
            & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
        c = t[0 as core::ffi::c_int as usize] >> 26 as core::ffi::c_int;
        t[1 as core::ffi::c_int as usize] =
            (t[1 as core::ffi::c_int as usize] as u64).wrapping_add(c) as uint64_t as uint64_t;
        (*state).h1 = t[1 as core::ffi::c_int as usize] as uint32_t
            & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
        b = (t[1 as core::ffi::c_int as usize] >> 26 as core::ffi::c_int) as uint32_t;
        t[2 as core::ffi::c_int as usize] = (t[2 as core::ffi::c_int as usize] as u64)
            .wrapping_add(b as u64) as uint64_t
            as uint64_t;
        (*state).h2 = t[2 as core::ffi::c_int as usize] as uint32_t
            & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
        b = (t[2 as core::ffi::c_int as usize] >> 26 as core::ffi::c_int) as uint32_t;
        t[3 as core::ffi::c_int as usize] = (t[3 as core::ffi::c_int as usize] as u64)
            .wrapping_add(b as u64) as uint64_t
            as uint64_t;
        (*state).h3 = t[3 as core::ffi::c_int as usize] as uint32_t
            & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
        b = (t[3 as core::ffi::c_int as usize] >> 26 as core::ffi::c_int) as uint32_t;
        t[4 as core::ffi::c_int as usize] = (t[4 as core::ffi::c_int as usize] as u64)
            .wrapping_add(b as u64) as uint64_t
            as uint64_t;
        (*state).h4 = t[4 as core::ffi::c_int as usize] as uint32_t
            & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
        b = (t[4 as core::ffi::c_int as usize] >> 26 as core::ffi::c_int) as uint32_t;
        let ref mut fresh5 = (*state).h0;
        *fresh5 = (*fresh5 as core::ffi::c_uint)
            .wrapping_add(b.wrapping_mul(5 as core::ffi::c_int as core::ffi::c_uint))
            as uint32_t as uint32_t;
        if len >= 16 as core::ffi::c_int as core::ffi::c_uint {
            current_block = 17160205090870801376;
        } else {
            current_block = 13995579333348105930;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_poly1305_init(
    mut statep: *mut poly1305_state,
    mut key: *const uint8_t,
) {
    let mut state: *mut poly1305_state_st = poly1305_aligned_state(statep);
    let mut t0: uint32_t = 0;
    let mut t1: uint32_t = 0;
    let mut t2: uint32_t = 0;
    let mut t3: uint32_t = 0;
    t0 = CRYPTO_load_u32_le(key.offset(0 as core::ffi::c_int as isize) as *const core::ffi::c_void);
    t1 = CRYPTO_load_u32_le(key.offset(4 as core::ffi::c_int as isize) as *const core::ffi::c_void);
    t2 = CRYPTO_load_u32_le(key.offset(8 as core::ffi::c_int as isize) as *const core::ffi::c_void);
    t3 =
        CRYPTO_load_u32_le(key.offset(12 as core::ffi::c_int as isize) as *const core::ffi::c_void);
    (*state).r0 = t0 & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    t0 >>= 26 as core::ffi::c_int;
    t0 |= t1 << 6 as core::ffi::c_int;
    (*state).r1 = t0 & 0x3ffff03 as core::ffi::c_int as core::ffi::c_uint;
    t1 >>= 20 as core::ffi::c_int;
    t1 |= t2 << 12 as core::ffi::c_int;
    (*state).r2 = t1 & 0x3ffc0ff as core::ffi::c_int as core::ffi::c_uint;
    t2 >>= 14 as core::ffi::c_int;
    t2 |= t3 << 18 as core::ffi::c_int;
    (*state).r3 = t2 & 0x3f03fff as core::ffi::c_int as core::ffi::c_uint;
    t3 >>= 8 as core::ffi::c_int;
    (*state).r4 = t3 & 0xfffff as core::ffi::c_int as core::ffi::c_uint;
    (*state).s1 = ((*state).r1).wrapping_mul(5 as core::ffi::c_int as core::ffi::c_uint);
    (*state).s2 = ((*state).r2).wrapping_mul(5 as core::ffi::c_int as core::ffi::c_uint);
    (*state).s3 = ((*state).r3).wrapping_mul(5 as core::ffi::c_int as core::ffi::c_uint);
    (*state).s4 = ((*state).r4).wrapping_mul(5 as core::ffi::c_int as core::ffi::c_uint);
    (*state).h0 = 0 as core::ffi::c_int as uint32_t;
    (*state).h1 = 0 as core::ffi::c_int as uint32_t;
    (*state).h2 = 0 as core::ffi::c_int as uint32_t;
    (*state).h3 = 0 as core::ffi::c_int as uint32_t;
    (*state).h4 = 0 as core::ffi::c_int as uint32_t;
    (*state).buf_used = 0 as core::ffi::c_int as size_t;
    OPENSSL_memcpy(
        ((*state).key).as_mut_ptr() as *mut core::ffi::c_void,
        key.offset(16 as core::ffi::c_int as isize) as *const core::ffi::c_void,
        core::mem::size_of::<[uint8_t; 16]>() as u32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_poly1305_update(
    mut statep: *mut poly1305_state,
    mut in_0: *const uint8_t,
    mut in_len: size_t,
) {
    let mut state: *mut poly1305_state_st = poly1305_aligned_state(statep);
    if in_len == 0 as core::ffi::c_int as core::ffi::c_uint {
        return;
    }
    if (*state).buf_used != 0 {
        let mut todo: size_t =
            (16 as core::ffi::c_int as core::ffi::c_uint).wrapping_sub((*state).buf_used);
        if todo > in_len {
            todo = in_len;
        }
        let mut i: size_t = 0 as core::ffi::c_int as size_t;
        while i < todo {
            (*state).buf[((*state).buf_used).wrapping_add(i) as usize] = *in_0.offset(i as isize);
            i = i.wrapping_add(1);
        }
        let ref mut fresh12 = (*state).buf_used;
        *fresh12 = (*fresh12 as core::ffi::c_uint).wrapping_add(todo) as size_t as size_t;
        in_len = (in_len as core::ffi::c_uint).wrapping_sub(todo) as size_t as size_t;
        in_0 = in_0.offset(todo as isize);
        if (*state).buf_used == 16 as core::ffi::c_int as core::ffi::c_uint {
            poly1305_update(
                state,
                ((*state).buf).as_mut_ptr(),
                16 as core::ffi::c_int as size_t,
            );
            (*state).buf_used = 0 as core::ffi::c_int as size_t;
        }
    }
    if in_len >= 16 as core::ffi::c_int as core::ffi::c_uint {
        let mut todo_0: size_t = in_len & !(0xf as core::ffi::c_int) as core::ffi::c_uint;
        poly1305_update(state, in_0, todo_0);
        in_0 = in_0.offset(todo_0 as isize);
        in_len &= 0xf as core::ffi::c_int as core::ffi::c_uint;
    }
    if in_len != 0 {
        let mut i_0: size_t = 0 as core::ffi::c_int as size_t;
        while i_0 < in_len {
            (*state).buf[i_0 as usize] = *in_0.offset(i_0 as isize);
            i_0 = i_0.wrapping_add(1);
        }
        (*state).buf_used = in_len;
    }
}
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_poly1305_finish(
    mut statep: *mut poly1305_state,
    mut mac: *mut uint8_t,
) {
    let mut state: *mut poly1305_state_st = poly1305_aligned_state(statep);
    let mut g0: uint32_t = 0;
    let mut g1: uint32_t = 0;
    let mut g2: uint32_t = 0;
    let mut g3: uint32_t = 0;
    let mut g4: uint32_t = 0;
    let mut b: uint32_t = 0;
    let mut nb: uint32_t = 0;
    if (*state).buf_used != 0 {
        poly1305_update(state, ((*state).buf).as_mut_ptr(), (*state).buf_used);
    }
    b = (*state).h0 >> 26 as core::ffi::c_int;
    (*state).h0 = (*state).h0 & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    let ref mut fresh13 = (*state).h1;
    *fresh13 = (*fresh13 as core::ffi::c_uint).wrapping_add(b) as uint32_t as uint32_t;
    b = (*state).h1 >> 26 as core::ffi::c_int;
    (*state).h1 = (*state).h1 & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    let ref mut fresh14 = (*state).h2;
    *fresh14 = (*fresh14 as core::ffi::c_uint).wrapping_add(b) as uint32_t as uint32_t;
    b = (*state).h2 >> 26 as core::ffi::c_int;
    (*state).h2 = (*state).h2 & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    let ref mut fresh15 = (*state).h3;
    *fresh15 = (*fresh15 as core::ffi::c_uint).wrapping_add(b) as uint32_t as uint32_t;
    b = (*state).h3 >> 26 as core::ffi::c_int;
    (*state).h3 = (*state).h3 & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    let ref mut fresh16 = (*state).h4;
    *fresh16 = (*fresh16 as core::ffi::c_uint).wrapping_add(b) as uint32_t as uint32_t;
    b = (*state).h4 >> 26 as core::ffi::c_int;
    (*state).h4 = (*state).h4 & 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    let ref mut fresh17 = (*state).h0;
    *fresh17 = (*fresh17 as core::ffi::c_uint)
        .wrapping_add(b.wrapping_mul(5 as core::ffi::c_int as core::ffi::c_uint))
        as uint32_t as uint32_t;
    g0 = ((*state).h0).wrapping_add(5 as core::ffi::c_int as core::ffi::c_uint);
    b = g0 >> 26 as core::ffi::c_int;
    g0 &= 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    g1 = ((*state).h1).wrapping_add(b);
    b = g1 >> 26 as core::ffi::c_int;
    g1 &= 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    g2 = ((*state).h2).wrapping_add(b);
    b = g2 >> 26 as core::ffi::c_int;
    g2 &= 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    g3 = ((*state).h3).wrapping_add(b);
    b = g3 >> 26 as core::ffi::c_int;
    g3 &= 0x3ffffff as core::ffi::c_int as core::ffi::c_uint;
    g4 = ((*state).h4)
        .wrapping_add(b)
        .wrapping_sub(((1 as core::ffi::c_int) << 26 as core::ffi::c_int) as core::ffi::c_uint);
    b = (g4 >> 31 as core::ffi::c_int).wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint);
    nb = !b;
    (*state).h0 = (*state).h0 & nb | g0 & b;
    (*state).h1 = (*state).h1 & nb | g1 & b;
    (*state).h2 = (*state).h2 & nb | g2 & b;
    (*state).h3 = (*state).h3 & nb | g3 & b;
    (*state).h4 = (*state).h4 & nb | g4 & b;
    let mut f0: uint64_t = (((*state).h0 | (*state).h1 << 26 as core::ffi::c_int) as u64)
        .wrapping_add(CRYPTO_load_u32_le(
            &mut *((*state).key)
                .as_mut_ptr()
                .offset(0 as core::ffi::c_int as isize) as *mut uint8_t
                as *const core::ffi::c_void,
        ) as uint64_t);
    let mut f1: uint64_t = (((*state).h1 >> 6 as core::ffi::c_int
        | (*state).h2 << 20 as core::ffi::c_int) as u64)
        .wrapping_add(CRYPTO_load_u32_le(
            &mut *((*state).key)
                .as_mut_ptr()
                .offset(4 as core::ffi::c_int as isize) as *mut uint8_t
                as *const core::ffi::c_void,
        ) as uint64_t);
    let mut f2: uint64_t = (((*state).h2 >> 12 as core::ffi::c_int
        | (*state).h3 << 14 as core::ffi::c_int) as u64)
        .wrapping_add(CRYPTO_load_u32_le(
            &mut *((*state).key)
                .as_mut_ptr()
                .offset(8 as core::ffi::c_int as isize) as *mut uint8_t
                as *const core::ffi::c_void,
        ) as uint64_t);
    let mut f3: uint64_t = (((*state).h3 >> 18 as core::ffi::c_int
        | (*state).h4 << 8 as core::ffi::c_int) as u64)
        .wrapping_add(CRYPTO_load_u32_le(
            &mut *((*state).key)
                .as_mut_ptr()
                .offset(12 as core::ffi::c_int as isize) as *mut uint8_t
                as *const core::ffi::c_void,
        ) as uint64_t);
    CRYPTO_store_u32_le(
        &mut *mac.offset(0 as core::ffi::c_int as isize) as *mut uint8_t as *mut core::ffi::c_void,
        f0 as uint32_t,
    );
    f1 = (f1 as u64).wrapping_add(f0 >> 32 as core::ffi::c_int) as uint64_t as uint64_t;
    CRYPTO_store_u32_le(
        &mut *mac.offset(4 as core::ffi::c_int as isize) as *mut uint8_t as *mut core::ffi::c_void,
        f1 as uint32_t,
    );
    f2 = (f2 as u64).wrapping_add(f1 >> 32 as core::ffi::c_int) as uint64_t as uint64_t;
    CRYPTO_store_u32_le(
        &mut *mac.offset(8 as core::ffi::c_int as isize) as *mut uint8_t as *mut core::ffi::c_void,
        f2 as uint32_t,
    );
    f3 = (f3 as u64).wrapping_add(f2 >> 32 as core::ffi::c_int) as uint64_t as uint64_t;
    CRYPTO_store_u32_le(
        &mut *mac.offset(12 as core::ffi::c_int as isize) as *mut uint8_t as *mut core::ffi::c_void,
        f3 as uint32_t,
    );
}

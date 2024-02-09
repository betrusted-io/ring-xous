#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern "C" {
    fn CRYPTO_memcmp(
        a: *const core::ffi::c_void,
        b: *const core::ffi::c_void,
        len: size_t,
    ) -> core::ffi::c_int;
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
}
pub type size_t = core::ffi::c_uint;
pub type __uint8_t = core::ffi::c_uchar;
pub type __int32_t = core::ffi::c_int;
pub type __uint32_t = core::ffi::c_uint;
pub type __int64_t = i64;
pub type __uint64_t = u64;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type crypto_word_t = uint32_t;
pub type fe_limb_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fe {
    pub v: [fe_limb_t; 10],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fe_loose {
    pub v: [fe_limb_t; 10],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_p2 {
    pub X: fe,
    pub Y: fe,
    pub Z: fe,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_p3 {
    pub X: fe,
    pub Y: fe,
    pub Z: fe,
    pub T: fe,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_p1p1 {
    pub X: fe_loose,
    pub Y: fe_loose,
    pub Z: fe_loose,
    pub T: fe_loose,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_precomp {
    pub yplusx: fe_loose,
    pub yminusx: fe_loose,
    pub xy2d: fe_loose,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ge_cached {
    pub YplusX: fe_loose,
    pub YminusX: fe_loose,
    pub Z: fe_loose,
    pub T2d: fe_loose,
}
pub type fiat_25519_uint1 = core::ffi::c_uchar;
pub type fiat_25519_int1 = core::ffi::c_schar;
#[inline]
unsafe extern "C" fn constant_time_eq_w(
    mut a: crypto_word_t,
    mut b: crypto_word_t,
) -> crypto_word_t {
    return constant_time_is_zero_w(a ^ b);
}
#[inline]
unsafe extern "C" fn constant_time_is_zero_w(mut a: crypto_word_t) -> crypto_word_t {
    return constant_time_msb_w(!a & a.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint));
}
#[inline]
unsafe extern "C" fn constant_time_msb_w(mut a: crypto_word_t) -> crypto_word_t {
    return (0 as core::ffi::c_uint).wrapping_sub(
        a >> (core::mem::size_of::<crypto_word_t>() as u32)
            .wrapping_mul(8 as core::ffi::c_int as core::ffi::c_uint)
            .wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint),
    );
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
#[inline]
unsafe extern "C" fn OPENSSL_memset(
    mut dst: *mut core::ffi::c_void,
    mut c: core::ffi::c_int,
    mut n: size_t,
) -> *mut core::ffi::c_void {
    if n == 0 as core::ffi::c_int as core::ffi::c_uint {
        return dst;
    }
    return memset(dst, c, n);
}
#[inline]
unsafe extern "C" fn fe_limbs_copy(mut r: *mut fe_limb_t, mut a: *const fe_limb_t) {
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < 10 as core::ffi::c_int as core::ffi::c_uint {
        *r.offset(i as isize) = *a.offset(i as isize);
        i = i.wrapping_add(1);
    }
}
static mut d: fe = {
    let mut init = fe {
        v: [
            56195235 as core::ffi::c_int as fe_limb_t,
            13857412 as core::ffi::c_int as fe_limb_t,
            51736253 as core::ffi::c_int as fe_limb_t,
            6949390 as core::ffi::c_int as fe_limb_t,
            114729 as core::ffi::c_int as fe_limb_t,
            24766616 as core::ffi::c_int as fe_limb_t,
            60832955 as core::ffi::c_int as fe_limb_t,
            30306712 as core::ffi::c_int as fe_limb_t,
            48412415 as core::ffi::c_int as fe_limb_t,
            21499315 as core::ffi::c_int as fe_limb_t,
        ],
    };
    init
};
static mut sqrtm1: fe = {
    let mut init = fe {
        v: [
            34513072 as core::ffi::c_int as fe_limb_t,
            25610706 as core::ffi::c_int as fe_limb_t,
            9377949 as core::ffi::c_int as fe_limb_t,
            3500415 as core::ffi::c_int as fe_limb_t,
            12389472 as core::ffi::c_int as fe_limb_t,
            33281959 as core::ffi::c_int as fe_limb_t,
            41962654 as core::ffi::c_int as fe_limb_t,
            31548777 as core::ffi::c_int as fe_limb_t,
            326685 as core::ffi::c_int as fe_limb_t,
            11406482 as core::ffi::c_int as fe_limb_t,
        ],
    };
    init
};
static mut d2: fe = {
    let mut init = fe {
        v: [
            45281625 as core::ffi::c_int as fe_limb_t,
            27714825 as core::ffi::c_int as fe_limb_t,
            36363642 as core::ffi::c_int as fe_limb_t,
            13898781 as core::ffi::c_int as fe_limb_t,
            229458 as core::ffi::c_int as fe_limb_t,
            15978800 as core::ffi::c_int as fe_limb_t,
            54557047 as core::ffi::c_int as fe_limb_t,
            27058993 as core::ffi::c_int as fe_limb_t,
            29715967 as core::ffi::c_int as fe_limb_t,
            9444199 as core::ffi::c_int as fe_limb_t,
        ],
    };
    init
};
static mut k25519SmallPrecomp: [uint8_t; 960] = [
    0x1a as core::ffi::c_int as uint8_t,
    0xd5 as core::ffi::c_int as uint8_t,
    0x25 as core::ffi::c_int as uint8_t,
    0x8f as core::ffi::c_int as uint8_t,
    0x60 as core::ffi::c_int as uint8_t,
    0x2d as core::ffi::c_int as uint8_t,
    0x56 as core::ffi::c_int as uint8_t,
    0xc9 as core::ffi::c_int as uint8_t,
    0xb2 as core::ffi::c_int as uint8_t,
    0xa7 as core::ffi::c_int as uint8_t,
    0x25 as core::ffi::c_int as uint8_t,
    0x95 as core::ffi::c_int as uint8_t,
    0x60 as core::ffi::c_int as uint8_t,
    0xc7 as core::ffi::c_int as uint8_t,
    0x2c as core::ffi::c_int as uint8_t,
    0x69 as core::ffi::c_int as uint8_t,
    0x5c as core::ffi::c_int as uint8_t,
    0xdc as core::ffi::c_int as uint8_t,
    0xd6 as core::ffi::c_int as uint8_t,
    0xfd as core::ffi::c_int as uint8_t,
    0x31 as core::ffi::c_int as uint8_t,
    0xe2 as core::ffi::c_int as uint8_t,
    0xa4 as core::ffi::c_int as uint8_t,
    0xc0 as core::ffi::c_int as uint8_t,
    0xfe as core::ffi::c_int as uint8_t,
    0x53 as core::ffi::c_int as uint8_t,
    0x6e as core::ffi::c_int as uint8_t,
    0xcd as core::ffi::c_int as uint8_t,
    0xd3 as core::ffi::c_int as uint8_t,
    0x36 as core::ffi::c_int as uint8_t,
    0x69 as core::ffi::c_int as uint8_t,
    0x21 as core::ffi::c_int as uint8_t,
    0x58 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x2 as core::ffi::c_int as uint8_t,
    0xa2 as core::ffi::c_int as uint8_t,
    0xed as core::ffi::c_int as uint8_t,
    0xf4 as core::ffi::c_int as uint8_t,
    0x8f as core::ffi::c_int as uint8_t,
    0x6b as core::ffi::c_int as uint8_t,
    0xb as core::ffi::c_int as uint8_t,
    0x3e as core::ffi::c_int as uint8_t,
    0xeb as core::ffi::c_int as uint8_t,
    0x35 as core::ffi::c_int as uint8_t,
    0x1a as core::ffi::c_int as uint8_t,
    0xd5 as core::ffi::c_int as uint8_t,
    0x7e as core::ffi::c_int as uint8_t,
    0xdb as core::ffi::c_int as uint8_t,
    0x78 as core::ffi::c_int as uint8_t,
    0 as core::ffi::c_int as uint8_t,
    0x96 as core::ffi::c_int as uint8_t,
    0x8a as core::ffi::c_int as uint8_t,
    0xa0 as core::ffi::c_int as uint8_t,
    0xb4 as core::ffi::c_int as uint8_t,
    0xcf as core::ffi::c_int as uint8_t,
    0x60 as core::ffi::c_int as uint8_t,
    0x4b as core::ffi::c_int as uint8_t,
    0xd4 as core::ffi::c_int as uint8_t,
    0xd5 as core::ffi::c_int as uint8_t,
    0xf9 as core::ffi::c_int as uint8_t,
    0x2d as core::ffi::c_int as uint8_t,
    0xbf as core::ffi::c_int as uint8_t,
    0x88 as core::ffi::c_int as uint8_t,
    0xbd as core::ffi::c_int as uint8_t,
    0x22 as core::ffi::c_int as uint8_t,
    0x62 as core::ffi::c_int as uint8_t,
    0x13 as core::ffi::c_int as uint8_t,
    0x53 as core::ffi::c_int as uint8_t,
    0xe4 as core::ffi::c_int as uint8_t,
    0x82 as core::ffi::c_int as uint8_t,
    0x57 as core::ffi::c_int as uint8_t,
    0xfa as core::ffi::c_int as uint8_t,
    0x1e as core::ffi::c_int as uint8_t,
    0x8f as core::ffi::c_int as uint8_t,
    0x6 as core::ffi::c_int as uint8_t,
    0x2b as core::ffi::c_int as uint8_t,
    0x90 as core::ffi::c_int as uint8_t,
    0xba as core::ffi::c_int as uint8_t,
    0x8 as core::ffi::c_int as uint8_t,
    0xb6 as core::ffi::c_int as uint8_t,
    0x10 as core::ffi::c_int as uint8_t,
    0x54 as core::ffi::c_int as uint8_t,
    0x4f as core::ffi::c_int as uint8_t,
    0x7c as core::ffi::c_int as uint8_t,
    0x1b as core::ffi::c_int as uint8_t,
    0x26 as core::ffi::c_int as uint8_t,
    0xed as core::ffi::c_int as uint8_t,
    0xda as core::ffi::c_int as uint8_t,
    0x6b as core::ffi::c_int as uint8_t,
    0xdd as core::ffi::c_int as uint8_t,
    0x25 as core::ffi::c_int as uint8_t,
    0xd0 as core::ffi::c_int as uint8_t,
    0x4e as core::ffi::c_int as uint8_t,
    0xea as core::ffi::c_int as uint8_t,
    0x42 as core::ffi::c_int as uint8_t,
    0xbb as core::ffi::c_int as uint8_t,
    0x25 as core::ffi::c_int as uint8_t,
    0x3 as core::ffi::c_int as uint8_t,
    0xa2 as core::ffi::c_int as uint8_t,
    0xfb as core::ffi::c_int as uint8_t,
    0xcc as core::ffi::c_int as uint8_t,
    0x61 as core::ffi::c_int as uint8_t,
    0x67 as core::ffi::c_int as uint8_t,
    0x6 as core::ffi::c_int as uint8_t,
    0x70 as core::ffi::c_int as uint8_t,
    0x1a as core::ffi::c_int as uint8_t,
    0xc4 as core::ffi::c_int as uint8_t,
    0x78 as core::ffi::c_int as uint8_t,
    0x3a as core::ffi::c_int as uint8_t,
    0xff as core::ffi::c_int as uint8_t,
    0x32 as core::ffi::c_int as uint8_t,
    0x62 as core::ffi::c_int as uint8_t,
    0xdd as core::ffi::c_int as uint8_t,
    0x2c as core::ffi::c_int as uint8_t,
    0xab as core::ffi::c_int as uint8_t,
    0x50 as core::ffi::c_int as uint8_t,
    0x19 as core::ffi::c_int as uint8_t,
    0x3b as core::ffi::c_int as uint8_t,
    0xf2 as core::ffi::c_int as uint8_t,
    0x9b as core::ffi::c_int as uint8_t,
    0x7d as core::ffi::c_int as uint8_t,
    0xb8 as core::ffi::c_int as uint8_t,
    0xfd as core::ffi::c_int as uint8_t,
    0x4f as core::ffi::c_int as uint8_t,
    0x29 as core::ffi::c_int as uint8_t,
    0x9c as core::ffi::c_int as uint8_t,
    0xa7 as core::ffi::c_int as uint8_t,
    0x91 as core::ffi::c_int as uint8_t,
    0xba as core::ffi::c_int as uint8_t,
    0xe as core::ffi::c_int as uint8_t,
    0x46 as core::ffi::c_int as uint8_t,
    0x5e as core::ffi::c_int as uint8_t,
    0x51 as core::ffi::c_int as uint8_t,
    0xfe as core::ffi::c_int as uint8_t,
    0x1d as core::ffi::c_int as uint8_t,
    0xbf as core::ffi::c_int as uint8_t,
    0xe5 as core::ffi::c_int as uint8_t,
    0xe5 as core::ffi::c_int as uint8_t,
    0x9b as core::ffi::c_int as uint8_t,
    0x95 as core::ffi::c_int as uint8_t,
    0xd as core::ffi::c_int as uint8_t,
    0x67 as core::ffi::c_int as uint8_t,
    0xf8 as core::ffi::c_int as uint8_t,
    0xd1 as core::ffi::c_int as uint8_t,
    0xb5 as core::ffi::c_int as uint8_t,
    0x5a as core::ffi::c_int as uint8_t,
    0xa1 as core::ffi::c_int as uint8_t,
    0x93 as core::ffi::c_int as uint8_t,
    0x2c as core::ffi::c_int as uint8_t,
    0xc3 as core::ffi::c_int as uint8_t,
    0xde as core::ffi::c_int as uint8_t,
    0xe as core::ffi::c_int as uint8_t,
    0x97 as core::ffi::c_int as uint8_t,
    0x85 as core::ffi::c_int as uint8_t,
    0x2d as core::ffi::c_int as uint8_t,
    0x7f as core::ffi::c_int as uint8_t,
    0xea as core::ffi::c_int as uint8_t,
    0xab as core::ffi::c_int as uint8_t,
    0x3e as core::ffi::c_int as uint8_t,
    0x47 as core::ffi::c_int as uint8_t,
    0x30 as core::ffi::c_int as uint8_t,
    0x18 as core::ffi::c_int as uint8_t,
    0x24 as core::ffi::c_int as uint8_t,
    0xe8 as core::ffi::c_int as uint8_t,
    0xb7 as core::ffi::c_int as uint8_t,
    0x60 as core::ffi::c_int as uint8_t,
    0xae as core::ffi::c_int as uint8_t,
    0x47 as core::ffi::c_int as uint8_t,
    0x80 as core::ffi::c_int as uint8_t,
    0xfc as core::ffi::c_int as uint8_t,
    0xe5 as core::ffi::c_int as uint8_t,
    0x23 as core::ffi::c_int as uint8_t,
    0xe7 as core::ffi::c_int as uint8_t,
    0xc2 as core::ffi::c_int as uint8_t,
    0xc9 as core::ffi::c_int as uint8_t,
    0x85 as core::ffi::c_int as uint8_t,
    0xe6 as core::ffi::c_int as uint8_t,
    0x98 as core::ffi::c_int as uint8_t,
    0xa0 as core::ffi::c_int as uint8_t,
    0x29 as core::ffi::c_int as uint8_t,
    0x4e as core::ffi::c_int as uint8_t,
    0xe1 as core::ffi::c_int as uint8_t,
    0x84 as core::ffi::c_int as uint8_t,
    0x39 as core::ffi::c_int as uint8_t,
    0x2d as core::ffi::c_int as uint8_t,
    0x95 as core::ffi::c_int as uint8_t,
    0x2c as core::ffi::c_int as uint8_t,
    0xf3 as core::ffi::c_int as uint8_t,
    0x45 as core::ffi::c_int as uint8_t,
    0x3c as core::ffi::c_int as uint8_t,
    0xff as core::ffi::c_int as uint8_t,
    0xaf as core::ffi::c_int as uint8_t,
    0x27 as core::ffi::c_int as uint8_t,
    0x4c as core::ffi::c_int as uint8_t,
    0x6b as core::ffi::c_int as uint8_t,
    0xa6 as core::ffi::c_int as uint8_t,
    0xf5 as core::ffi::c_int as uint8_t,
    0x4b as core::ffi::c_int as uint8_t,
    0x11 as core::ffi::c_int as uint8_t,
    0xbd as core::ffi::c_int as uint8_t,
    0xba as core::ffi::c_int as uint8_t,
    0x5b as core::ffi::c_int as uint8_t,
    0x9e as core::ffi::c_int as uint8_t,
    0xc4 as core::ffi::c_int as uint8_t,
    0xa4 as core::ffi::c_int as uint8_t,
    0x51 as core::ffi::c_int as uint8_t,
    0x1e as core::ffi::c_int as uint8_t,
    0xbe as core::ffi::c_int as uint8_t,
    0xd0 as core::ffi::c_int as uint8_t,
    0x90 as core::ffi::c_int as uint8_t,
    0x3a as core::ffi::c_int as uint8_t,
    0x9c as core::ffi::c_int as uint8_t,
    0xc2 as core::ffi::c_int as uint8_t,
    0x26 as core::ffi::c_int as uint8_t,
    0xb6 as core::ffi::c_int as uint8_t,
    0x1e as core::ffi::c_int as uint8_t,
    0xf1 as core::ffi::c_int as uint8_t,
    0x95 as core::ffi::c_int as uint8_t,
    0x7d as core::ffi::c_int as uint8_t,
    0xc8 as core::ffi::c_int as uint8_t,
    0x6d as core::ffi::c_int as uint8_t,
    0x52 as core::ffi::c_int as uint8_t,
    0xe6 as core::ffi::c_int as uint8_t,
    0x99 as core::ffi::c_int as uint8_t,
    0x2c as core::ffi::c_int as uint8_t,
    0x5f as core::ffi::c_int as uint8_t,
    0x9a as core::ffi::c_int as uint8_t,
    0x96 as core::ffi::c_int as uint8_t,
    0xc as core::ffi::c_int as uint8_t,
    0x68 as core::ffi::c_int as uint8_t,
    0x29 as core::ffi::c_int as uint8_t,
    0xfd as core::ffi::c_int as uint8_t,
    0xe2 as core::ffi::c_int as uint8_t,
    0xfb as core::ffi::c_int as uint8_t,
    0xe6 as core::ffi::c_int as uint8_t,
    0xbc as core::ffi::c_int as uint8_t,
    0xec as core::ffi::c_int as uint8_t,
    0x31 as core::ffi::c_int as uint8_t,
    0x8 as core::ffi::c_int as uint8_t,
    0xec as core::ffi::c_int as uint8_t,
    0xe6 as core::ffi::c_int as uint8_t,
    0xb0 as core::ffi::c_int as uint8_t,
    0x53 as core::ffi::c_int as uint8_t,
    0x60 as core::ffi::c_int as uint8_t,
    0xc3 as core::ffi::c_int as uint8_t,
    0x8c as core::ffi::c_int as uint8_t,
    0xbe as core::ffi::c_int as uint8_t,
    0xc1 as core::ffi::c_int as uint8_t,
    0xb3 as core::ffi::c_int as uint8_t,
    0x8a as core::ffi::c_int as uint8_t,
    0x8f as core::ffi::c_int as uint8_t,
    0xe4 as core::ffi::c_int as uint8_t,
    0x88 as core::ffi::c_int as uint8_t,
    0x2b as core::ffi::c_int as uint8_t,
    0x55 as core::ffi::c_int as uint8_t,
    0xe5 as core::ffi::c_int as uint8_t,
    0x64 as core::ffi::c_int as uint8_t,
    0x6e as core::ffi::c_int as uint8_t,
    0x9b as core::ffi::c_int as uint8_t,
    0xd0 as core::ffi::c_int as uint8_t,
    0xaf as core::ffi::c_int as uint8_t,
    0x7b as core::ffi::c_int as uint8_t,
    0x64 as core::ffi::c_int as uint8_t,
    0x2a as core::ffi::c_int as uint8_t,
    0x35 as core::ffi::c_int as uint8_t,
    0x25 as core::ffi::c_int as uint8_t,
    0x10 as core::ffi::c_int as uint8_t,
    0x52 as core::ffi::c_int as uint8_t,
    0xc5 as core::ffi::c_int as uint8_t,
    0x9e as core::ffi::c_int as uint8_t,
    0x58 as core::ffi::c_int as uint8_t,
    0x11 as core::ffi::c_int as uint8_t,
    0x39 as core::ffi::c_int as uint8_t,
    0x36 as core::ffi::c_int as uint8_t,
    0x45 as core::ffi::c_int as uint8_t,
    0x51 as core::ffi::c_int as uint8_t,
    0xb8 as core::ffi::c_int as uint8_t,
    0x39 as core::ffi::c_int as uint8_t,
    0x93 as core::ffi::c_int as uint8_t,
    0xfc as core::ffi::c_int as uint8_t,
    0x9d as core::ffi::c_int as uint8_t,
    0x6a as core::ffi::c_int as uint8_t,
    0xbe as core::ffi::c_int as uint8_t,
    0x58 as core::ffi::c_int as uint8_t,
    0xcb as core::ffi::c_int as uint8_t,
    0xa4 as core::ffi::c_int as uint8_t,
    0xf as core::ffi::c_int as uint8_t,
    0x51 as core::ffi::c_int as uint8_t,
    0x3c as core::ffi::c_int as uint8_t,
    0x38 as core::ffi::c_int as uint8_t,
    0x5 as core::ffi::c_int as uint8_t,
    0xca as core::ffi::c_int as uint8_t,
    0xab as core::ffi::c_int as uint8_t,
    0x43 as core::ffi::c_int as uint8_t,
    0x63 as core::ffi::c_int as uint8_t,
    0xe as core::ffi::c_int as uint8_t,
    0xf3 as core::ffi::c_int as uint8_t,
    0x8b as core::ffi::c_int as uint8_t,
    0x41 as core::ffi::c_int as uint8_t,
    0xa6 as core::ffi::c_int as uint8_t,
    0xf8 as core::ffi::c_int as uint8_t,
    0x9b as core::ffi::c_int as uint8_t,
    0x53 as core::ffi::c_int as uint8_t,
    0x70 as core::ffi::c_int as uint8_t,
    0x80 as core::ffi::c_int as uint8_t,
    0x53 as core::ffi::c_int as uint8_t,
    0x86 as core::ffi::c_int as uint8_t,
    0x5e as core::ffi::c_int as uint8_t,
    0x8f as core::ffi::c_int as uint8_t,
    0xe3 as core::ffi::c_int as uint8_t,
    0xc3 as core::ffi::c_int as uint8_t,
    0xd as core::ffi::c_int as uint8_t,
    0x18 as core::ffi::c_int as uint8_t,
    0xc8 as core::ffi::c_int as uint8_t,
    0x4b as core::ffi::c_int as uint8_t,
    0x34 as core::ffi::c_int as uint8_t,
    0x1f as core::ffi::c_int as uint8_t,
    0xd8 as core::ffi::c_int as uint8_t,
    0x1d as core::ffi::c_int as uint8_t,
    0xbc as core::ffi::c_int as uint8_t,
    0xf2 as core::ffi::c_int as uint8_t,
    0x6d as core::ffi::c_int as uint8_t,
    0x34 as core::ffi::c_int as uint8_t,
    0x3a as core::ffi::c_int as uint8_t,
    0xbe as core::ffi::c_int as uint8_t,
    0xdf as core::ffi::c_int as uint8_t,
    0xd9 as core::ffi::c_int as uint8_t,
    0xf6 as core::ffi::c_int as uint8_t,
    0xf3 as core::ffi::c_int as uint8_t,
    0x89 as core::ffi::c_int as uint8_t,
    0xa1 as core::ffi::c_int as uint8_t,
    0xe1 as core::ffi::c_int as uint8_t,
    0x94 as core::ffi::c_int as uint8_t,
    0x9f as core::ffi::c_int as uint8_t,
    0x5d as core::ffi::c_int as uint8_t,
    0x4c as core::ffi::c_int as uint8_t,
    0x5d as core::ffi::c_int as uint8_t,
    0xe9 as core::ffi::c_int as uint8_t,
    0xa1 as core::ffi::c_int as uint8_t,
    0x49 as core::ffi::c_int as uint8_t,
    0x92 as core::ffi::c_int as uint8_t,
    0xef as core::ffi::c_int as uint8_t,
    0xe as core::ffi::c_int as uint8_t,
    0x53 as core::ffi::c_int as uint8_t,
    0x81 as core::ffi::c_int as uint8_t,
    0x89 as core::ffi::c_int as uint8_t,
    0x58 as core::ffi::c_int as uint8_t,
    0x87 as core::ffi::c_int as uint8_t,
    0xa6 as core::ffi::c_int as uint8_t,
    0x37 as core::ffi::c_int as uint8_t,
    0xf1 as core::ffi::c_int as uint8_t,
    0xdd as core::ffi::c_int as uint8_t,
    0x62 as core::ffi::c_int as uint8_t,
    0x60 as core::ffi::c_int as uint8_t,
    0x63 as core::ffi::c_int as uint8_t,
    0x5a as core::ffi::c_int as uint8_t,
    0x9d as core::ffi::c_int as uint8_t,
    0x1b as core::ffi::c_int as uint8_t,
    0x8c as core::ffi::c_int as uint8_t,
    0xc6 as core::ffi::c_int as uint8_t,
    0x7d as core::ffi::c_int as uint8_t,
    0x52 as core::ffi::c_int as uint8_t,
    0xea as core::ffi::c_int as uint8_t,
    0x70 as core::ffi::c_int as uint8_t,
    0x9 as core::ffi::c_int as uint8_t,
    0x6a as core::ffi::c_int as uint8_t,
    0xe1 as core::ffi::c_int as uint8_t,
    0x32 as core::ffi::c_int as uint8_t,
    0xf3 as core::ffi::c_int as uint8_t,
    0x73 as core::ffi::c_int as uint8_t,
    0x21 as core::ffi::c_int as uint8_t,
    0x1f as core::ffi::c_int as uint8_t,
    0x7 as core::ffi::c_int as uint8_t,
    0x7b as core::ffi::c_int as uint8_t,
    0x7c as core::ffi::c_int as uint8_t,
    0x9b as core::ffi::c_int as uint8_t,
    0x49 as core::ffi::c_int as uint8_t,
    0xd8 as core::ffi::c_int as uint8_t,
    0xc0 as core::ffi::c_int as uint8_t,
    0xf3 as core::ffi::c_int as uint8_t,
    0x25 as core::ffi::c_int as uint8_t,
    0x72 as core::ffi::c_int as uint8_t,
    0x6f as core::ffi::c_int as uint8_t,
    0x9d as core::ffi::c_int as uint8_t,
    0xed as core::ffi::c_int as uint8_t,
    0x31 as core::ffi::c_int as uint8_t,
    0x67 as core::ffi::c_int as uint8_t,
    0x36 as core::ffi::c_int as uint8_t,
    0x36 as core::ffi::c_int as uint8_t,
    0x54 as core::ffi::c_int as uint8_t,
    0x40 as core::ffi::c_int as uint8_t,
    0x92 as core::ffi::c_int as uint8_t,
    0x71 as core::ffi::c_int as uint8_t,
    0xe6 as core::ffi::c_int as uint8_t,
    0x11 as core::ffi::c_int as uint8_t,
    0x28 as core::ffi::c_int as uint8_t,
    0x11 as core::ffi::c_int as uint8_t,
    0xad as core::ffi::c_int as uint8_t,
    0x93 as core::ffi::c_int as uint8_t,
    0x32 as core::ffi::c_int as uint8_t,
    0x85 as core::ffi::c_int as uint8_t,
    0x7b as core::ffi::c_int as uint8_t,
    0x3e as core::ffi::c_int as uint8_t,
    0xb7 as core::ffi::c_int as uint8_t,
    0x3b as core::ffi::c_int as uint8_t,
    0x49 as core::ffi::c_int as uint8_t,
    0x13 as core::ffi::c_int as uint8_t,
    0x1c as core::ffi::c_int as uint8_t,
    0x7 as core::ffi::c_int as uint8_t,
    0xb0 as core::ffi::c_int as uint8_t,
    0x2e as core::ffi::c_int as uint8_t,
    0x93 as core::ffi::c_int as uint8_t,
    0xaa as core::ffi::c_int as uint8_t,
    0xfd as core::ffi::c_int as uint8_t,
    0xfd as core::ffi::c_int as uint8_t,
    0x28 as core::ffi::c_int as uint8_t,
    0x47 as core::ffi::c_int as uint8_t,
    0x3d as core::ffi::c_int as uint8_t,
    0x8d as core::ffi::c_int as uint8_t,
    0xd2 as core::ffi::c_int as uint8_t,
    0xda as core::ffi::c_int as uint8_t,
    0xc7 as core::ffi::c_int as uint8_t,
    0x44 as core::ffi::c_int as uint8_t,
    0xd6 as core::ffi::c_int as uint8_t,
    0x7a as core::ffi::c_int as uint8_t,
    0xdb as core::ffi::c_int as uint8_t,
    0x26 as core::ffi::c_int as uint8_t,
    0x7d as core::ffi::c_int as uint8_t,
    0x1d as core::ffi::c_int as uint8_t,
    0xb8 as core::ffi::c_int as uint8_t,
    0xe1 as core::ffi::c_int as uint8_t,
    0xde as core::ffi::c_int as uint8_t,
    0x9d as core::ffi::c_int as uint8_t,
    0x7a as core::ffi::c_int as uint8_t,
    0x7d as core::ffi::c_int as uint8_t,
    0x17 as core::ffi::c_int as uint8_t,
    0x7e as core::ffi::c_int as uint8_t,
    0x1c as core::ffi::c_int as uint8_t,
    0x37 as core::ffi::c_int as uint8_t,
    0x4 as core::ffi::c_int as uint8_t,
    0x8d as core::ffi::c_int as uint8_t,
    0x2d as core::ffi::c_int as uint8_t,
    0x7c as core::ffi::c_int as uint8_t,
    0x5e as core::ffi::c_int as uint8_t,
    0x18 as core::ffi::c_int as uint8_t,
    0x38 as core::ffi::c_int as uint8_t,
    0x1e as core::ffi::c_int as uint8_t,
    0xaf as core::ffi::c_int as uint8_t,
    0xc7 as core::ffi::c_int as uint8_t,
    0x1b as core::ffi::c_int as uint8_t,
    0x33 as core::ffi::c_int as uint8_t,
    0x48 as core::ffi::c_int as uint8_t,
    0x31 as core::ffi::c_int as uint8_t,
    0 as core::ffi::c_int as uint8_t,
    0x59 as core::ffi::c_int as uint8_t,
    0xf6 as core::ffi::c_int as uint8_t,
    0xf2 as core::ffi::c_int as uint8_t,
    0xca as core::ffi::c_int as uint8_t,
    0xf as core::ffi::c_int as uint8_t,
    0x27 as core::ffi::c_int as uint8_t,
    0x1b as core::ffi::c_int as uint8_t,
    0x63 as core::ffi::c_int as uint8_t,
    0x12 as core::ffi::c_int as uint8_t,
    0x7e as core::ffi::c_int as uint8_t,
    0x2 as core::ffi::c_int as uint8_t,
    0x1d as core::ffi::c_int as uint8_t,
    0x49 as core::ffi::c_int as uint8_t,
    0xc0 as core::ffi::c_int as uint8_t,
    0x5d as core::ffi::c_int as uint8_t,
    0x79 as core::ffi::c_int as uint8_t,
    0x87 as core::ffi::c_int as uint8_t,
    0xef as core::ffi::c_int as uint8_t,
    0x5e as core::ffi::c_int as uint8_t,
    0x7a as core::ffi::c_int as uint8_t,
    0x2f as core::ffi::c_int as uint8_t,
    0x1f as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x55 as core::ffi::c_int as uint8_t,
    0xd8 as core::ffi::c_int as uint8_t,
    0x9 as core::ffi::c_int as uint8_t,
    0xd9 as core::ffi::c_int as uint8_t,
    0x61 as core::ffi::c_int as uint8_t,
    0x38 as core::ffi::c_int as uint8_t,
    0x68 as core::ffi::c_int as uint8_t,
    0xb0 as core::ffi::c_int as uint8_t,
    0x7 as core::ffi::c_int as uint8_t,
    0xa3 as core::ffi::c_int as uint8_t,
    0xfc as core::ffi::c_int as uint8_t,
    0xcc as core::ffi::c_int as uint8_t,
    0x85 as core::ffi::c_int as uint8_t,
    0x10 as core::ffi::c_int as uint8_t,
    0x7f as core::ffi::c_int as uint8_t,
    0x4c as core::ffi::c_int as uint8_t,
    0x65 as core::ffi::c_int as uint8_t,
    0x65 as core::ffi::c_int as uint8_t,
    0xb3 as core::ffi::c_int as uint8_t,
    0xfa as core::ffi::c_int as uint8_t,
    0xfa as core::ffi::c_int as uint8_t,
    0xa5 as core::ffi::c_int as uint8_t,
    0x53 as core::ffi::c_int as uint8_t,
    0x6f as core::ffi::c_int as uint8_t,
    0xdb as core::ffi::c_int as uint8_t,
    0x74 as core::ffi::c_int as uint8_t,
    0x4c as core::ffi::c_int as uint8_t,
    0x56 as core::ffi::c_int as uint8_t,
    0x46 as core::ffi::c_int as uint8_t,
    0x3 as core::ffi::c_int as uint8_t,
    0xe2 as core::ffi::c_int as uint8_t,
    0xd5 as core::ffi::c_int as uint8_t,
    0x7a as core::ffi::c_int as uint8_t,
    0x29 as core::ffi::c_int as uint8_t,
    0x1c as core::ffi::c_int as uint8_t,
    0xc6 as core::ffi::c_int as uint8_t,
    0x2 as core::ffi::c_int as uint8_t,
    0xbc as core::ffi::c_int as uint8_t,
    0x59 as core::ffi::c_int as uint8_t,
    0xf2 as core::ffi::c_int as uint8_t,
    0x4 as core::ffi::c_int as uint8_t,
    0x75 as core::ffi::c_int as uint8_t,
    0x63 as core::ffi::c_int as uint8_t,
    0xc0 as core::ffi::c_int as uint8_t,
    0x84 as core::ffi::c_int as uint8_t,
    0x2f as core::ffi::c_int as uint8_t,
    0x60 as core::ffi::c_int as uint8_t,
    0x1c as core::ffi::c_int as uint8_t,
    0x67 as core::ffi::c_int as uint8_t,
    0x76 as core::ffi::c_int as uint8_t,
    0xfd as core::ffi::c_int as uint8_t,
    0x63 as core::ffi::c_int as uint8_t,
    0x86 as core::ffi::c_int as uint8_t,
    0xf3 as core::ffi::c_int as uint8_t,
    0xfa as core::ffi::c_int as uint8_t,
    0xbf as core::ffi::c_int as uint8_t,
    0xdc as core::ffi::c_int as uint8_t,
    0xd2 as core::ffi::c_int as uint8_t,
    0x2d as core::ffi::c_int as uint8_t,
    0x90 as core::ffi::c_int as uint8_t,
    0x91 as core::ffi::c_int as uint8_t,
    0xbd as core::ffi::c_int as uint8_t,
    0x33 as core::ffi::c_int as uint8_t,
    0xa9 as core::ffi::c_int as uint8_t,
    0xe5 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0xc as core::ffi::c_int as uint8_t,
    0xda as core::ffi::c_int as uint8_t,
    0x42 as core::ffi::c_int as uint8_t,
    0x27 as core::ffi::c_int as uint8_t,
    0xca as core::ffi::c_int as uint8_t,
    0xf4 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0xc2 as core::ffi::c_int as uint8_t,
    0xec as core::ffi::c_int as uint8_t,
    0x92 as core::ffi::c_int as uint8_t,
    0x14 as core::ffi::c_int as uint8_t,
    0x57 as core::ffi::c_int as uint8_t,
    0x6 as core::ffi::c_int as uint8_t,
    0x63 as core::ffi::c_int as uint8_t,
    0xd0 as core::ffi::c_int as uint8_t,
    0x4d as core::ffi::c_int as uint8_t,
    0x15 as core::ffi::c_int as uint8_t,
    0x6 as core::ffi::c_int as uint8_t,
    0xeb as core::ffi::c_int as uint8_t,
    0x69 as core::ffi::c_int as uint8_t,
    0x58 as core::ffi::c_int as uint8_t,
    0x4f as core::ffi::c_int as uint8_t,
    0x77 as core::ffi::c_int as uint8_t,
    0xc5 as core::ffi::c_int as uint8_t,
    0x8b as core::ffi::c_int as uint8_t,
    0xc7 as core::ffi::c_int as uint8_t,
    0xf0 as core::ffi::c_int as uint8_t,
    0x8e as core::ffi::c_int as uint8_t,
    0xed as core::ffi::c_int as uint8_t,
    0x64 as core::ffi::c_int as uint8_t,
    0xa0 as core::ffi::c_int as uint8_t,
    0xb3 as core::ffi::c_int as uint8_t,
    0x3c as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0x71 as core::ffi::c_int as uint8_t,
    0xc6 as core::ffi::c_int as uint8_t,
    0x2d as core::ffi::c_int as uint8_t,
    0xda as core::ffi::c_int as uint8_t,
    0xa as core::ffi::c_int as uint8_t,
    0xd as core::ffi::c_int as uint8_t,
    0xfe as core::ffi::c_int as uint8_t,
    0x70 as core::ffi::c_int as uint8_t,
    0x27 as core::ffi::c_int as uint8_t,
    0x64 as core::ffi::c_int as uint8_t,
    0xf8 as core::ffi::c_int as uint8_t,
    0x27 as core::ffi::c_int as uint8_t,
    0xfa as core::ffi::c_int as uint8_t,
    0xf6 as core::ffi::c_int as uint8_t,
    0x5f as core::ffi::c_int as uint8_t,
    0x30 as core::ffi::c_int as uint8_t,
    0xa5 as core::ffi::c_int as uint8_t,
    0xd as core::ffi::c_int as uint8_t,
    0x6c as core::ffi::c_int as uint8_t,
    0xda as core::ffi::c_int as uint8_t,
    0xf2 as core::ffi::c_int as uint8_t,
    0x62 as core::ffi::c_int as uint8_t,
    0x5e as core::ffi::c_int as uint8_t,
    0x78 as core::ffi::c_int as uint8_t,
    0x47 as core::ffi::c_int as uint8_t,
    0xd3 as core::ffi::c_int as uint8_t,
    0x66 as core::ffi::c_int as uint8_t,
    0 as core::ffi::c_int as uint8_t,
    0x1c as core::ffi::c_int as uint8_t,
    0xfd as core::ffi::c_int as uint8_t,
    0x56 as core::ffi::c_int as uint8_t,
    0x1f as core::ffi::c_int as uint8_t,
    0x5d as core::ffi::c_int as uint8_t,
    0x3f as core::ffi::c_int as uint8_t,
    0x6f as core::ffi::c_int as uint8_t,
    0xf4 as core::ffi::c_int as uint8_t,
    0x4c as core::ffi::c_int as uint8_t,
    0xd8 as core::ffi::c_int as uint8_t,
    0xfd as core::ffi::c_int as uint8_t,
    0xe as core::ffi::c_int as uint8_t,
    0x27 as core::ffi::c_int as uint8_t,
    0xc9 as core::ffi::c_int as uint8_t,
    0x5c as core::ffi::c_int as uint8_t,
    0x2b as core::ffi::c_int as uint8_t,
    0xbc as core::ffi::c_int as uint8_t,
    0xc0 as core::ffi::c_int as uint8_t,
    0xa4 as core::ffi::c_int as uint8_t,
    0xe7 as core::ffi::c_int as uint8_t,
    0x23 as core::ffi::c_int as uint8_t,
    0x29 as core::ffi::c_int as uint8_t,
    0x2 as core::ffi::c_int as uint8_t,
    0x9f as core::ffi::c_int as uint8_t,
    0x31 as core::ffi::c_int as uint8_t,
    0xd6 as core::ffi::c_int as uint8_t,
    0xe9 as core::ffi::c_int as uint8_t,
    0xd7 as core::ffi::c_int as uint8_t,
    0x96 as core::ffi::c_int as uint8_t,
    0xf4 as core::ffi::c_int as uint8_t,
    0xe0 as core::ffi::c_int as uint8_t,
    0x5e as core::ffi::c_int as uint8_t,
    0xb as core::ffi::c_int as uint8_t,
    0xe as core::ffi::c_int as uint8_t,
    0x13 as core::ffi::c_int as uint8_t,
    0xee as core::ffi::c_int as uint8_t,
    0x3c as core::ffi::c_int as uint8_t,
    0x9 as core::ffi::c_int as uint8_t,
    0xed as core::ffi::c_int as uint8_t,
    0xf2 as core::ffi::c_int as uint8_t,
    0x3d as core::ffi::c_int as uint8_t,
    0x76 as core::ffi::c_int as uint8_t,
    0x91 as core::ffi::c_int as uint8_t,
    0xc3 as core::ffi::c_int as uint8_t,
    0xa4 as core::ffi::c_int as uint8_t,
    0x97 as core::ffi::c_int as uint8_t,
    0xae as core::ffi::c_int as uint8_t,
    0xd4 as core::ffi::c_int as uint8_t,
    0x87 as core::ffi::c_int as uint8_t,
    0xd0 as core::ffi::c_int as uint8_t,
    0x5d as core::ffi::c_int as uint8_t,
    0xf6 as core::ffi::c_int as uint8_t,
    0x18 as core::ffi::c_int as uint8_t,
    0x47 as core::ffi::c_int as uint8_t,
    0x1f as core::ffi::c_int as uint8_t,
    0x1d as core::ffi::c_int as uint8_t,
    0x67 as core::ffi::c_int as uint8_t,
    0xf2 as core::ffi::c_int as uint8_t,
    0xcf as core::ffi::c_int as uint8_t,
    0x63 as core::ffi::c_int as uint8_t,
    0xa0 as core::ffi::c_int as uint8_t,
    0x91 as core::ffi::c_int as uint8_t,
    0x27 as core::ffi::c_int as uint8_t,
    0xf8 as core::ffi::c_int as uint8_t,
    0x93 as core::ffi::c_int as uint8_t,
    0x45 as core::ffi::c_int as uint8_t,
    0x75 as core::ffi::c_int as uint8_t,
    0x23 as core::ffi::c_int as uint8_t,
    0x3f as core::ffi::c_int as uint8_t,
    0xd1 as core::ffi::c_int as uint8_t,
    0xf1 as core::ffi::c_int as uint8_t,
    0xad as core::ffi::c_int as uint8_t,
    0x23 as core::ffi::c_int as uint8_t,
    0xdd as core::ffi::c_int as uint8_t,
    0x64 as core::ffi::c_int as uint8_t,
    0x93 as core::ffi::c_int as uint8_t,
    0x96 as core::ffi::c_int as uint8_t,
    0x41 as core::ffi::c_int as uint8_t,
    0x70 as core::ffi::c_int as uint8_t,
    0x7f as core::ffi::c_int as uint8_t,
    0xf7 as core::ffi::c_int as uint8_t,
    0xf5 as core::ffi::c_int as uint8_t,
    0xa9 as core::ffi::c_int as uint8_t,
    0x89 as core::ffi::c_int as uint8_t,
    0xa2 as core::ffi::c_int as uint8_t,
    0x34 as core::ffi::c_int as uint8_t,
    0xb0 as core::ffi::c_int as uint8_t,
    0x8d as core::ffi::c_int as uint8_t,
    0x1b as core::ffi::c_int as uint8_t,
    0xae as core::ffi::c_int as uint8_t,
    0x19 as core::ffi::c_int as uint8_t,
    0x15 as core::ffi::c_int as uint8_t,
    0x49 as core::ffi::c_int as uint8_t,
    0x58 as core::ffi::c_int as uint8_t,
    0x23 as core::ffi::c_int as uint8_t,
    0x6d as core::ffi::c_int as uint8_t,
    0x87 as core::ffi::c_int as uint8_t,
    0x15 as core::ffi::c_int as uint8_t,
    0x4f as core::ffi::c_int as uint8_t,
    0x81 as core::ffi::c_int as uint8_t,
    0x76 as core::ffi::c_int as uint8_t,
    0xfb as core::ffi::c_int as uint8_t,
    0x23 as core::ffi::c_int as uint8_t,
    0xb5 as core::ffi::c_int as uint8_t,
    0xea as core::ffi::c_int as uint8_t,
    0xcf as core::ffi::c_int as uint8_t,
    0xac as core::ffi::c_int as uint8_t,
    0x54 as core::ffi::c_int as uint8_t,
    0x8d as core::ffi::c_int as uint8_t,
    0x4e as core::ffi::c_int as uint8_t,
    0x42 as core::ffi::c_int as uint8_t,
    0x2f as core::ffi::c_int as uint8_t,
    0xeb as core::ffi::c_int as uint8_t,
    0xf as core::ffi::c_int as uint8_t,
    0x63 as core::ffi::c_int as uint8_t,
    0xdb as core::ffi::c_int as uint8_t,
    0x68 as core::ffi::c_int as uint8_t,
    0x37 as core::ffi::c_int as uint8_t,
    0xa8 as core::ffi::c_int as uint8_t,
    0xcf as core::ffi::c_int as uint8_t,
    0x8b as core::ffi::c_int as uint8_t,
    0xab as core::ffi::c_int as uint8_t,
    0xf5 as core::ffi::c_int as uint8_t,
    0xa4 as core::ffi::c_int as uint8_t,
    0x6e as core::ffi::c_int as uint8_t,
    0x96 as core::ffi::c_int as uint8_t,
    0x2a as core::ffi::c_int as uint8_t,
    0xb2 as core::ffi::c_int as uint8_t,
    0xd6 as core::ffi::c_int as uint8_t,
    0xbe as core::ffi::c_int as uint8_t,
    0x9e as core::ffi::c_int as uint8_t,
    0xbd as core::ffi::c_int as uint8_t,
    0xd as core::ffi::c_int as uint8_t,
    0xb4 as core::ffi::c_int as uint8_t,
    0x42 as core::ffi::c_int as uint8_t,
    0xa9 as core::ffi::c_int as uint8_t,
    0xcf as core::ffi::c_int as uint8_t,
    0x1 as core::ffi::c_int as uint8_t,
    0x83 as core::ffi::c_int as uint8_t,
    0x8a as core::ffi::c_int as uint8_t,
    0x17 as core::ffi::c_int as uint8_t,
    0x47 as core::ffi::c_int as uint8_t,
    0x76 as core::ffi::c_int as uint8_t,
    0xc4 as core::ffi::c_int as uint8_t,
    0xc6 as core::ffi::c_int as uint8_t,
    0x83 as core::ffi::c_int as uint8_t,
    0x4 as core::ffi::c_int as uint8_t,
    0x95 as core::ffi::c_int as uint8_t,
    0xb as core::ffi::c_int as uint8_t,
    0xfc as core::ffi::c_int as uint8_t,
    0x11 as core::ffi::c_int as uint8_t,
    0xc9 as core::ffi::c_int as uint8_t,
    0x62 as core::ffi::c_int as uint8_t,
    0xb8 as core::ffi::c_int as uint8_t,
    0xc as core::ffi::c_int as uint8_t,
    0x76 as core::ffi::c_int as uint8_t,
    0x84 as core::ffi::c_int as uint8_t,
    0xd9 as core::ffi::c_int as uint8_t,
    0xb9 as core::ffi::c_int as uint8_t,
    0x37 as core::ffi::c_int as uint8_t,
    0xfa as core::ffi::c_int as uint8_t,
    0xfc as core::ffi::c_int as uint8_t,
    0x7c as core::ffi::c_int as uint8_t,
    0xc2 as core::ffi::c_int as uint8_t,
    0x6d as core::ffi::c_int as uint8_t,
    0x58 as core::ffi::c_int as uint8_t,
    0x3e as core::ffi::c_int as uint8_t,
    0xb3 as core::ffi::c_int as uint8_t,
    0x4 as core::ffi::c_int as uint8_t,
    0xbb as core::ffi::c_int as uint8_t,
    0x8c as core::ffi::c_int as uint8_t,
    0x8f as core::ffi::c_int as uint8_t,
    0x48 as core::ffi::c_int as uint8_t,
    0xbc as core::ffi::c_int as uint8_t,
    0x91 as core::ffi::c_int as uint8_t,
    0x27 as core::ffi::c_int as uint8_t,
    0xcc as core::ffi::c_int as uint8_t,
    0xf9 as core::ffi::c_int as uint8_t,
    0xb7 as core::ffi::c_int as uint8_t,
    0x22 as core::ffi::c_int as uint8_t,
    0x19 as core::ffi::c_int as uint8_t,
    0x83 as core::ffi::c_int as uint8_t,
    0x2e as core::ffi::c_int as uint8_t,
    0x9 as core::ffi::c_int as uint8_t,
    0xb5 as core::ffi::c_int as uint8_t,
    0x72 as core::ffi::c_int as uint8_t,
    0xd9 as core::ffi::c_int as uint8_t,
    0x54 as core::ffi::c_int as uint8_t,
    0x1c as core::ffi::c_int as uint8_t,
    0x4d as core::ffi::c_int as uint8_t,
    0xa1 as core::ffi::c_int as uint8_t,
    0xea as core::ffi::c_int as uint8_t,
    0xb as core::ffi::c_int as uint8_t,
    0xf1 as core::ffi::c_int as uint8_t,
    0xc6 as core::ffi::c_int as uint8_t,
    0x8 as core::ffi::c_int as uint8_t,
    0x72 as core::ffi::c_int as uint8_t,
    0x46 as core::ffi::c_int as uint8_t,
    0x87 as core::ffi::c_int as uint8_t,
    0x7a as core::ffi::c_int as uint8_t,
    0x6e as core::ffi::c_int as uint8_t,
    0x80 as core::ffi::c_int as uint8_t,
    0x56 as core::ffi::c_int as uint8_t,
    0xa as core::ffi::c_int as uint8_t,
    0x8a as core::ffi::c_int as uint8_t,
    0xc0 as core::ffi::c_int as uint8_t,
    0xdd as core::ffi::c_int as uint8_t,
    0x11 as core::ffi::c_int as uint8_t,
    0x6b as core::ffi::c_int as uint8_t,
    0xd6 as core::ffi::c_int as uint8_t,
    0xdd as core::ffi::c_int as uint8_t,
    0x47 as core::ffi::c_int as uint8_t,
    0xdf as core::ffi::c_int as uint8_t,
    0x10 as core::ffi::c_int as uint8_t,
    0xd9 as core::ffi::c_int as uint8_t,
    0xd8 as core::ffi::c_int as uint8_t,
    0xea as core::ffi::c_int as uint8_t,
    0x7c as core::ffi::c_int as uint8_t,
    0xb0 as core::ffi::c_int as uint8_t,
    0x8f as core::ffi::c_int as uint8_t,
    0x3 as core::ffi::c_int as uint8_t,
    0 as core::ffi::c_int as uint8_t,
    0x2e as core::ffi::c_int as uint8_t,
    0xc1 as core::ffi::c_int as uint8_t,
    0x8f as core::ffi::c_int as uint8_t,
    0x44 as core::ffi::c_int as uint8_t,
    0xa8 as core::ffi::c_int as uint8_t,
    0xd3 as core::ffi::c_int as uint8_t,
    0x30 as core::ffi::c_int as uint8_t,
    0x6 as core::ffi::c_int as uint8_t,
    0x89 as core::ffi::c_int as uint8_t,
    0xa2 as core::ffi::c_int as uint8_t,
    0xf9 as core::ffi::c_int as uint8_t,
    0x34 as core::ffi::c_int as uint8_t,
    0xad as core::ffi::c_int as uint8_t,
    0xdc as core::ffi::c_int as uint8_t,
    0x3 as core::ffi::c_int as uint8_t,
    0x85 as core::ffi::c_int as uint8_t,
    0xed as core::ffi::c_int as uint8_t,
    0x51 as core::ffi::c_int as uint8_t,
    0xa7 as core::ffi::c_int as uint8_t,
    0x82 as core::ffi::c_int as uint8_t,
    0x9c as core::ffi::c_int as uint8_t,
    0xe7 as core::ffi::c_int as uint8_t,
    0x5d as core::ffi::c_int as uint8_t,
    0x52 as core::ffi::c_int as uint8_t,
    0x93 as core::ffi::c_int as uint8_t,
    0xc as core::ffi::c_int as uint8_t,
    0x32 as core::ffi::c_int as uint8_t,
    0x9a as core::ffi::c_int as uint8_t,
    0x5b as core::ffi::c_int as uint8_t,
    0xe1 as core::ffi::c_int as uint8_t,
    0xaa as core::ffi::c_int as uint8_t,
    0xca as core::ffi::c_int as uint8_t,
    0xb8 as core::ffi::c_int as uint8_t,
    0x2 as core::ffi::c_int as uint8_t,
    0x6d as core::ffi::c_int as uint8_t,
    0x3a as core::ffi::c_int as uint8_t,
    0xd4 as core::ffi::c_int as uint8_t,
    0xb1 as core::ffi::c_int as uint8_t,
    0x3a as core::ffi::c_int as uint8_t,
    0xf0 as core::ffi::c_int as uint8_t,
    0x5f as core::ffi::c_int as uint8_t,
    0xbe as core::ffi::c_int as uint8_t,
    0xb5 as core::ffi::c_int as uint8_t,
    0xd as core::ffi::c_int as uint8_t,
    0x10 as core::ffi::c_int as uint8_t,
    0x6b as core::ffi::c_int as uint8_t,
    0x38 as core::ffi::c_int as uint8_t,
    0x32 as core::ffi::c_int as uint8_t,
    0xac as core::ffi::c_int as uint8_t,
    0x76 as core::ffi::c_int as uint8_t,
    0x80 as core::ffi::c_int as uint8_t,
    0xbd as core::ffi::c_int as uint8_t,
    0xca as core::ffi::c_int as uint8_t,
    0x94 as core::ffi::c_int as uint8_t,
    0x71 as core::ffi::c_int as uint8_t,
    0x7a as core::ffi::c_int as uint8_t,
    0xf2 as core::ffi::c_int as uint8_t,
    0xc9 as core::ffi::c_int as uint8_t,
    0x35 as core::ffi::c_int as uint8_t,
    0x2a as core::ffi::c_int as uint8_t,
    0xde as core::ffi::c_int as uint8_t,
    0x9f as core::ffi::c_int as uint8_t,
    0x42 as core::ffi::c_int as uint8_t,
    0x49 as core::ffi::c_int as uint8_t,
    0x18 as core::ffi::c_int as uint8_t,
    0x1 as core::ffi::c_int as uint8_t,
    0xab as core::ffi::c_int as uint8_t,
    0xbc as core::ffi::c_int as uint8_t,
    0xef as core::ffi::c_int as uint8_t,
    0x7c as core::ffi::c_int as uint8_t,
    0x64 as core::ffi::c_int as uint8_t,
    0x3f as core::ffi::c_int as uint8_t,
    0x58 as core::ffi::c_int as uint8_t,
    0x3d as core::ffi::c_int as uint8_t,
    0x92 as core::ffi::c_int as uint8_t,
    0x59 as core::ffi::c_int as uint8_t,
    0xdb as core::ffi::c_int as uint8_t,
    0x13 as core::ffi::c_int as uint8_t,
    0xdb as core::ffi::c_int as uint8_t,
    0x58 as core::ffi::c_int as uint8_t,
    0x6e as core::ffi::c_int as uint8_t,
    0xa as core::ffi::c_int as uint8_t,
    0xe0 as core::ffi::c_int as uint8_t,
    0xb7 as core::ffi::c_int as uint8_t,
    0x91 as core::ffi::c_int as uint8_t,
    0x4a as core::ffi::c_int as uint8_t,
    0x8 as core::ffi::c_int as uint8_t,
    0x20 as core::ffi::c_int as uint8_t,
    0xd6 as core::ffi::c_int as uint8_t,
    0x2e as core::ffi::c_int as uint8_t,
    0x3c as core::ffi::c_int as uint8_t,
    0x45 as core::ffi::c_int as uint8_t,
    0xc9 as core::ffi::c_int as uint8_t,
    0x8b as core::ffi::c_int as uint8_t,
    0x17 as core::ffi::c_int as uint8_t,
    0x79 as core::ffi::c_int as uint8_t,
    0xe7 as core::ffi::c_int as uint8_t,
    0xc7 as core::ffi::c_int as uint8_t,
    0x90 as core::ffi::c_int as uint8_t,
    0x99 as core::ffi::c_int as uint8_t,
    0x3a as core::ffi::c_int as uint8_t,
    0x18 as core::ffi::c_int as uint8_t,
    0x25 as core::ffi::c_int as uint8_t,
];
static mut Bi: [ge_precomp; 8] = [
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        25967493 as core::ffi::c_int as fe_limb_t,
                        19198397 as core::ffi::c_int as fe_limb_t,
                        29566455 as core::ffi::c_int as fe_limb_t,
                        3660896 as core::ffi::c_int as fe_limb_t,
                        54414519 as core::ffi::c_int as fe_limb_t,
                        4014786 as core::ffi::c_int as fe_limb_t,
                        27544626 as core::ffi::c_int as fe_limb_t,
                        21800161 as core::ffi::c_int as fe_limb_t,
                        61029707 as core::ffi::c_int as fe_limb_t,
                        2047604 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        54563134 as core::ffi::c_int as fe_limb_t,
                        934261 as core::ffi::c_int as fe_limb_t,
                        64385954 as core::ffi::c_int as fe_limb_t,
                        3049989 as core::ffi::c_int as fe_limb_t,
                        66381436 as core::ffi::c_int as fe_limb_t,
                        9406985 as core::ffi::c_int as fe_limb_t,
                        12720692 as core::ffi::c_int as fe_limb_t,
                        5043384 as core::ffi::c_int as fe_limb_t,
                        19500929 as core::ffi::c_int as fe_limb_t,
                        18085054 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        58370664 as core::ffi::c_int as fe_limb_t,
                        4489569 as core::ffi::c_int as fe_limb_t,
                        9688441 as core::ffi::c_int as fe_limb_t,
                        18769238 as core::ffi::c_int as fe_limb_t,
                        10184608 as core::ffi::c_int as fe_limb_t,
                        21191052 as core::ffi::c_int as fe_limb_t,
                        29287918 as core::ffi::c_int as fe_limb_t,
                        11864899 as core::ffi::c_int as fe_limb_t,
                        42594502 as core::ffi::c_int as fe_limb_t,
                        29115885 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        15636272 as core::ffi::c_int as fe_limb_t,
                        23865875 as core::ffi::c_int as fe_limb_t,
                        24204772 as core::ffi::c_int as fe_limb_t,
                        25642034 as core::ffi::c_int as fe_limb_t,
                        616976 as core::ffi::c_int as fe_limb_t,
                        16869170 as core::ffi::c_int as fe_limb_t,
                        27787599 as core::ffi::c_int as fe_limb_t,
                        18782243 as core::ffi::c_int as fe_limb_t,
                        28944399 as core::ffi::c_int as fe_limb_t,
                        32004408 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        16568933 as core::ffi::c_int as fe_limb_t,
                        4717097 as core::ffi::c_int as fe_limb_t,
                        55552716 as core::ffi::c_int as fe_limb_t,
                        32452109 as core::ffi::c_int as fe_limb_t,
                        15682895 as core::ffi::c_int as fe_limb_t,
                        21747389 as core::ffi::c_int as fe_limb_t,
                        16354576 as core::ffi::c_int as fe_limb_t,
                        21778470 as core::ffi::c_int as fe_limb_t,
                        7689661 as core::ffi::c_int as fe_limb_t,
                        11199574 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        30464137 as core::ffi::c_int as fe_limb_t,
                        27578307 as core::ffi::c_int as fe_limb_t,
                        55329429 as core::ffi::c_int as fe_limb_t,
                        17883566 as core::ffi::c_int as fe_limb_t,
                        23220364 as core::ffi::c_int as fe_limb_t,
                        15915852 as core::ffi::c_int as fe_limb_t,
                        7512774 as core::ffi::c_int as fe_limb_t,
                        10017326 as core::ffi::c_int as fe_limb_t,
                        49359771 as core::ffi::c_int as fe_limb_t,
                        23634074 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        10861363 as core::ffi::c_int as fe_limb_t,
                        11473154 as core::ffi::c_int as fe_limb_t,
                        27284546 as core::ffi::c_int as fe_limb_t,
                        1981175 as core::ffi::c_int as fe_limb_t,
                        37044515 as core::ffi::c_int as fe_limb_t,
                        12577860 as core::ffi::c_int as fe_limb_t,
                        32867885 as core::ffi::c_int as fe_limb_t,
                        14515107 as core::ffi::c_int as fe_limb_t,
                        51670560 as core::ffi::c_int as fe_limb_t,
                        10819379 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        4708026 as core::ffi::c_int as fe_limb_t,
                        6336745 as core::ffi::c_int as fe_limb_t,
                        20377586 as core::ffi::c_int as fe_limb_t,
                        9066809 as core::ffi::c_int as fe_limb_t,
                        55836755 as core::ffi::c_int as fe_limb_t,
                        6594695 as core::ffi::c_int as fe_limb_t,
                        41455196 as core::ffi::c_int as fe_limb_t,
                        12483687 as core::ffi::c_int as fe_limb_t,
                        54440373 as core::ffi::c_int as fe_limb_t,
                        5581305 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        19563141 as core::ffi::c_int as fe_limb_t,
                        16186464 as core::ffi::c_int as fe_limb_t,
                        37722007 as core::ffi::c_int as fe_limb_t,
                        4097518 as core::ffi::c_int as fe_limb_t,
                        10237984 as core::ffi::c_int as fe_limb_t,
                        29206317 as core::ffi::c_int as fe_limb_t,
                        28542349 as core::ffi::c_int as fe_limb_t,
                        13850243 as core::ffi::c_int as fe_limb_t,
                        43430843 as core::ffi::c_int as fe_limb_t,
                        17738489 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        5153727 as core::ffi::c_int as fe_limb_t,
                        9909285 as core::ffi::c_int as fe_limb_t,
                        1723747 as core::ffi::c_int as fe_limb_t,
                        30776558 as core::ffi::c_int as fe_limb_t,
                        30523604 as core::ffi::c_int as fe_limb_t,
                        5516873 as core::ffi::c_int as fe_limb_t,
                        19480852 as core::ffi::c_int as fe_limb_t,
                        5230134 as core::ffi::c_int as fe_limb_t,
                        43156425 as core::ffi::c_int as fe_limb_t,
                        18378665 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        36839857 as core::ffi::c_int as fe_limb_t,
                        30090922 as core::ffi::c_int as fe_limb_t,
                        7665485 as core::ffi::c_int as fe_limb_t,
                        10083793 as core::ffi::c_int as fe_limb_t,
                        28475525 as core::ffi::c_int as fe_limb_t,
                        1649722 as core::ffi::c_int as fe_limb_t,
                        20654025 as core::ffi::c_int as fe_limb_t,
                        16520125 as core::ffi::c_int as fe_limb_t,
                        30598449 as core::ffi::c_int as fe_limb_t,
                        7715701 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        28881826 as core::ffi::c_int as fe_limb_t,
                        14381568 as core::ffi::c_int as fe_limb_t,
                        9657904 as core::ffi::c_int as fe_limb_t,
                        3680757 as core::ffi::c_int as fe_limb_t,
                        46927229 as core::ffi::c_int as fe_limb_t,
                        7843315 as core::ffi::c_int as fe_limb_t,
                        35708204 as core::ffi::c_int as fe_limb_t,
                        1370707 as core::ffi::c_int as fe_limb_t,
                        29794553 as core::ffi::c_int as fe_limb_t,
                        32145132 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        44589871 as core::ffi::c_int as fe_limb_t,
                        26862249 as core::ffi::c_int as fe_limb_t,
                        14201701 as core::ffi::c_int as fe_limb_t,
                        24808930 as core::ffi::c_int as fe_limb_t,
                        43598457 as core::ffi::c_int as fe_limb_t,
                        8844725 as core::ffi::c_int as fe_limb_t,
                        18474211 as core::ffi::c_int as fe_limb_t,
                        32192982 as core::ffi::c_int as fe_limb_t,
                        54046167 as core::ffi::c_int as fe_limb_t,
                        13821876 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        60653668 as core::ffi::c_int as fe_limb_t,
                        25714560 as core::ffi::c_int as fe_limb_t,
                        3374701 as core::ffi::c_int as fe_limb_t,
                        28813570 as core::ffi::c_int as fe_limb_t,
                        40010246 as core::ffi::c_int as fe_limb_t,
                        22982724 as core::ffi::c_int as fe_limb_t,
                        31655027 as core::ffi::c_int as fe_limb_t,
                        26342105 as core::ffi::c_int as fe_limb_t,
                        18853321 as core::ffi::c_int as fe_limb_t,
                        19333481 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        4566811 as core::ffi::c_int as fe_limb_t,
                        20590564 as core::ffi::c_int as fe_limb_t,
                        38133974 as core::ffi::c_int as fe_limb_t,
                        21313742 as core::ffi::c_int as fe_limb_t,
                        59506191 as core::ffi::c_int as fe_limb_t,
                        30723862 as core::ffi::c_int as fe_limb_t,
                        58594505 as core::ffi::c_int as fe_limb_t,
                        23123294 as core::ffi::c_int as fe_limb_t,
                        2207752 as core::ffi::c_int as fe_limb_t,
                        30344648 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        41954014 as core::ffi::c_int as fe_limb_t,
                        29368610 as core::ffi::c_int as fe_limb_t,
                        29681143 as core::ffi::c_int as fe_limb_t,
                        7868801 as core::ffi::c_int as fe_limb_t,
                        60254203 as core::ffi::c_int as fe_limb_t,
                        24130566 as core::ffi::c_int as fe_limb_t,
                        54671499 as core::ffi::c_int as fe_limb_t,
                        32891431 as core::ffi::c_int as fe_limb_t,
                        35997400 as core::ffi::c_int as fe_limb_t,
                        17421995 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        25576264 as core::ffi::c_int as fe_limb_t,
                        30851218 as core::ffi::c_int as fe_limb_t,
                        7349803 as core::ffi::c_int as fe_limb_t,
                        21739588 as core::ffi::c_int as fe_limb_t,
                        16472781 as core::ffi::c_int as fe_limb_t,
                        9300885 as core::ffi::c_int as fe_limb_t,
                        3844789 as core::ffi::c_int as fe_limb_t,
                        15725684 as core::ffi::c_int as fe_limb_t,
                        171356 as core::ffi::c_int as fe_limb_t,
                        6466918 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        23103977 as core::ffi::c_int as fe_limb_t,
                        13316479 as core::ffi::c_int as fe_limb_t,
                        9739013 as core::ffi::c_int as fe_limb_t,
                        17404951 as core::ffi::c_int as fe_limb_t,
                        817874 as core::ffi::c_int as fe_limb_t,
                        18515490 as core::ffi::c_int as fe_limb_t,
                        8965338 as core::ffi::c_int as fe_limb_t,
                        19466374 as core::ffi::c_int as fe_limb_t,
                        36393951 as core::ffi::c_int as fe_limb_t,
                        16193876 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        33587053 as core::ffi::c_int as fe_limb_t,
                        3180712 as core::ffi::c_int as fe_limb_t,
                        64714734 as core::ffi::c_int as fe_limb_t,
                        14003686 as core::ffi::c_int as fe_limb_t,
                        50205390 as core::ffi::c_int as fe_limb_t,
                        17283591 as core::ffi::c_int as fe_limb_t,
                        17238397 as core::ffi::c_int as fe_limb_t,
                        4729455 as core::ffi::c_int as fe_limb_t,
                        49034351 as core::ffi::c_int as fe_limb_t,
                        9256799 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        41926547 as core::ffi::c_int as fe_limb_t,
                        29380300 as core::ffi::c_int as fe_limb_t,
                        32336397 as core::ffi::c_int as fe_limb_t,
                        5036987 as core::ffi::c_int as fe_limb_t,
                        45872047 as core::ffi::c_int as fe_limb_t,
                        11360616 as core::ffi::c_int as fe_limb_t,
                        22616405 as core::ffi::c_int as fe_limb_t,
                        9761698 as core::ffi::c_int as fe_limb_t,
                        47281666 as core::ffi::c_int as fe_limb_t,
                        630304 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        53388152 as core::ffi::c_int as fe_limb_t,
                        2639452 as core::ffi::c_int as fe_limb_t,
                        42871404 as core::ffi::c_int as fe_limb_t,
                        26147950 as core::ffi::c_int as fe_limb_t,
                        9494426 as core::ffi::c_int as fe_limb_t,
                        27780403 as core::ffi::c_int as fe_limb_t,
                        60554312 as core::ffi::c_int as fe_limb_t,
                        17593437 as core::ffi::c_int as fe_limb_t,
                        64659607 as core::ffi::c_int as fe_limb_t,
                        19263131 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
        };
        init
    },
    {
        let mut init = ge_precomp {
            yplusx: {
                let mut init = fe_loose {
                    v: [
                        63957664 as core::ffi::c_int as fe_limb_t,
                        28508356 as core::ffi::c_int as fe_limb_t,
                        9282713 as core::ffi::c_int as fe_limb_t,
                        6866145 as core::ffi::c_int as fe_limb_t,
                        35201802 as core::ffi::c_int as fe_limb_t,
                        32691408 as core::ffi::c_int as fe_limb_t,
                        48168288 as core::ffi::c_int as fe_limb_t,
                        15033783 as core::ffi::c_int as fe_limb_t,
                        25105118 as core::ffi::c_int as fe_limb_t,
                        25659556 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            yminusx: {
                let mut init = fe_loose {
                    v: [
                        42782475 as core::ffi::c_int as fe_limb_t,
                        15950225 as core::ffi::c_int as fe_limb_t,
                        35307649 as core::ffi::c_int as fe_limb_t,
                        18961608 as core::ffi::c_int as fe_limb_t,
                        55446126 as core::ffi::c_int as fe_limb_t,
                        28463506 as core::ffi::c_int as fe_limb_t,
                        1573891 as core::ffi::c_int as fe_limb_t,
                        30928545 as core::ffi::c_int as fe_limb_t,
                        2198789 as core::ffi::c_int as fe_limb_t,
                        17749813 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
            xy2d: {
                let mut init = fe_loose {
                    v: [
                        64009494 as core::ffi::c_int as fe_limb_t,
                        10324966 as core::ffi::c_int as fe_limb_t,
                        64867251 as core::ffi::c_int as fe_limb_t,
                        7453182 as core::ffi::c_int as fe_limb_t,
                        61661885 as core::ffi::c_int as fe_limb_t,
                        30818928 as core::ffi::c_int as fe_limb_t,
                        53296841 as core::ffi::c_int as fe_limb_t,
                        17317989 as core::ffi::c_int as fe_limb_t,
                        34647629 as core::ffi::c_int as fe_limb_t,
                        21263748 as core::ffi::c_int as fe_limb_t,
                    ],
                };
                init
            },
        };
        init
    },
];
#[inline]
unsafe extern "C" fn fiat_25519_value_barrier_u32(mut a: uint32_t) -> uint32_t {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    return a;
}
#[inline]
unsafe extern "C" fn fiat_25519_addcarryx_u26(
    mut out1: *mut uint32_t,
    mut out2: *mut fiat_25519_uint1,
    mut arg1: fiat_25519_uint1,
    mut arg2: uint32_t,
    mut arg3: uint32_t,
) {
    let mut x1: uint32_t = 0;
    let mut x2: uint32_t = 0;
    let mut x3: fiat_25519_uint1 = 0;
    x1 = (arg1 as core::ffi::c_uint)
        .wrapping_add(arg2)
        .wrapping_add(arg3);
    x2 = x1 & 0x3ffffff as core::ffi::c_uint;
    x3 = (x1 >> 26 as core::ffi::c_int) as fiat_25519_uint1;
    *out1 = x2;
    *out2 = x3;
}
#[inline]
unsafe extern "C" fn fiat_25519_subborrowx_u26(
    mut out1: *mut uint32_t,
    mut out2: *mut fiat_25519_uint1,
    mut arg1: fiat_25519_uint1,
    mut arg2: uint32_t,
    mut arg3: uint32_t,
) {
    let mut x1: int32_t = 0;
    let mut x2: fiat_25519_int1 = 0;
    let mut x3: uint32_t = 0;
    x1 = arg2.wrapping_sub(arg1 as core::ffi::c_uint) as int32_t - arg3 as int32_t;
    x2 = (x1 >> 26 as core::ffi::c_int) as fiat_25519_int1;
    x3 = x1 as core::ffi::c_uint & 0x3ffffff as core::ffi::c_uint;
    *out1 = x3;
    *out2 = (0 as core::ffi::c_int - x2 as core::ffi::c_int) as fiat_25519_uint1;
}
#[inline]
unsafe extern "C" fn fiat_25519_addcarryx_u25(
    mut out1: *mut uint32_t,
    mut out2: *mut fiat_25519_uint1,
    mut arg1: fiat_25519_uint1,
    mut arg2: uint32_t,
    mut arg3: uint32_t,
) {
    let mut x1: uint32_t = 0;
    let mut x2: uint32_t = 0;
    let mut x3: fiat_25519_uint1 = 0;
    x1 = (arg1 as core::ffi::c_uint)
        .wrapping_add(arg2)
        .wrapping_add(arg3);
    x2 = x1 & 0x1ffffff as core::ffi::c_uint;
    x3 = (x1 >> 25 as core::ffi::c_int) as fiat_25519_uint1;
    *out1 = x2;
    *out2 = x3;
}
#[inline]
unsafe extern "C" fn fiat_25519_subborrowx_u25(
    mut out1: *mut uint32_t,
    mut out2: *mut fiat_25519_uint1,
    mut arg1: fiat_25519_uint1,
    mut arg2: uint32_t,
    mut arg3: uint32_t,
) {
    let mut x1: int32_t = 0;
    let mut x2: fiat_25519_int1 = 0;
    let mut x3: uint32_t = 0;
    x1 = arg2.wrapping_sub(arg1 as core::ffi::c_uint) as int32_t - arg3 as int32_t;
    x2 = (x1 >> 25 as core::ffi::c_int) as fiat_25519_int1;
    x3 = x1 as core::ffi::c_uint & 0x1ffffff as core::ffi::c_uint;
    *out1 = x3;
    *out2 = (0 as core::ffi::c_int - x2 as core::ffi::c_int) as fiat_25519_uint1;
}
#[inline]
unsafe extern "C" fn fiat_25519_cmovznz_u32(
    mut out1: *mut uint32_t,
    mut arg1: fiat_25519_uint1,
    mut arg2: uint32_t,
    mut arg3: uint32_t,
) {
    let mut x1: fiat_25519_uint1 = 0;
    let mut x2: uint32_t = 0;
    let mut x3: uint32_t = 0;
    x1 = (arg1 != 0) as core::ffi::c_int as fiat_25519_uint1;
    x2 = (0 as core::ffi::c_int - x1 as core::ffi::c_int) as fiat_25519_int1 as core::ffi::c_uint
        & 0xffffffff as core::ffi::c_uint;
    x3 = fiat_25519_value_barrier_u32(x2) & arg3 | fiat_25519_value_barrier_u32(!x2) & arg2;
    *out1 = x3;
}
#[inline]
unsafe extern "C" fn fiat_25519_carry_mul(
    mut out1: *mut uint32_t,
    mut arg1: *const uint32_t,
    mut arg2: *const uint32_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    let mut x6: uint64_t = 0;
    let mut x7: uint64_t = 0;
    let mut x8: uint64_t = 0;
    let mut x9: uint64_t = 0;
    let mut x10: uint64_t = 0;
    let mut x11: uint64_t = 0;
    let mut x12: uint64_t = 0;
    let mut x13: uint64_t = 0;
    let mut x14: uint64_t = 0;
    let mut x15: uint64_t = 0;
    let mut x16: uint64_t = 0;
    let mut x17: uint64_t = 0;
    let mut x18: uint64_t = 0;
    let mut x19: uint64_t = 0;
    let mut x20: uint64_t = 0;
    let mut x21: uint64_t = 0;
    let mut x22: uint64_t = 0;
    let mut x23: uint64_t = 0;
    let mut x24: uint64_t = 0;
    let mut x25: uint64_t = 0;
    let mut x26: uint64_t = 0;
    let mut x27: uint64_t = 0;
    let mut x28: uint64_t = 0;
    let mut x29: uint64_t = 0;
    let mut x30: uint64_t = 0;
    let mut x31: uint64_t = 0;
    let mut x32: uint64_t = 0;
    let mut x33: uint64_t = 0;
    let mut x34: uint64_t = 0;
    let mut x35: uint64_t = 0;
    let mut x36: uint64_t = 0;
    let mut x37: uint64_t = 0;
    let mut x38: uint64_t = 0;
    let mut x39: uint64_t = 0;
    let mut x40: uint64_t = 0;
    let mut x41: uint64_t = 0;
    let mut x42: uint64_t = 0;
    let mut x43: uint64_t = 0;
    let mut x44: uint64_t = 0;
    let mut x45: uint64_t = 0;
    let mut x46: uint64_t = 0;
    let mut x47: uint64_t = 0;
    let mut x48: uint64_t = 0;
    let mut x49: uint64_t = 0;
    let mut x50: uint64_t = 0;
    let mut x51: uint64_t = 0;
    let mut x52: uint64_t = 0;
    let mut x53: uint64_t = 0;
    let mut x54: uint64_t = 0;
    let mut x55: uint64_t = 0;
    let mut x56: uint64_t = 0;
    let mut x57: uint64_t = 0;
    let mut x58: uint64_t = 0;
    let mut x59: uint64_t = 0;
    let mut x60: uint64_t = 0;
    let mut x61: uint64_t = 0;
    let mut x62: uint64_t = 0;
    let mut x63: uint64_t = 0;
    let mut x64: uint64_t = 0;
    let mut x65: uint64_t = 0;
    let mut x66: uint64_t = 0;
    let mut x67: uint64_t = 0;
    let mut x68: uint64_t = 0;
    let mut x69: uint64_t = 0;
    let mut x70: uint64_t = 0;
    let mut x71: uint64_t = 0;
    let mut x72: uint64_t = 0;
    let mut x73: uint64_t = 0;
    let mut x74: uint64_t = 0;
    let mut x75: uint64_t = 0;
    let mut x76: uint64_t = 0;
    let mut x77: uint64_t = 0;
    let mut x78: uint64_t = 0;
    let mut x79: uint64_t = 0;
    let mut x80: uint64_t = 0;
    let mut x81: uint64_t = 0;
    let mut x82: uint64_t = 0;
    let mut x83: uint64_t = 0;
    let mut x84: uint64_t = 0;
    let mut x85: uint64_t = 0;
    let mut x86: uint64_t = 0;
    let mut x87: uint64_t = 0;
    let mut x88: uint64_t = 0;
    let mut x89: uint64_t = 0;
    let mut x90: uint64_t = 0;
    let mut x91: uint64_t = 0;
    let mut x92: uint64_t = 0;
    let mut x93: uint64_t = 0;
    let mut x94: uint64_t = 0;
    let mut x95: uint64_t = 0;
    let mut x96: uint64_t = 0;
    let mut x97: uint64_t = 0;
    let mut x98: uint64_t = 0;
    let mut x99: uint64_t = 0;
    let mut x100: uint64_t = 0;
    let mut x101: uint64_t = 0;
    let mut x102: uint64_t = 0;
    let mut x103: uint32_t = 0;
    let mut x104: uint64_t = 0;
    let mut x105: uint64_t = 0;
    let mut x106: uint64_t = 0;
    let mut x107: uint64_t = 0;
    let mut x108: uint64_t = 0;
    let mut x109: uint64_t = 0;
    let mut x110: uint64_t = 0;
    let mut x111: uint64_t = 0;
    let mut x112: uint64_t = 0;
    let mut x113: uint64_t = 0;
    let mut x114: uint64_t = 0;
    let mut x115: uint32_t = 0;
    let mut x116: uint64_t = 0;
    let mut x117: uint64_t = 0;
    let mut x118: uint32_t = 0;
    let mut x119: uint64_t = 0;
    let mut x120: uint64_t = 0;
    let mut x121: uint32_t = 0;
    let mut x122: uint64_t = 0;
    let mut x123: uint64_t = 0;
    let mut x124: uint32_t = 0;
    let mut x125: uint64_t = 0;
    let mut x126: uint64_t = 0;
    let mut x127: uint32_t = 0;
    let mut x128: uint64_t = 0;
    let mut x129: uint64_t = 0;
    let mut x130: uint32_t = 0;
    let mut x131: uint64_t = 0;
    let mut x132: uint64_t = 0;
    let mut x133: uint32_t = 0;
    let mut x134: uint64_t = 0;
    let mut x135: uint64_t = 0;
    let mut x136: uint32_t = 0;
    let mut x137: uint64_t = 0;
    let mut x138: uint64_t = 0;
    let mut x139: uint32_t = 0;
    let mut x140: uint64_t = 0;
    let mut x141: uint64_t = 0;
    let mut x142: uint32_t = 0;
    let mut x143: uint32_t = 0;
    let mut x144: uint32_t = 0;
    let mut x145: fiat_25519_uint1 = 0;
    let mut x146: uint32_t = 0;
    let mut x147: uint32_t = 0;
    x1 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(9 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x2 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(8 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x3 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(7 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x4 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(6 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x5 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(5 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x6 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(4 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x7 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(3 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x8 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(2 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x9 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(1 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x10 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(9 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x11 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(8 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x12 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(7 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x13 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(6 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x14 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(5 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x15 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(4 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x16 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(3 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x17 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(2 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x18 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(9 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x19 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(8 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x20 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(7 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x21 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(6 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x22 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(5 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x23 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(4 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x24 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(3 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x25 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(9 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x26 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(8 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x27 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(7 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x28 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(6 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x29 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(5 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x30 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(4 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x31 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(9 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x32 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(8 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x33 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(7 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x34 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(6 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x35 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(5 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x36 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(9 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x37 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(8 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x38 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(7 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x39 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(6 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x40 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(9 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x41 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(8 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x42 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(7 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x43 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(9 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x44 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(8 as core::ffi::c_int as isize))
            .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x45 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(9 as core::ffi::c_int as isize))
            .wrapping_mul(0x26 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x46 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x47 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(1 as core::ffi::c_int as isize) as u64);
    x48 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x49 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(2 as core::ffi::c_int as isize) as u64);
    x50 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(1 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x51 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x52 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(3 as core::ffi::c_int as isize) as u64);
    x53 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(2 as core::ffi::c_int as isize) as u64);
    x54 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(1 as core::ffi::c_int as isize) as u64);
    x55 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x56 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(4 as core::ffi::c_int as isize) as u64);
    x57 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(3 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x58 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(2 as core::ffi::c_int as isize) as u64);
    x59 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(1 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x60 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x61 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(5 as core::ffi::c_int as isize) as u64);
    x62 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(4 as core::ffi::c_int as isize) as u64);
    x63 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(3 as core::ffi::c_int as isize) as u64);
    x64 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(2 as core::ffi::c_int as isize) as u64);
    x65 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(1 as core::ffi::c_int as isize) as u64);
    x66 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x67 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(6 as core::ffi::c_int as isize) as u64);
    x68 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(5 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x69 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(4 as core::ffi::c_int as isize) as u64);
    x70 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(3 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x71 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(2 as core::ffi::c_int as isize) as u64);
    x72 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(1 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x73 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x74 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(7 as core::ffi::c_int as isize) as u64);
    x75 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(6 as core::ffi::c_int as isize) as u64);
    x76 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(5 as core::ffi::c_int as isize) as u64);
    x77 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(4 as core::ffi::c_int as isize) as u64);
    x78 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(3 as core::ffi::c_int as isize) as u64);
    x79 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(2 as core::ffi::c_int as isize) as u64);
    x80 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(1 as core::ffi::c_int as isize) as u64);
    x81 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x82 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(8 as core::ffi::c_int as isize) as u64);
    x83 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(7 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x84 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(6 as core::ffi::c_int as isize) as u64);
    x85 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(5 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x86 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(4 as core::ffi::c_int as isize) as u64);
    x87 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(3 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x88 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(2 as core::ffi::c_int as isize) as u64);
    x89 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg2.offset(1 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x90 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x91 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(9 as core::ffi::c_int as isize) as u64);
    x92 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(8 as core::ffi::c_int as isize) as u64);
    x93 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(7 as core::ffi::c_int as isize) as u64);
    x94 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(6 as core::ffi::c_int as isize) as u64);
    x95 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(5 as core::ffi::c_int as isize) as u64);
    x96 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(4 as core::ffi::c_int as isize) as u64);
    x97 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(3 as core::ffi::c_int as isize) as u64);
    x98 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(2 as core::ffi::c_int as isize) as u64);
    x99 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(1 as core::ffi::c_int as isize) as u64);
    x100 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg2.offset(0 as core::ffi::c_int as isize) as u64);
    x101 = x100.wrapping_add(x45.wrapping_add(x44.wrapping_add(x42.wrapping_add(
        x39.wrapping_add(
            x35.wrapping_add(x30.wrapping_add(x24.wrapping_add(x17.wrapping_add(x9)))),
        ),
    ))));
    x102 = x101 >> 26 as core::ffi::c_int;
    x103 = (x101 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x104 = x91.wrapping_add(x82.wrapping_add(x74.wrapping_add(x67.wrapping_add(
        x61.wrapping_add(
            x56.wrapping_add(x52.wrapping_add(x49.wrapping_add(x47.wrapping_add(x46)))),
        ),
    ))));
    x105 = x92.wrapping_add(x83.wrapping_add(x75.wrapping_add(x68.wrapping_add(
        x62.wrapping_add(
            x57.wrapping_add(x53.wrapping_add(x50.wrapping_add(x48.wrapping_add(x1)))),
        ),
    ))));
    x106 = x93.wrapping_add(x84.wrapping_add(x76.wrapping_add(x69.wrapping_add(
        x63.wrapping_add(
            x58.wrapping_add(x54.wrapping_add(x51.wrapping_add(x10.wrapping_add(x2)))),
        ),
    ))));
    x107 = x94.wrapping_add(x85.wrapping_add(x77.wrapping_add(x70.wrapping_add(
        x64.wrapping_add(
            x59.wrapping_add(x55.wrapping_add(x18.wrapping_add(x11.wrapping_add(x3)))),
        ),
    ))));
    x108 = x95.wrapping_add(x86.wrapping_add(x78.wrapping_add(x71.wrapping_add(
        x65.wrapping_add(
            x60.wrapping_add(x25.wrapping_add(x19.wrapping_add(x12.wrapping_add(x4)))),
        ),
    ))));
    x109 = x96.wrapping_add(x87.wrapping_add(x79.wrapping_add(x72.wrapping_add(
        x66.wrapping_add(
            x31.wrapping_add(x26.wrapping_add(x20.wrapping_add(x13.wrapping_add(x5)))),
        ),
    ))));
    x110 = x97.wrapping_add(x88.wrapping_add(x80.wrapping_add(x73.wrapping_add(
        x36.wrapping_add(
            x32.wrapping_add(x27.wrapping_add(x21.wrapping_add(x14.wrapping_add(x6)))),
        ),
    ))));
    x111 = x98.wrapping_add(x89.wrapping_add(x81.wrapping_add(x40.wrapping_add(
        x37.wrapping_add(
            x33.wrapping_add(x28.wrapping_add(x22.wrapping_add(x15.wrapping_add(x7)))),
        ),
    ))));
    x112 = x99.wrapping_add(x90.wrapping_add(x43.wrapping_add(x41.wrapping_add(
        x38.wrapping_add(
            x34.wrapping_add(x29.wrapping_add(x23.wrapping_add(x16.wrapping_add(x8)))),
        ),
    ))));
    x113 = x102.wrapping_add(x112);
    x114 = x113 >> 25 as core::ffi::c_int;
    x115 = (x113 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x116 = x114.wrapping_add(x111);
    x117 = x116 >> 26 as core::ffi::c_int;
    x118 = (x116 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x119 = x117.wrapping_add(x110);
    x120 = x119 >> 25 as core::ffi::c_int;
    x121 = (x119 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x122 = x120.wrapping_add(x109);
    x123 = x122 >> 26 as core::ffi::c_int;
    x124 = (x122 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x125 = x123.wrapping_add(x108);
    x126 = x125 >> 25 as core::ffi::c_int;
    x127 = (x125 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x128 = x126.wrapping_add(x107);
    x129 = x128 >> 26 as core::ffi::c_int;
    x130 = (x128 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x131 = x129.wrapping_add(x106);
    x132 = x131 >> 25 as core::ffi::c_int;
    x133 = (x131 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x134 = x132.wrapping_add(x105);
    x135 = x134 >> 26 as core::ffi::c_int;
    x136 = (x134 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x137 = x135.wrapping_add(x104);
    x138 = x137 >> 25 as core::ffi::c_int;
    x139 = (x137 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x140 = x138.wrapping_mul(0x13 as core::ffi::c_int as u64);
    x141 = (x103 as u64).wrapping_add(x140);
    x142 = (x141 >> 26 as core::ffi::c_int) as uint32_t;
    x143 = (x141 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x144 = x142.wrapping_add(x115);
    x145 = (x144 >> 25 as core::ffi::c_int) as fiat_25519_uint1;
    x146 = x144 & 0x1ffffff as core::ffi::c_uint;
    x147 = (x145 as core::ffi::c_uint).wrapping_add(x118);
    *out1.offset(0 as core::ffi::c_int as isize) = x143;
    *out1.offset(1 as core::ffi::c_int as isize) = x146;
    *out1.offset(2 as core::ffi::c_int as isize) = x147;
    *out1.offset(3 as core::ffi::c_int as isize) = x121;
    *out1.offset(4 as core::ffi::c_int as isize) = x124;
    *out1.offset(5 as core::ffi::c_int as isize) = x127;
    *out1.offset(6 as core::ffi::c_int as isize) = x130;
    *out1.offset(7 as core::ffi::c_int as isize) = x133;
    *out1.offset(8 as core::ffi::c_int as isize) = x136;
    *out1.offset(9 as core::ffi::c_int as isize) = x139;
}
#[inline]
unsafe extern "C" fn fiat_25519_carry_square(mut out1: *mut uint32_t, mut arg1: *const uint32_t) {
    let mut x1: uint32_t = 0;
    let mut x2: uint32_t = 0;
    let mut x3: uint32_t = 0;
    let mut x4: uint32_t = 0;
    let mut x5: uint64_t = 0;
    let mut x6: uint32_t = 0;
    let mut x7: uint32_t = 0;
    let mut x8: uint32_t = 0;
    let mut x9: uint32_t = 0;
    let mut x10: uint32_t = 0;
    let mut x11: uint64_t = 0;
    let mut x12: uint32_t = 0;
    let mut x13: uint32_t = 0;
    let mut x14: uint32_t = 0;
    let mut x15: uint32_t = 0;
    let mut x16: uint32_t = 0;
    let mut x17: uint32_t = 0;
    let mut x18: uint32_t = 0;
    let mut x19: uint64_t = 0;
    let mut x20: uint64_t = 0;
    let mut x21: uint64_t = 0;
    let mut x22: uint64_t = 0;
    let mut x23: uint64_t = 0;
    let mut x24: uint64_t = 0;
    let mut x25: uint64_t = 0;
    let mut x26: uint64_t = 0;
    let mut x27: uint64_t = 0;
    let mut x28: uint64_t = 0;
    let mut x29: uint64_t = 0;
    let mut x30: uint64_t = 0;
    let mut x31: uint64_t = 0;
    let mut x32: uint64_t = 0;
    let mut x33: uint64_t = 0;
    let mut x34: uint64_t = 0;
    let mut x35: uint64_t = 0;
    let mut x36: uint64_t = 0;
    let mut x37: uint64_t = 0;
    let mut x38: uint64_t = 0;
    let mut x39: uint64_t = 0;
    let mut x40: uint64_t = 0;
    let mut x41: uint64_t = 0;
    let mut x42: uint64_t = 0;
    let mut x43: uint64_t = 0;
    let mut x44: uint64_t = 0;
    let mut x45: uint64_t = 0;
    let mut x46: uint64_t = 0;
    let mut x47: uint64_t = 0;
    let mut x48: uint64_t = 0;
    let mut x49: uint64_t = 0;
    let mut x50: uint64_t = 0;
    let mut x51: uint64_t = 0;
    let mut x52: uint64_t = 0;
    let mut x53: uint64_t = 0;
    let mut x54: uint64_t = 0;
    let mut x55: uint64_t = 0;
    let mut x56: uint64_t = 0;
    let mut x57: uint64_t = 0;
    let mut x58: uint64_t = 0;
    let mut x59: uint64_t = 0;
    let mut x60: uint64_t = 0;
    let mut x61: uint64_t = 0;
    let mut x62: uint64_t = 0;
    let mut x63: uint64_t = 0;
    let mut x64: uint64_t = 0;
    let mut x65: uint64_t = 0;
    let mut x66: uint64_t = 0;
    let mut x67: uint64_t = 0;
    let mut x68: uint64_t = 0;
    let mut x69: uint64_t = 0;
    let mut x70: uint64_t = 0;
    let mut x71: uint64_t = 0;
    let mut x72: uint64_t = 0;
    let mut x73: uint64_t = 0;
    let mut x74: uint64_t = 0;
    let mut x75: uint64_t = 0;
    let mut x76: uint32_t = 0;
    let mut x77: uint64_t = 0;
    let mut x78: uint64_t = 0;
    let mut x79: uint64_t = 0;
    let mut x80: uint64_t = 0;
    let mut x81: uint64_t = 0;
    let mut x82: uint64_t = 0;
    let mut x83: uint64_t = 0;
    let mut x84: uint64_t = 0;
    let mut x85: uint64_t = 0;
    let mut x86: uint64_t = 0;
    let mut x87: uint64_t = 0;
    let mut x88: uint32_t = 0;
    let mut x89: uint64_t = 0;
    let mut x90: uint64_t = 0;
    let mut x91: uint32_t = 0;
    let mut x92: uint64_t = 0;
    let mut x93: uint64_t = 0;
    let mut x94: uint32_t = 0;
    let mut x95: uint64_t = 0;
    let mut x96: uint64_t = 0;
    let mut x97: uint32_t = 0;
    let mut x98: uint64_t = 0;
    let mut x99: uint64_t = 0;
    let mut x100: uint32_t = 0;
    let mut x101: uint64_t = 0;
    let mut x102: uint64_t = 0;
    let mut x103: uint32_t = 0;
    let mut x104: uint64_t = 0;
    let mut x105: uint64_t = 0;
    let mut x106: uint32_t = 0;
    let mut x107: uint64_t = 0;
    let mut x108: uint64_t = 0;
    let mut x109: uint32_t = 0;
    let mut x110: uint64_t = 0;
    let mut x111: uint64_t = 0;
    let mut x112: uint32_t = 0;
    let mut x113: uint64_t = 0;
    let mut x114: uint64_t = 0;
    let mut x115: uint32_t = 0;
    let mut x116: uint32_t = 0;
    let mut x117: uint32_t = 0;
    let mut x118: fiat_25519_uint1 = 0;
    let mut x119: uint32_t = 0;
    let mut x120: uint32_t = 0;
    x1 = (*arg1.offset(9 as core::ffi::c_int as isize))
        .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint);
    x2 = x1.wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x3 = (*arg1.offset(9 as core::ffi::c_int as isize))
        .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x4 = (*arg1.offset(8 as core::ffi::c_int as isize))
        .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint);
    x5 = (x4 as uint64_t).wrapping_mul(0x2 as core::ffi::c_int as u64);
    x6 = (*arg1.offset(8 as core::ffi::c_int as isize))
        .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x7 = (*arg1.offset(7 as core::ffi::c_int as isize))
        .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint);
    x8 = x7.wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x9 = (*arg1.offset(7 as core::ffi::c_int as isize))
        .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x10 = (*arg1.offset(6 as core::ffi::c_int as isize))
        .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint);
    x11 = (x10 as uint64_t).wrapping_mul(0x2 as core::ffi::c_int as u64);
    x12 = (*arg1.offset(6 as core::ffi::c_int as isize))
        .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x13 = (*arg1.offset(5 as core::ffi::c_int as isize))
        .wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint);
    x14 = (*arg1.offset(5 as core::ffi::c_int as isize))
        .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x15 = (*arg1.offset(4 as core::ffi::c_int as isize))
        .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x16 = (*arg1.offset(3 as core::ffi::c_int as isize))
        .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x17 = (*arg1.offset(2 as core::ffi::c_int as isize))
        .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x18 = (*arg1.offset(1 as core::ffi::c_int as isize))
        .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint);
    x19 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(x1.wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64);
    x20 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x2 as u64);
    x21 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x4 as u64);
    x22 = (*arg1.offset(7 as core::ffi::c_int as isize) as u64)
        .wrapping_mul((x2 as uint64_t).wrapping_mul(0x2 as core::ffi::c_int as u64));
    x23 = (*arg1.offset(7 as core::ffi::c_int as isize) as u64).wrapping_mul(x5);
    x24 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(x7.wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64);
    x25 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x2 as u64);
    x26 = (*arg1.offset(6 as core::ffi::c_int as isize) as u64).wrapping_mul(x5);
    x27 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x8 as u64);
    x28 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x10 as u64);
    x29 = (*arg1.offset(5 as core::ffi::c_int as isize) as u64)
        .wrapping_mul((x2 as uint64_t).wrapping_mul(0x2 as core::ffi::c_int as u64));
    x30 = (*arg1.offset(5 as core::ffi::c_int as isize) as u64).wrapping_mul(x5);
    x31 = (*arg1.offset(5 as core::ffi::c_int as isize) as u64)
        .wrapping_mul((x8 as uint64_t).wrapping_mul(0x2 as core::ffi::c_int as u64));
    x32 = (*arg1.offset(5 as core::ffi::c_int as isize) as u64).wrapping_mul(x11);
    x33 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(x13.wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64);
    x34 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x2 as u64);
    x35 = (*arg1.offset(4 as core::ffi::c_int as isize) as u64).wrapping_mul(x5);
    x36 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x8 as u64);
    x37 = (*arg1.offset(4 as core::ffi::c_int as isize) as u64).wrapping_mul(x11);
    x38 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x14 as u64);
    x39 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg1.offset(4 as core::ffi::c_int as isize) as u64);
    x40 = (*arg1.offset(3 as core::ffi::c_int as isize) as u64)
        .wrapping_mul((x2 as uint64_t).wrapping_mul(0x2 as core::ffi::c_int as u64));
    x41 = (*arg1.offset(3 as core::ffi::c_int as isize) as u64).wrapping_mul(x5);
    x42 = (*arg1.offset(3 as core::ffi::c_int as isize) as u64)
        .wrapping_mul((x8 as uint64_t).wrapping_mul(0x2 as core::ffi::c_int as u64));
    x43 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x12 as u64);
    x44 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(x14.wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64);
    x45 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x15 as u64);
    x46 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg1.offset(3 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x47 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x2 as u64);
    x48 = (*arg1.offset(2 as core::ffi::c_int as isize) as u64).wrapping_mul(x5);
    x49 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x9 as u64);
    x50 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x12 as u64);
    x51 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x14 as u64);
    x52 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x15 as u64);
    x53 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x16 as u64);
    x54 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg1.offset(2 as core::ffi::c_int as isize) as u64);
    x55 = (*arg1.offset(1 as core::ffi::c_int as isize) as u64)
        .wrapping_mul((x2 as uint64_t).wrapping_mul(0x2 as core::ffi::c_int as u64));
    x56 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x6 as u64);
    x57 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(x9.wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64);
    x58 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x12 as u64);
    x59 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(x14.wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64);
    x60 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x15 as u64);
    x61 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(x16.wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64);
    x62 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x17 as u64);
    x63 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(
        (*arg1.offset(1 as core::ffi::c_int as isize))
            .wrapping_mul(0x2 as core::ffi::c_int as core::ffi::c_uint) as u64,
    );
    x64 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x3 as u64);
    x65 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x6 as u64);
    x66 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x9 as u64);
    x67 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x12 as u64);
    x68 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x14 as u64);
    x69 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x15 as u64);
    x70 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x16 as u64);
    x71 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x17 as u64);
    x72 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t).wrapping_mul(x18 as u64);
    x73 = (*arg1.offset(0 as core::ffi::c_int as isize) as uint64_t)
        .wrapping_mul(*arg1.offset(0 as core::ffi::c_int as isize) as u64);
    x74 = x73
        .wrapping_add(x55.wrapping_add(x48.wrapping_add(x42.wrapping_add(x37.wrapping_add(x33)))));
    x75 = x74 >> 26 as core::ffi::c_int;
    x76 = (x74 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x77 = x64.wrapping_add(x56.wrapping_add(x49.wrapping_add(x43.wrapping_add(x38))));
    x78 = x65
        .wrapping_add(x57.wrapping_add(x50.wrapping_add(x44.wrapping_add(x39.wrapping_add(x19)))));
    x79 = x66.wrapping_add(x58.wrapping_add(x51.wrapping_add(x45.wrapping_add(x20))));
    x80 = x67
        .wrapping_add(x59.wrapping_add(x52.wrapping_add(x46.wrapping_add(x22.wrapping_add(x21)))));
    x81 = x68.wrapping_add(x60.wrapping_add(x53.wrapping_add(x25.wrapping_add(x23))));
    x82 = x69
        .wrapping_add(x61.wrapping_add(x54.wrapping_add(x29.wrapping_add(x26.wrapping_add(x24)))));
    x83 = x70.wrapping_add(x62.wrapping_add(x34.wrapping_add(x30.wrapping_add(x27))));
    x84 = x71
        .wrapping_add(x63.wrapping_add(x40.wrapping_add(x35.wrapping_add(x31.wrapping_add(x28)))));
    x85 = x72.wrapping_add(x47.wrapping_add(x41.wrapping_add(x36.wrapping_add(x32))));
    x86 = x75.wrapping_add(x85);
    x87 = x86 >> 25 as core::ffi::c_int;
    x88 = (x86 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x89 = x87.wrapping_add(x84);
    x90 = x89 >> 26 as core::ffi::c_int;
    x91 = (x89 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x92 = x90.wrapping_add(x83);
    x93 = x92 >> 25 as core::ffi::c_int;
    x94 = (x92 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x95 = x93.wrapping_add(x82);
    x96 = x95 >> 26 as core::ffi::c_int;
    x97 = (x95 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x98 = x96.wrapping_add(x81);
    x99 = x98 >> 25 as core::ffi::c_int;
    x100 = (x98 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x101 = x99.wrapping_add(x80);
    x102 = x101 >> 26 as core::ffi::c_int;
    x103 = (x101 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x104 = x102.wrapping_add(x79);
    x105 = x104 >> 25 as core::ffi::c_int;
    x106 = (x104 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x107 = x105.wrapping_add(x78);
    x108 = x107 >> 26 as core::ffi::c_int;
    x109 = (x107 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x110 = x108.wrapping_add(x77);
    x111 = x110 >> 25 as core::ffi::c_int;
    x112 = (x110 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x113 = x111.wrapping_mul(0x13 as core::ffi::c_int as u64);
    x114 = (x76 as u64).wrapping_add(x113);
    x115 = (x114 >> 26 as core::ffi::c_int) as uint32_t;
    x116 = (x114 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x117 = x115.wrapping_add(x88);
    x118 = (x117 >> 25 as core::ffi::c_int) as fiat_25519_uint1;
    x119 = x117 & 0x1ffffff as core::ffi::c_uint;
    x120 = (x118 as core::ffi::c_uint).wrapping_add(x91);
    *out1.offset(0 as core::ffi::c_int as isize) = x116;
    *out1.offset(1 as core::ffi::c_int as isize) = x119;
    *out1.offset(2 as core::ffi::c_int as isize) = x120;
    *out1.offset(3 as core::ffi::c_int as isize) = x94;
    *out1.offset(4 as core::ffi::c_int as isize) = x97;
    *out1.offset(5 as core::ffi::c_int as isize) = x100;
    *out1.offset(6 as core::ffi::c_int as isize) = x103;
    *out1.offset(7 as core::ffi::c_int as isize) = x106;
    *out1.offset(8 as core::ffi::c_int as isize) = x109;
    *out1.offset(9 as core::ffi::c_int as isize) = x112;
}
#[inline]
unsafe extern "C" fn fiat_25519_carry(mut out1: *mut uint32_t, mut arg1: *const uint32_t) {
    let mut x1: uint32_t = 0;
    let mut x2: uint32_t = 0;
    let mut x3: uint32_t = 0;
    let mut x4: uint32_t = 0;
    let mut x5: uint32_t = 0;
    let mut x6: uint32_t = 0;
    let mut x7: uint32_t = 0;
    let mut x8: uint32_t = 0;
    let mut x9: uint32_t = 0;
    let mut x10: uint32_t = 0;
    let mut x11: uint32_t = 0;
    let mut x12: uint32_t = 0;
    let mut x13: uint32_t = 0;
    let mut x14: uint32_t = 0;
    let mut x15: uint32_t = 0;
    let mut x16: uint32_t = 0;
    let mut x17: uint32_t = 0;
    let mut x18: uint32_t = 0;
    let mut x19: uint32_t = 0;
    let mut x20: uint32_t = 0;
    let mut x21: uint32_t = 0;
    let mut x22: uint32_t = 0;
    x1 = *arg1.offset(0 as core::ffi::c_int as isize);
    x2 = (x1 >> 26 as core::ffi::c_int).wrapping_add(*arg1.offset(1 as core::ffi::c_int as isize));
    x3 = (x2 >> 25 as core::ffi::c_int).wrapping_add(*arg1.offset(2 as core::ffi::c_int as isize));
    x4 = (x3 >> 26 as core::ffi::c_int).wrapping_add(*arg1.offset(3 as core::ffi::c_int as isize));
    x5 = (x4 >> 25 as core::ffi::c_int).wrapping_add(*arg1.offset(4 as core::ffi::c_int as isize));
    x6 = (x5 >> 26 as core::ffi::c_int).wrapping_add(*arg1.offset(5 as core::ffi::c_int as isize));
    x7 = (x6 >> 25 as core::ffi::c_int).wrapping_add(*arg1.offset(6 as core::ffi::c_int as isize));
    x8 = (x7 >> 26 as core::ffi::c_int).wrapping_add(*arg1.offset(7 as core::ffi::c_int as isize));
    x9 = (x8 >> 25 as core::ffi::c_int).wrapping_add(*arg1.offset(8 as core::ffi::c_int as isize));
    x10 = (x9 >> 26 as core::ffi::c_int).wrapping_add(*arg1.offset(9 as core::ffi::c_int as isize));
    x11 = (x1 & 0x3ffffff as core::ffi::c_uint).wrapping_add(
        (x10 >> 25 as core::ffi::c_int).wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint),
    );
    x12 = ((x11 >> 26 as core::ffi::c_int) as fiat_25519_uint1 as core::ffi::c_uint)
        .wrapping_add(x2 & 0x1ffffff as core::ffi::c_uint);
    x13 = x11 & 0x3ffffff as core::ffi::c_uint;
    x14 = x12 & 0x1ffffff as core::ffi::c_uint;
    x15 = ((x12 >> 25 as core::ffi::c_int) as fiat_25519_uint1 as core::ffi::c_uint)
        .wrapping_add(x3 & 0x3ffffff as core::ffi::c_uint);
    x16 = x4 & 0x1ffffff as core::ffi::c_uint;
    x17 = x5 & 0x3ffffff as core::ffi::c_uint;
    x18 = x6 & 0x1ffffff as core::ffi::c_uint;
    x19 = x7 & 0x3ffffff as core::ffi::c_uint;
    x20 = x8 & 0x1ffffff as core::ffi::c_uint;
    x21 = x9 & 0x3ffffff as core::ffi::c_uint;
    x22 = x10 & 0x1ffffff as core::ffi::c_uint;
    *out1.offset(0 as core::ffi::c_int as isize) = x13;
    *out1.offset(1 as core::ffi::c_int as isize) = x14;
    *out1.offset(2 as core::ffi::c_int as isize) = x15;
    *out1.offset(3 as core::ffi::c_int as isize) = x16;
    *out1.offset(4 as core::ffi::c_int as isize) = x17;
    *out1.offset(5 as core::ffi::c_int as isize) = x18;
    *out1.offset(6 as core::ffi::c_int as isize) = x19;
    *out1.offset(7 as core::ffi::c_int as isize) = x20;
    *out1.offset(8 as core::ffi::c_int as isize) = x21;
    *out1.offset(9 as core::ffi::c_int as isize) = x22;
}
#[inline]
unsafe extern "C" fn fiat_25519_add(
    mut out1: *mut uint32_t,
    mut arg1: *const uint32_t,
    mut arg2: *const uint32_t,
) {
    let mut x1: uint32_t = 0;
    let mut x2: uint32_t = 0;
    let mut x3: uint32_t = 0;
    let mut x4: uint32_t = 0;
    let mut x5: uint32_t = 0;
    let mut x6: uint32_t = 0;
    let mut x7: uint32_t = 0;
    let mut x8: uint32_t = 0;
    let mut x9: uint32_t = 0;
    let mut x10: uint32_t = 0;
    x1 = (*arg1.offset(0 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(0 as core::ffi::c_int as isize));
    x2 = (*arg1.offset(1 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(1 as core::ffi::c_int as isize));
    x3 = (*arg1.offset(2 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(2 as core::ffi::c_int as isize));
    x4 = (*arg1.offset(3 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(3 as core::ffi::c_int as isize));
    x5 = (*arg1.offset(4 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(4 as core::ffi::c_int as isize));
    x6 = (*arg1.offset(5 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(5 as core::ffi::c_int as isize));
    x7 = (*arg1.offset(6 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(6 as core::ffi::c_int as isize));
    x8 = (*arg1.offset(7 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(7 as core::ffi::c_int as isize));
    x9 = (*arg1.offset(8 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(8 as core::ffi::c_int as isize));
    x10 = (*arg1.offset(9 as core::ffi::c_int as isize))
        .wrapping_add(*arg2.offset(9 as core::ffi::c_int as isize));
    *out1.offset(0 as core::ffi::c_int as isize) = x1;
    *out1.offset(1 as core::ffi::c_int as isize) = x2;
    *out1.offset(2 as core::ffi::c_int as isize) = x3;
    *out1.offset(3 as core::ffi::c_int as isize) = x4;
    *out1.offset(4 as core::ffi::c_int as isize) = x5;
    *out1.offset(5 as core::ffi::c_int as isize) = x6;
    *out1.offset(6 as core::ffi::c_int as isize) = x7;
    *out1.offset(7 as core::ffi::c_int as isize) = x8;
    *out1.offset(8 as core::ffi::c_int as isize) = x9;
    *out1.offset(9 as core::ffi::c_int as isize) = x10;
}
#[inline]
unsafe extern "C" fn fiat_25519_sub(
    mut out1: *mut uint32_t,
    mut arg1: *const uint32_t,
    mut arg2: *const uint32_t,
) {
    let mut x1: uint32_t = 0;
    let mut x2: uint32_t = 0;
    let mut x3: uint32_t = 0;
    let mut x4: uint32_t = 0;
    let mut x5: uint32_t = 0;
    let mut x6: uint32_t = 0;
    let mut x7: uint32_t = 0;
    let mut x8: uint32_t = 0;
    let mut x9: uint32_t = 0;
    let mut x10: uint32_t = 0;
    x1 = (0x7ffffda as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(0 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(0 as core::ffi::c_int as isize));
    x2 = (0x3fffffe as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(1 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(1 as core::ffi::c_int as isize));
    x3 = (0x7fffffe as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(2 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(2 as core::ffi::c_int as isize));
    x4 = (0x3fffffe as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(3 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(3 as core::ffi::c_int as isize));
    x5 = (0x7fffffe as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(4 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(4 as core::ffi::c_int as isize));
    x6 = (0x3fffffe as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(5 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(5 as core::ffi::c_int as isize));
    x7 = (0x7fffffe as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(6 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(6 as core::ffi::c_int as isize));
    x8 = (0x3fffffe as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(7 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(7 as core::ffi::c_int as isize));
    x9 = (0x7fffffe as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(8 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(8 as core::ffi::c_int as isize));
    x10 = (0x3fffffe as core::ffi::c_uint)
        .wrapping_add(*arg1.offset(9 as core::ffi::c_int as isize))
        .wrapping_sub(*arg2.offset(9 as core::ffi::c_int as isize));
    *out1.offset(0 as core::ffi::c_int as isize) = x1;
    *out1.offset(1 as core::ffi::c_int as isize) = x2;
    *out1.offset(2 as core::ffi::c_int as isize) = x3;
    *out1.offset(3 as core::ffi::c_int as isize) = x4;
    *out1.offset(4 as core::ffi::c_int as isize) = x5;
    *out1.offset(5 as core::ffi::c_int as isize) = x6;
    *out1.offset(6 as core::ffi::c_int as isize) = x7;
    *out1.offset(7 as core::ffi::c_int as isize) = x8;
    *out1.offset(8 as core::ffi::c_int as isize) = x9;
    *out1.offset(9 as core::ffi::c_int as isize) = x10;
}
#[inline]
unsafe extern "C" fn fiat_25519_opp(mut out1: *mut uint32_t, mut arg1: *const uint32_t) {
    let mut x1: uint32_t = 0;
    let mut x2: uint32_t = 0;
    let mut x3: uint32_t = 0;
    let mut x4: uint32_t = 0;
    let mut x5: uint32_t = 0;
    let mut x6: uint32_t = 0;
    let mut x7: uint32_t = 0;
    let mut x8: uint32_t = 0;
    let mut x9: uint32_t = 0;
    let mut x10: uint32_t = 0;
    x1 =
        (0x7ffffda as core::ffi::c_uint).wrapping_sub(*arg1.offset(0 as core::ffi::c_int as isize));
    x2 =
        (0x3fffffe as core::ffi::c_uint).wrapping_sub(*arg1.offset(1 as core::ffi::c_int as isize));
    x3 =
        (0x7fffffe as core::ffi::c_uint).wrapping_sub(*arg1.offset(2 as core::ffi::c_int as isize));
    x4 =
        (0x3fffffe as core::ffi::c_uint).wrapping_sub(*arg1.offset(3 as core::ffi::c_int as isize));
    x5 =
        (0x7fffffe as core::ffi::c_uint).wrapping_sub(*arg1.offset(4 as core::ffi::c_int as isize));
    x6 =
        (0x3fffffe as core::ffi::c_uint).wrapping_sub(*arg1.offset(5 as core::ffi::c_int as isize));
    x7 =
        (0x7fffffe as core::ffi::c_uint).wrapping_sub(*arg1.offset(6 as core::ffi::c_int as isize));
    x8 =
        (0x3fffffe as core::ffi::c_uint).wrapping_sub(*arg1.offset(7 as core::ffi::c_int as isize));
    x9 =
        (0x7fffffe as core::ffi::c_uint).wrapping_sub(*arg1.offset(8 as core::ffi::c_int as isize));
    x10 =
        (0x3fffffe as core::ffi::c_uint).wrapping_sub(*arg1.offset(9 as core::ffi::c_int as isize));
    *out1.offset(0 as core::ffi::c_int as isize) = x1;
    *out1.offset(1 as core::ffi::c_int as isize) = x2;
    *out1.offset(2 as core::ffi::c_int as isize) = x3;
    *out1.offset(3 as core::ffi::c_int as isize) = x4;
    *out1.offset(4 as core::ffi::c_int as isize) = x5;
    *out1.offset(5 as core::ffi::c_int as isize) = x6;
    *out1.offset(6 as core::ffi::c_int as isize) = x7;
    *out1.offset(7 as core::ffi::c_int as isize) = x8;
    *out1.offset(8 as core::ffi::c_int as isize) = x9;
    *out1.offset(9 as core::ffi::c_int as isize) = x10;
}
#[inline]
unsafe extern "C" fn fiat_25519_selectznz(
    mut out1: *mut uint32_t,
    mut arg1: fiat_25519_uint1,
    mut arg2: *const uint32_t,
    mut arg3: *const uint32_t,
) {
    let mut x1: uint32_t = 0;
    let mut x2: uint32_t = 0;
    let mut x3: uint32_t = 0;
    let mut x4: uint32_t = 0;
    let mut x5: uint32_t = 0;
    let mut x6: uint32_t = 0;
    let mut x7: uint32_t = 0;
    let mut x8: uint32_t = 0;
    let mut x9: uint32_t = 0;
    let mut x10: uint32_t = 0;
    fiat_25519_cmovznz_u32(
        &mut x1,
        arg1,
        *arg2.offset(0 as core::ffi::c_int as isize),
        *arg3.offset(0 as core::ffi::c_int as isize),
    );
    fiat_25519_cmovznz_u32(
        &mut x2,
        arg1,
        *arg2.offset(1 as core::ffi::c_int as isize),
        *arg3.offset(1 as core::ffi::c_int as isize),
    );
    fiat_25519_cmovznz_u32(
        &mut x3,
        arg1,
        *arg2.offset(2 as core::ffi::c_int as isize),
        *arg3.offset(2 as core::ffi::c_int as isize),
    );
    fiat_25519_cmovznz_u32(
        &mut x4,
        arg1,
        *arg2.offset(3 as core::ffi::c_int as isize),
        *arg3.offset(3 as core::ffi::c_int as isize),
    );
    fiat_25519_cmovznz_u32(
        &mut x5,
        arg1,
        *arg2.offset(4 as core::ffi::c_int as isize),
        *arg3.offset(4 as core::ffi::c_int as isize),
    );
    fiat_25519_cmovznz_u32(
        &mut x6,
        arg1,
        *arg2.offset(5 as core::ffi::c_int as isize),
        *arg3.offset(5 as core::ffi::c_int as isize),
    );
    fiat_25519_cmovznz_u32(
        &mut x7,
        arg1,
        *arg2.offset(6 as core::ffi::c_int as isize),
        *arg3.offset(6 as core::ffi::c_int as isize),
    );
    fiat_25519_cmovznz_u32(
        &mut x8,
        arg1,
        *arg2.offset(7 as core::ffi::c_int as isize),
        *arg3.offset(7 as core::ffi::c_int as isize),
    );
    fiat_25519_cmovznz_u32(
        &mut x9,
        arg1,
        *arg2.offset(8 as core::ffi::c_int as isize),
        *arg3.offset(8 as core::ffi::c_int as isize),
    );
    fiat_25519_cmovznz_u32(
        &mut x10,
        arg1,
        *arg2.offset(9 as core::ffi::c_int as isize),
        *arg3.offset(9 as core::ffi::c_int as isize),
    );
    *out1.offset(0 as core::ffi::c_int as isize) = x1;
    *out1.offset(1 as core::ffi::c_int as isize) = x2;
    *out1.offset(2 as core::ffi::c_int as isize) = x3;
    *out1.offset(3 as core::ffi::c_int as isize) = x4;
    *out1.offset(4 as core::ffi::c_int as isize) = x5;
    *out1.offset(5 as core::ffi::c_int as isize) = x6;
    *out1.offset(6 as core::ffi::c_int as isize) = x7;
    *out1.offset(7 as core::ffi::c_int as isize) = x8;
    *out1.offset(8 as core::ffi::c_int as isize) = x9;
    *out1.offset(9 as core::ffi::c_int as isize) = x10;
}
#[inline]
unsafe extern "C" fn fiat_25519_to_bytes(mut out1: *mut uint8_t, mut arg1: *const uint32_t) {
    let mut x1: uint32_t = 0;
    let mut x2: fiat_25519_uint1 = 0;
    let mut x3: uint32_t = 0;
    let mut x4: fiat_25519_uint1 = 0;
    let mut x5: uint32_t = 0;
    let mut x6: fiat_25519_uint1 = 0;
    let mut x7: uint32_t = 0;
    let mut x8: fiat_25519_uint1 = 0;
    let mut x9: uint32_t = 0;
    let mut x10: fiat_25519_uint1 = 0;
    let mut x11: uint32_t = 0;
    let mut x12: fiat_25519_uint1 = 0;
    let mut x13: uint32_t = 0;
    let mut x14: fiat_25519_uint1 = 0;
    let mut x15: uint32_t = 0;
    let mut x16: fiat_25519_uint1 = 0;
    let mut x17: uint32_t = 0;
    let mut x18: fiat_25519_uint1 = 0;
    let mut x19: uint32_t = 0;
    let mut x20: fiat_25519_uint1 = 0;
    let mut x21: uint32_t = 0;
    let mut x22: uint32_t = 0;
    let mut x23: fiat_25519_uint1 = 0;
    let mut x24: uint32_t = 0;
    let mut x25: fiat_25519_uint1 = 0;
    let mut x26: uint32_t = 0;
    let mut x27: fiat_25519_uint1 = 0;
    let mut x28: uint32_t = 0;
    let mut x29: fiat_25519_uint1 = 0;
    let mut x30: uint32_t = 0;
    let mut x31: fiat_25519_uint1 = 0;
    let mut x32: uint32_t = 0;
    let mut x33: fiat_25519_uint1 = 0;
    let mut x34: uint32_t = 0;
    let mut x35: fiat_25519_uint1 = 0;
    let mut x36: uint32_t = 0;
    let mut x37: fiat_25519_uint1 = 0;
    let mut x38: uint32_t = 0;
    let mut x39: fiat_25519_uint1 = 0;
    let mut x40: uint32_t = 0;
    let mut x41: fiat_25519_uint1 = 0;
    let mut x42: uint32_t = 0;
    let mut x43: uint32_t = 0;
    let mut x44: uint32_t = 0;
    let mut x45: uint32_t = 0;
    let mut x46: uint32_t = 0;
    let mut x47: uint32_t = 0;
    let mut x48: uint32_t = 0;
    let mut x49: uint32_t = 0;
    let mut x50: uint8_t = 0;
    let mut x51: uint32_t = 0;
    let mut x52: uint8_t = 0;
    let mut x53: uint32_t = 0;
    let mut x54: uint8_t = 0;
    let mut x55: uint8_t = 0;
    let mut x56: uint32_t = 0;
    let mut x57: uint8_t = 0;
    let mut x58: uint32_t = 0;
    let mut x59: uint8_t = 0;
    let mut x60: uint32_t = 0;
    let mut x61: uint8_t = 0;
    let mut x62: uint8_t = 0;
    let mut x63: uint32_t = 0;
    let mut x64: uint8_t = 0;
    let mut x65: uint32_t = 0;
    let mut x66: uint8_t = 0;
    let mut x67: uint32_t = 0;
    let mut x68: uint8_t = 0;
    let mut x69: uint8_t = 0;
    let mut x70: uint32_t = 0;
    let mut x71: uint8_t = 0;
    let mut x72: uint32_t = 0;
    let mut x73: uint8_t = 0;
    let mut x74: uint32_t = 0;
    let mut x75: uint8_t = 0;
    let mut x76: uint8_t = 0;
    let mut x77: uint32_t = 0;
    let mut x78: uint8_t = 0;
    let mut x79: uint32_t = 0;
    let mut x80: uint8_t = 0;
    let mut x81: uint32_t = 0;
    let mut x82: uint8_t = 0;
    let mut x83: uint8_t = 0;
    let mut x84: uint8_t = 0;
    let mut x85: uint32_t = 0;
    let mut x86: uint8_t = 0;
    let mut x87: uint32_t = 0;
    let mut x88: uint8_t = 0;
    let mut x89: fiat_25519_uint1 = 0;
    let mut x90: uint32_t = 0;
    let mut x91: uint8_t = 0;
    let mut x92: uint32_t = 0;
    let mut x93: uint8_t = 0;
    let mut x94: uint32_t = 0;
    let mut x95: uint8_t = 0;
    let mut x96: uint8_t = 0;
    let mut x97: uint32_t = 0;
    let mut x98: uint8_t = 0;
    let mut x99: uint32_t = 0;
    let mut x100: uint8_t = 0;
    let mut x101: uint32_t = 0;
    let mut x102: uint8_t = 0;
    let mut x103: uint8_t = 0;
    let mut x104: uint32_t = 0;
    let mut x105: uint8_t = 0;
    let mut x106: uint32_t = 0;
    let mut x107: uint8_t = 0;
    let mut x108: uint32_t = 0;
    let mut x109: uint8_t = 0;
    let mut x110: uint8_t = 0;
    let mut x111: uint32_t = 0;
    let mut x112: uint8_t = 0;
    let mut x113: uint32_t = 0;
    let mut x114: uint8_t = 0;
    let mut x115: uint32_t = 0;
    let mut x116: uint8_t = 0;
    let mut x117: uint8_t = 0;
    fiat_25519_subborrowx_u26(
        &mut x1,
        &mut x2,
        0 as core::ffi::c_int as fiat_25519_uint1,
        *arg1.offset(0 as core::ffi::c_int as isize),
        0x3ffffed as core::ffi::c_uint,
    );
    fiat_25519_subborrowx_u25(
        &mut x3,
        &mut x4,
        x2,
        *arg1.offset(1 as core::ffi::c_int as isize),
        0x1ffffff as core::ffi::c_uint,
    );
    fiat_25519_subborrowx_u26(
        &mut x5,
        &mut x6,
        x4,
        *arg1.offset(2 as core::ffi::c_int as isize),
        0x3ffffff as core::ffi::c_uint,
    );
    fiat_25519_subborrowx_u25(
        &mut x7,
        &mut x8,
        x6,
        *arg1.offset(3 as core::ffi::c_int as isize),
        0x1ffffff as core::ffi::c_uint,
    );
    fiat_25519_subborrowx_u26(
        &mut x9,
        &mut x10,
        x8,
        *arg1.offset(4 as core::ffi::c_int as isize),
        0x3ffffff as core::ffi::c_uint,
    );
    fiat_25519_subborrowx_u25(
        &mut x11,
        &mut x12,
        x10,
        *arg1.offset(5 as core::ffi::c_int as isize),
        0x1ffffff as core::ffi::c_uint,
    );
    fiat_25519_subborrowx_u26(
        &mut x13,
        &mut x14,
        x12,
        *arg1.offset(6 as core::ffi::c_int as isize),
        0x3ffffff as core::ffi::c_uint,
    );
    fiat_25519_subborrowx_u25(
        &mut x15,
        &mut x16,
        x14,
        *arg1.offset(7 as core::ffi::c_int as isize),
        0x1ffffff as core::ffi::c_uint,
    );
    fiat_25519_subborrowx_u26(
        &mut x17,
        &mut x18,
        x16,
        *arg1.offset(8 as core::ffi::c_int as isize),
        0x3ffffff as core::ffi::c_uint,
    );
    fiat_25519_subborrowx_u25(
        &mut x19,
        &mut x20,
        x18,
        *arg1.offset(9 as core::ffi::c_int as isize),
        0x1ffffff as core::ffi::c_uint,
    );
    fiat_25519_cmovznz_u32(
        &mut x21,
        x20,
        0 as core::ffi::c_int as uint32_t,
        0xffffffff as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u26(
        &mut x22,
        &mut x23,
        0 as core::ffi::c_int as fiat_25519_uint1,
        x1,
        x21 & 0x3ffffed as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u25(
        &mut x24,
        &mut x25,
        x23,
        x3,
        x21 & 0x1ffffff as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u26(
        &mut x26,
        &mut x27,
        x25,
        x5,
        x21 & 0x3ffffff as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u25(
        &mut x28,
        &mut x29,
        x27,
        x7,
        x21 & 0x1ffffff as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u26(
        &mut x30,
        &mut x31,
        x29,
        x9,
        x21 & 0x3ffffff as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u25(
        &mut x32,
        &mut x33,
        x31,
        x11,
        x21 & 0x1ffffff as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u26(
        &mut x34,
        &mut x35,
        x33,
        x13,
        x21 & 0x3ffffff as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u25(
        &mut x36,
        &mut x37,
        x35,
        x15,
        x21 & 0x1ffffff as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u26(
        &mut x38,
        &mut x39,
        x37,
        x17,
        x21 & 0x3ffffff as core::ffi::c_uint,
    );
    fiat_25519_addcarryx_u25(
        &mut x40,
        &mut x41,
        x39,
        x19,
        x21 & 0x1ffffff as core::ffi::c_uint,
    );
    x42 = x40 << 6 as core::ffi::c_int;
    x43 = x38 << 4 as core::ffi::c_int;
    x44 = x36 << 3 as core::ffi::c_int;
    x45 = x34.wrapping_mul(0x2 as core::ffi::c_int as uint32_t);
    x46 = x30 << 6 as core::ffi::c_int;
    x47 = x28 << 5 as core::ffi::c_int;
    x48 = x26 << 3 as core::ffi::c_int;
    x49 = x24 << 2 as core::ffi::c_int;
    x50 = (x22 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x51 = x22 >> 8 as core::ffi::c_int;
    x52 = (x51 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x53 = x51 >> 8 as core::ffi::c_int;
    x54 = (x53 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x55 = (x53 >> 8 as core::ffi::c_int) as uint8_t;
    x56 = x49.wrapping_add(x55 as uint32_t);
    x57 = (x56 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x58 = x56 >> 8 as core::ffi::c_int;
    x59 = (x58 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x60 = x58 >> 8 as core::ffi::c_int;
    x61 = (x60 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x62 = (x60 >> 8 as core::ffi::c_int) as uint8_t;
    x63 = x48.wrapping_add(x62 as uint32_t);
    x64 = (x63 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x65 = x63 >> 8 as core::ffi::c_int;
    x66 = (x65 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x67 = x65 >> 8 as core::ffi::c_int;
    x68 = (x67 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x69 = (x67 >> 8 as core::ffi::c_int) as uint8_t;
    x70 = x47.wrapping_add(x69 as uint32_t);
    x71 = (x70 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x72 = x70 >> 8 as core::ffi::c_int;
    x73 = (x72 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x74 = x72 >> 8 as core::ffi::c_int;
    x75 = (x74 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x76 = (x74 >> 8 as core::ffi::c_int) as uint8_t;
    x77 = x46.wrapping_add(x76 as uint32_t);
    x78 = (x77 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x79 = x77 >> 8 as core::ffi::c_int;
    x80 = (x79 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x81 = x79 >> 8 as core::ffi::c_int;
    x82 = (x81 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x83 = (x81 >> 8 as core::ffi::c_int) as uint8_t;
    x84 = (x32 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x85 = x32 >> 8 as core::ffi::c_int;
    x86 = (x85 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x87 = x85 >> 8 as core::ffi::c_int;
    x88 = (x87 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x89 = (x87 >> 8 as core::ffi::c_int) as fiat_25519_uint1;
    x90 = x45.wrapping_add(x89 as uint32_t);
    x91 = (x90 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x92 = x90 >> 8 as core::ffi::c_int;
    x93 = (x92 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x94 = x92 >> 8 as core::ffi::c_int;
    x95 = (x94 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x96 = (x94 >> 8 as core::ffi::c_int) as uint8_t;
    x97 = x44.wrapping_add(x96 as uint32_t);
    x98 = (x97 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x99 = x97 >> 8 as core::ffi::c_int;
    x100 = (x99 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x101 = x99 >> 8 as core::ffi::c_int;
    x102 = (x101 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x103 = (x101 >> 8 as core::ffi::c_int) as uint8_t;
    x104 = x43.wrapping_add(x103 as uint32_t);
    x105 = (x104 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x106 = x104 >> 8 as core::ffi::c_int;
    x107 = (x106 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x108 = x106 >> 8 as core::ffi::c_int;
    x109 = (x108 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x110 = (x108 >> 8 as core::ffi::c_int) as uint8_t;
    x111 = x42.wrapping_add(x110 as uint32_t);
    x112 = (x111 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x113 = x111 >> 8 as core::ffi::c_int;
    x114 = (x113 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x115 = x113 >> 8 as core::ffi::c_int;
    x116 = (x115 & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
    x117 = (x115 >> 8 as core::ffi::c_int) as uint8_t;
    *out1.offset(0 as core::ffi::c_int as isize) = x50;
    *out1.offset(1 as core::ffi::c_int as isize) = x52;
    *out1.offset(2 as core::ffi::c_int as isize) = x54;
    *out1.offset(3 as core::ffi::c_int as isize) = x57;
    *out1.offset(4 as core::ffi::c_int as isize) = x59;
    *out1.offset(5 as core::ffi::c_int as isize) = x61;
    *out1.offset(6 as core::ffi::c_int as isize) = x64;
    *out1.offset(7 as core::ffi::c_int as isize) = x66;
    *out1.offset(8 as core::ffi::c_int as isize) = x68;
    *out1.offset(9 as core::ffi::c_int as isize) = x71;
    *out1.offset(10 as core::ffi::c_int as isize) = x73;
    *out1.offset(11 as core::ffi::c_int as isize) = x75;
    *out1.offset(12 as core::ffi::c_int as isize) = x78;
    *out1.offset(13 as core::ffi::c_int as isize) = x80;
    *out1.offset(14 as core::ffi::c_int as isize) = x82;
    *out1.offset(15 as core::ffi::c_int as isize) = x83;
    *out1.offset(16 as core::ffi::c_int as isize) = x84;
    *out1.offset(17 as core::ffi::c_int as isize) = x86;
    *out1.offset(18 as core::ffi::c_int as isize) = x88;
    *out1.offset(19 as core::ffi::c_int as isize) = x91;
    *out1.offset(20 as core::ffi::c_int as isize) = x93;
    *out1.offset(21 as core::ffi::c_int as isize) = x95;
    *out1.offset(22 as core::ffi::c_int as isize) = x98;
    *out1.offset(23 as core::ffi::c_int as isize) = x100;
    *out1.offset(24 as core::ffi::c_int as isize) = x102;
    *out1.offset(25 as core::ffi::c_int as isize) = x105;
    *out1.offset(26 as core::ffi::c_int as isize) = x107;
    *out1.offset(27 as core::ffi::c_int as isize) = x109;
    *out1.offset(28 as core::ffi::c_int as isize) = x112;
    *out1.offset(29 as core::ffi::c_int as isize) = x114;
    *out1.offset(30 as core::ffi::c_int as isize) = x116;
    *out1.offset(31 as core::ffi::c_int as isize) = x117;
}
#[inline]
unsafe extern "C" fn fiat_25519_from_bytes(mut out1: *mut uint32_t, mut arg1: *const uint8_t) {
    let mut x1: uint32_t = 0;
    let mut x2: uint32_t = 0;
    let mut x3: uint32_t = 0;
    let mut x4: uint32_t = 0;
    let mut x5: uint32_t = 0;
    let mut x6: uint32_t = 0;
    let mut x7: uint32_t = 0;
    let mut x8: uint32_t = 0;
    let mut x9: uint32_t = 0;
    let mut x10: uint32_t = 0;
    let mut x11: uint32_t = 0;
    let mut x12: uint32_t = 0;
    let mut x13: uint32_t = 0;
    let mut x14: uint32_t = 0;
    let mut x15: uint32_t = 0;
    let mut x16: uint8_t = 0;
    let mut x17: uint32_t = 0;
    let mut x18: uint32_t = 0;
    let mut x19: uint32_t = 0;
    let mut x20: uint32_t = 0;
    let mut x21: uint32_t = 0;
    let mut x22: uint32_t = 0;
    let mut x23: uint32_t = 0;
    let mut x24: uint32_t = 0;
    let mut x25: uint32_t = 0;
    let mut x26: uint32_t = 0;
    let mut x27: uint32_t = 0;
    let mut x28: uint32_t = 0;
    let mut x29: uint32_t = 0;
    let mut x30: uint32_t = 0;
    let mut x31: uint32_t = 0;
    let mut x32: uint8_t = 0;
    let mut x33: uint32_t = 0;
    let mut x34: uint32_t = 0;
    let mut x35: uint32_t = 0;
    let mut x36: uint32_t = 0;
    let mut x37: uint8_t = 0;
    let mut x38: uint32_t = 0;
    let mut x39: uint32_t = 0;
    let mut x40: uint32_t = 0;
    let mut x41: uint32_t = 0;
    let mut x42: uint8_t = 0;
    let mut x43: uint32_t = 0;
    let mut x44: uint32_t = 0;
    let mut x45: uint32_t = 0;
    let mut x46: uint32_t = 0;
    let mut x47: uint8_t = 0;
    let mut x48: uint32_t = 0;
    let mut x49: uint32_t = 0;
    let mut x50: uint32_t = 0;
    let mut x51: uint32_t = 0;
    let mut x52: uint8_t = 0;
    let mut x53: uint32_t = 0;
    let mut x54: uint32_t = 0;
    let mut x55: uint32_t = 0;
    let mut x56: uint32_t = 0;
    let mut x57: uint32_t = 0;
    let mut x58: uint32_t = 0;
    let mut x59: uint32_t = 0;
    let mut x60: uint8_t = 0;
    let mut x61: uint32_t = 0;
    let mut x62: uint32_t = 0;
    let mut x63: uint32_t = 0;
    let mut x64: uint32_t = 0;
    let mut x65: uint8_t = 0;
    let mut x66: uint32_t = 0;
    let mut x67: uint32_t = 0;
    let mut x68: uint32_t = 0;
    let mut x69: uint32_t = 0;
    let mut x70: uint8_t = 0;
    let mut x71: uint32_t = 0;
    let mut x72: uint32_t = 0;
    let mut x73: uint32_t = 0;
    let mut x74: uint32_t = 0;
    let mut x75: uint8_t = 0;
    let mut x76: uint32_t = 0;
    let mut x77: uint32_t = 0;
    let mut x78: uint32_t = 0;
    x1 = (*arg1.offset(31 as core::ffi::c_int as isize) as uint32_t) << 18 as core::ffi::c_int;
    x2 = (*arg1.offset(30 as core::ffi::c_int as isize) as uint32_t) << 10 as core::ffi::c_int;
    x3 = (*arg1.offset(29 as core::ffi::c_int as isize) as uint32_t) << 2 as core::ffi::c_int;
    x4 = (*arg1.offset(28 as core::ffi::c_int as isize) as uint32_t) << 20 as core::ffi::c_int;
    x5 = (*arg1.offset(27 as core::ffi::c_int as isize) as uint32_t) << 12 as core::ffi::c_int;
    x6 = (*arg1.offset(26 as core::ffi::c_int as isize) as uint32_t) << 4 as core::ffi::c_int;
    x7 = (*arg1.offset(25 as core::ffi::c_int as isize) as uint32_t) << 21 as core::ffi::c_int;
    x8 = (*arg1.offset(24 as core::ffi::c_int as isize) as uint32_t) << 13 as core::ffi::c_int;
    x9 = (*arg1.offset(23 as core::ffi::c_int as isize) as uint32_t) << 5 as core::ffi::c_int;
    x10 = (*arg1.offset(22 as core::ffi::c_int as isize) as uint32_t) << 23 as core::ffi::c_int;
    x11 = (*arg1.offset(21 as core::ffi::c_int as isize) as uint32_t) << 15 as core::ffi::c_int;
    x12 = (*arg1.offset(20 as core::ffi::c_int as isize) as uint32_t) << 7 as core::ffi::c_int;
    x13 = (*arg1.offset(19 as core::ffi::c_int as isize) as uint32_t) << 24 as core::ffi::c_int;
    x14 = (*arg1.offset(18 as core::ffi::c_int as isize) as uint32_t) << 16 as core::ffi::c_int;
    x15 = (*arg1.offset(17 as core::ffi::c_int as isize) as uint32_t) << 8 as core::ffi::c_int;
    x16 = *arg1.offset(16 as core::ffi::c_int as isize);
    x17 = (*arg1.offset(15 as core::ffi::c_int as isize) as uint32_t) << 18 as core::ffi::c_int;
    x18 = (*arg1.offset(14 as core::ffi::c_int as isize) as uint32_t) << 10 as core::ffi::c_int;
    x19 = (*arg1.offset(13 as core::ffi::c_int as isize) as uint32_t) << 2 as core::ffi::c_int;
    x20 = (*arg1.offset(12 as core::ffi::c_int as isize) as uint32_t) << 19 as core::ffi::c_int;
    x21 = (*arg1.offset(11 as core::ffi::c_int as isize) as uint32_t) << 11 as core::ffi::c_int;
    x22 = (*arg1.offset(10 as core::ffi::c_int as isize) as uint32_t) << 3 as core::ffi::c_int;
    x23 = (*arg1.offset(9 as core::ffi::c_int as isize) as uint32_t) << 21 as core::ffi::c_int;
    x24 = (*arg1.offset(8 as core::ffi::c_int as isize) as uint32_t) << 13 as core::ffi::c_int;
    x25 = (*arg1.offset(7 as core::ffi::c_int as isize) as uint32_t) << 5 as core::ffi::c_int;
    x26 = (*arg1.offset(6 as core::ffi::c_int as isize) as uint32_t) << 22 as core::ffi::c_int;
    x27 = (*arg1.offset(5 as core::ffi::c_int as isize) as uint32_t) << 14 as core::ffi::c_int;
    x28 = (*arg1.offset(4 as core::ffi::c_int as isize) as uint32_t) << 6 as core::ffi::c_int;
    x29 = (*arg1.offset(3 as core::ffi::c_int as isize) as uint32_t) << 24 as core::ffi::c_int;
    x30 = (*arg1.offset(2 as core::ffi::c_int as isize) as uint32_t) << 16 as core::ffi::c_int;
    x31 = (*arg1.offset(1 as core::ffi::c_int as isize) as uint32_t) << 8 as core::ffi::c_int;
    x32 = *arg1.offset(0 as core::ffi::c_int as isize);
    x33 = x31.wrapping_add(x32 as uint32_t);
    x34 = x30.wrapping_add(x33);
    x35 = x29.wrapping_add(x34);
    x36 = x35 & 0x3ffffff as core::ffi::c_uint;
    x37 = (x35 >> 26 as core::ffi::c_int) as uint8_t;
    x38 = x28.wrapping_add(x37 as uint32_t);
    x39 = x27.wrapping_add(x38);
    x40 = x26.wrapping_add(x39);
    x41 = x40 & 0x1ffffff as core::ffi::c_uint;
    x42 = (x40 >> 25 as core::ffi::c_int) as uint8_t;
    x43 = x25.wrapping_add(x42 as uint32_t);
    x44 = x24.wrapping_add(x43);
    x45 = x23.wrapping_add(x44);
    x46 = x45 & 0x3ffffff as core::ffi::c_uint;
    x47 = (x45 >> 26 as core::ffi::c_int) as uint8_t;
    x48 = x22.wrapping_add(x47 as uint32_t);
    x49 = x21.wrapping_add(x48);
    x50 = x20.wrapping_add(x49);
    x51 = x50 & 0x1ffffff as core::ffi::c_uint;
    x52 = (x50 >> 25 as core::ffi::c_int) as uint8_t;
    x53 = x19.wrapping_add(x52 as uint32_t);
    x54 = x18.wrapping_add(x53);
    x55 = x17.wrapping_add(x54);
    x56 = x15.wrapping_add(x16 as uint32_t);
    x57 = x14.wrapping_add(x56);
    x58 = x13.wrapping_add(x57);
    x59 = x58 & 0x1ffffff as core::ffi::c_uint;
    x60 = (x58 >> 25 as core::ffi::c_int) as uint8_t;
    x61 = x12.wrapping_add(x60 as uint32_t);
    x62 = x11.wrapping_add(x61);
    x63 = x10.wrapping_add(x62);
    x64 = x63 & 0x3ffffff as core::ffi::c_uint;
    x65 = (x63 >> 26 as core::ffi::c_int) as uint8_t;
    x66 = x9.wrapping_add(x65 as uint32_t);
    x67 = x8.wrapping_add(x66);
    x68 = x7.wrapping_add(x67);
    x69 = x68 & 0x1ffffff as core::ffi::c_uint;
    x70 = (x68 >> 25 as core::ffi::c_int) as uint8_t;
    x71 = x6.wrapping_add(x70 as uint32_t);
    x72 = x5.wrapping_add(x71);
    x73 = x4.wrapping_add(x72);
    x74 = x73 & 0x3ffffff as core::ffi::c_uint;
    x75 = (x73 >> 26 as core::ffi::c_int) as uint8_t;
    x76 = x3.wrapping_add(x75 as uint32_t);
    x77 = x2.wrapping_add(x76);
    x78 = x1.wrapping_add(x77);
    *out1.offset(0 as core::ffi::c_int as isize) = x36;
    *out1.offset(1 as core::ffi::c_int as isize) = x41;
    *out1.offset(2 as core::ffi::c_int as isize) = x46;
    *out1.offset(3 as core::ffi::c_int as isize) = x51;
    *out1.offset(4 as core::ffi::c_int as isize) = x55;
    *out1.offset(5 as core::ffi::c_int as isize) = x59;
    *out1.offset(6 as core::ffi::c_int as isize) = x64;
    *out1.offset(7 as core::ffi::c_int as isize) = x69;
    *out1.offset(8 as core::ffi::c_int as isize) = x74;
    *out1.offset(9 as core::ffi::c_int as isize) = x78;
}
#[inline]
unsafe extern "C" fn fiat_25519_carry_scmul_121666(
    mut out1: *mut uint32_t,
    mut arg1: *const uint32_t,
) {
    let mut x1: uint64_t = 0;
    let mut x2: uint64_t = 0;
    let mut x3: uint64_t = 0;
    let mut x4: uint64_t = 0;
    let mut x5: uint64_t = 0;
    let mut x6: uint64_t = 0;
    let mut x7: uint64_t = 0;
    let mut x8: uint64_t = 0;
    let mut x9: uint64_t = 0;
    let mut x10: uint64_t = 0;
    let mut x11: uint32_t = 0;
    let mut x12: uint32_t = 0;
    let mut x13: uint64_t = 0;
    let mut x14: uint32_t = 0;
    let mut x15: uint32_t = 0;
    let mut x16: uint64_t = 0;
    let mut x17: uint32_t = 0;
    let mut x18: uint32_t = 0;
    let mut x19: uint64_t = 0;
    let mut x20: uint32_t = 0;
    let mut x21: uint32_t = 0;
    let mut x22: uint64_t = 0;
    let mut x23: uint32_t = 0;
    let mut x24: uint32_t = 0;
    let mut x25: uint64_t = 0;
    let mut x26: uint32_t = 0;
    let mut x27: uint32_t = 0;
    let mut x28: uint64_t = 0;
    let mut x29: uint32_t = 0;
    let mut x30: uint32_t = 0;
    let mut x31: uint64_t = 0;
    let mut x32: uint32_t = 0;
    let mut x33: uint32_t = 0;
    let mut x34: uint64_t = 0;
    let mut x35: uint32_t = 0;
    let mut x36: uint32_t = 0;
    let mut x37: uint64_t = 0;
    let mut x38: uint32_t = 0;
    let mut x39: uint32_t = 0;
    let mut x40: uint32_t = 0;
    let mut x41: uint32_t = 0;
    let mut x42: fiat_25519_uint1 = 0;
    let mut x43: uint32_t = 0;
    let mut x44: uint32_t = 0;
    let mut x45: fiat_25519_uint1 = 0;
    let mut x46: uint32_t = 0;
    let mut x47: uint32_t = 0;
    x1 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(9 as core::ffi::c_int as isize) as u64);
    x2 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(8 as core::ffi::c_int as isize) as u64);
    x3 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(7 as core::ffi::c_int as isize) as u64);
    x4 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(6 as core::ffi::c_int as isize) as u64);
    x5 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(5 as core::ffi::c_int as isize) as u64);
    x6 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(4 as core::ffi::c_int as isize) as u64);
    x7 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(3 as core::ffi::c_int as isize) as u64);
    x8 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(2 as core::ffi::c_int as isize) as u64);
    x9 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(1 as core::ffi::c_int as isize) as u64);
    x10 = (0x1db42 as core::ffi::c_uint as uint64_t)
        .wrapping_mul(*arg1.offset(0 as core::ffi::c_int as isize) as u64);
    x11 = (x10 >> 26 as core::ffi::c_int) as uint32_t;
    x12 = (x10 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x13 = (x11 as u64).wrapping_add(x9);
    x14 = (x13 >> 25 as core::ffi::c_int) as uint32_t;
    x15 = (x13 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x16 = (x14 as u64).wrapping_add(x8);
    x17 = (x16 >> 26 as core::ffi::c_int) as uint32_t;
    x18 = (x16 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x19 = (x17 as u64).wrapping_add(x7);
    x20 = (x19 >> 25 as core::ffi::c_int) as uint32_t;
    x21 = (x19 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x22 = (x20 as u64).wrapping_add(x6);
    x23 = (x22 >> 26 as core::ffi::c_int) as uint32_t;
    x24 = (x22 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x25 = (x23 as u64).wrapping_add(x5);
    x26 = (x25 >> 25 as core::ffi::c_int) as uint32_t;
    x27 = (x25 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x28 = (x26 as u64).wrapping_add(x4);
    x29 = (x28 >> 26 as core::ffi::c_int) as uint32_t;
    x30 = (x28 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x31 = (x29 as u64).wrapping_add(x3);
    x32 = (x31 >> 25 as core::ffi::c_int) as uint32_t;
    x33 = (x31 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x34 = (x32 as u64).wrapping_add(x2);
    x35 = (x34 >> 26 as core::ffi::c_int) as uint32_t;
    x36 = (x34 & 0x3ffffff as core::ffi::c_uint as u64) as uint32_t;
    x37 = (x35 as u64).wrapping_add(x1);
    x38 = (x37 >> 25 as core::ffi::c_int) as uint32_t;
    x39 = (x37 & 0x1ffffff as core::ffi::c_uint as u64) as uint32_t;
    x40 = x38.wrapping_mul(0x13 as core::ffi::c_int as core::ffi::c_uint);
    x41 = x12.wrapping_add(x40);
    x42 = (x41 >> 26 as core::ffi::c_int) as fiat_25519_uint1;
    x43 = x41 & 0x3ffffff as core::ffi::c_uint;
    x44 = (x42 as core::ffi::c_uint).wrapping_add(x15);
    x45 = (x44 >> 25 as core::ffi::c_int) as fiat_25519_uint1;
    x46 = x44 & 0x1ffffff as core::ffi::c_uint;
    x47 = (x45 as core::ffi::c_uint).wrapping_add(x18);
    *out1.offset(0 as core::ffi::c_int as isize) = x43;
    *out1.offset(1 as core::ffi::c_int as isize) = x46;
    *out1.offset(2 as core::ffi::c_int as isize) = x47;
    *out1.offset(3 as core::ffi::c_int as isize) = x21;
    *out1.offset(4 as core::ffi::c_int as isize) = x24;
    *out1.offset(5 as core::ffi::c_int as isize) = x27;
    *out1.offset(6 as core::ffi::c_int as isize) = x30;
    *out1.offset(7 as core::ffi::c_int as isize) = x33;
    *out1.offset(8 as core::ffi::c_int as isize) = x36;
    *out1.offset(9 as core::ffi::c_int as isize) = x39;
}
unsafe extern "C" fn load_3(mut in_0: *const uint8_t) -> uint64_t {
    let mut result: uint64_t = 0;
    result = *in_0.offset(0 as core::ffi::c_int as isize) as uint64_t;
    result |= (*in_0.offset(1 as core::ffi::c_int as isize) as uint64_t) << 8 as core::ffi::c_int;
    result |= (*in_0.offset(2 as core::ffi::c_int as isize) as uint64_t) << 16 as core::ffi::c_int;
    return result;
}
unsafe extern "C" fn load_4(mut in_0: *const uint8_t) -> uint64_t {
    let mut result: uint64_t = 0;
    result = *in_0.offset(0 as core::ffi::c_int as isize) as uint64_t;
    result |= (*in_0.offset(1 as core::ffi::c_int as isize) as uint64_t) << 8 as core::ffi::c_int;
    result |= (*in_0.offset(2 as core::ffi::c_int as isize) as uint64_t) << 16 as core::ffi::c_int;
    result |= (*in_0.offset(3 as core::ffi::c_int as isize) as uint64_t) << 24 as core::ffi::c_int;
    return result;
}
unsafe extern "C" fn fe_frombytes_strict(mut h: *mut fe, mut s: *const uint8_t) {
    fiat_25519_from_bytes(((*h).v).as_mut_ptr(), s);
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_frombytes(mut h: *mut fe, mut s: *const uint8_t) {
    let mut s_copy: [uint8_t; 32] = [0; 32];
    OPENSSL_memcpy(
        s_copy.as_mut_ptr() as *mut core::ffi::c_void,
        s as *const core::ffi::c_void,
        32 as core::ffi::c_int as size_t,
    );
    s_copy[31 as core::ffi::c_int as usize] = (s_copy[31 as core::ffi::c_int as usize]
        as core::ffi::c_int
        & 0x7f as core::ffi::c_int) as uint8_t;
    fe_frombytes_strict(h, s_copy.as_mut_ptr() as *const uint8_t);
}
unsafe extern "C" fn fe_tobytes(mut s: *mut uint8_t, mut f: *const fe) {
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
    fiat_25519_to_bytes(s, ((*f).v).as_ptr());
}
unsafe extern "C" fn fe_0(mut h: *mut fe) {
    OPENSSL_memset(
        h as *mut core::ffi::c_void,
        0 as core::ffi::c_int,
        core::mem::size_of::<fe>() as u32,
    );
}
unsafe extern "C" fn fe_loose_0(mut h: *mut fe_loose) {
    OPENSSL_memset(
        h as *mut core::ffi::c_void,
        0 as core::ffi::c_int,
        core::mem::size_of::<fe_loose>() as u32,
    );
}
unsafe extern "C" fn fe_1(mut h: *mut fe) {
    OPENSSL_memset(
        h as *mut core::ffi::c_void,
        0 as core::ffi::c_int,
        core::mem::size_of::<fe>() as u32,
    );
    (*h).v[0 as core::ffi::c_int as usize] = 1 as core::ffi::c_int as fe_limb_t;
}
unsafe extern "C" fn fe_loose_1(mut h: *mut fe_loose) {
    OPENSSL_memset(
        h as *mut core::ffi::c_void,
        0 as core::ffi::c_int,
        core::mem::size_of::<fe_loose>() as u32,
    );
    (*h).v[0 as core::ffi::c_int as usize] = 1 as core::ffi::c_int as fe_limb_t;
}
unsafe extern "C" fn fe_add(mut h: *mut fe_loose, mut f: *const fe, mut g: *const fe) {
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
    let mut _assert_fe_i_0: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_0 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
    }
    fiat_25519_add(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
    let mut _assert_fe_i_1: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_1 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_1 = _assert_fe_i_1.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_sub(mut h: *mut fe_loose, mut f: *const fe, mut g: *const fe) {
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
    let mut _assert_fe_i_0: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_0 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
    }
    fiat_25519_sub(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
    let mut _assert_fe_i_1: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_1 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_1 = _assert_fe_i_1.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_carry(mut h: *mut fe, mut f: *const fe_loose) {
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
    fiat_25519_carry(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_0 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_mul_impl(
    mut out: *mut fe_limb_t,
    mut in1: *const fe_limb_t,
    mut in2: *const fe_limb_t,
) {
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
    let mut _assert_fe_i_0: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_0 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
    }
    fiat_25519_carry_mul(out, in1, in2);
    let mut _assert_fe_i_1: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_1 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_1 = _assert_fe_i_1.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_mul_ltt(mut h: *mut fe_loose, mut f: *const fe, mut g: *const fe) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_llt(mut h: *mut fe_loose, mut f: *const fe_loose, mut g: *const fe) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_ttt(mut h: *mut fe, mut f: *const fe, mut g: *const fe) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_tlt(mut h: *mut fe, mut f: *const fe_loose, mut g: *const fe) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_ttl(mut h: *mut fe, mut f: *const fe, mut g: *const fe_loose) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_mul_tll(mut h: *mut fe, mut f: *const fe_loose, mut g: *const fe_loose) {
    fe_mul_impl(((*h).v).as_mut_ptr(), ((*f).v).as_ptr(), ((*g).v).as_ptr());
}
unsafe extern "C" fn fe_sq_tl(mut h: *mut fe, mut f: *const fe_loose) {
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
    fiat_25519_carry_square(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_0 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_sq_tt(mut h: *mut fe, mut f: *const fe) {
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
    fiat_25519_carry_square(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_0 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_cswap(mut f: *mut fe, mut g: *mut fe, mut b: fe_limb_t) {
    b = (0 as core::ffi::c_int as core::ffi::c_uint).wrapping_sub(b);
    let mut i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while i < 10 as core::ffi::c_int as core::ffi::c_uint {
        let mut x: fe_limb_t = (*f).v[i as usize] ^ (*g).v[i as usize];
        x &= b;
        let ref mut fresh0 = (*f).v[i as usize];
        *fresh0 ^= x;
        let ref mut fresh1 = (*g).v[i as usize];
        *fresh1 ^= x;
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_mul121666(mut h: *mut fe, mut f: *const fe_loose) {
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
    fiat_25519_carry_scmul_121666(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_0 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_neg(mut h: *mut fe_loose, mut f: *const fe) {
    let mut _assert_fe_i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i = _assert_fe_i.wrapping_add(1);
    }
    fiat_25519_opp(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
    let mut _assert_fe_i_0: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while _assert_fe_i_0 < 10 as core::ffi::c_int as core::ffi::c_uint {
        _assert_fe_i_0 = _assert_fe_i_0.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_cmov(mut f: *mut fe_loose, mut g: *const fe_loose, mut b: fe_limb_t) {
    b = (0 as core::ffi::c_int as core::ffi::c_uint).wrapping_sub(b);
    let mut i: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    while i < 10 as core::ffi::c_int as core::ffi::c_uint {
        let mut x: fe_limb_t = (*f).v[i as usize] ^ (*g).v[i as usize];
        x &= b;
        let ref mut fresh2 = (*f).v[i as usize];
        *fresh2 ^= x;
        i = i.wrapping_add(1);
    }
}
unsafe extern "C" fn fe_copy(mut h: *mut fe, mut f: *const fe) {
    fe_limbs_copy(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
}
unsafe extern "C" fn fe_copy_lt(mut h: *mut fe_loose, mut f: *const fe) {
    fe_limbs_copy(((*h).v).as_mut_ptr(), ((*f).v).as_ptr());
}
unsafe extern "C" fn fe_loose_invert(mut out: *mut fe, mut z: *const fe_loose) {
    let mut t0: fe = fe { v: [0; 10] };
    let mut t1: fe = fe { v: [0; 10] };
    let mut t2: fe = fe { v: [0; 10] };
    let mut t3: fe = fe { v: [0; 10] };
    let mut i: core::ffi::c_int = 0;
    fe_sq_tl(&mut t0, z);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as core::ffi::c_int;
    while i < 2 as core::ffi::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
    }
    fe_mul_tlt(&mut t1, z, &mut t1);
    fe_mul_ttt(&mut t0, &mut t0, &mut t1);
    fe_sq_tt(&mut t2, &mut t0);
    fe_mul_ttt(&mut t1, &mut t1, &mut t2);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as core::ffi::c_int;
    while i < 5 as core::ffi::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as core::ffi::c_int;
    while i < 10 as core::ffi::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
    }
    fe_mul_ttt(&mut t2, &mut t2, &mut t1);
    fe_sq_tt(&mut t3, &mut t2);
    i = 1 as core::ffi::c_int;
    while i < 20 as core::ffi::c_int {
        fe_sq_tt(&mut t3, &mut t3);
        i += 1;
    }
    fe_mul_ttt(&mut t2, &mut t3, &mut t2);
    fe_sq_tt(&mut t2, &mut t2);
    i = 1 as core::ffi::c_int;
    while i < 10 as core::ffi::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as core::ffi::c_int;
    while i < 50 as core::ffi::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
    }
    fe_mul_ttt(&mut t2, &mut t2, &mut t1);
    fe_sq_tt(&mut t3, &mut t2);
    i = 1 as core::ffi::c_int;
    while i < 100 as core::ffi::c_int {
        fe_sq_tt(&mut t3, &mut t3);
        i += 1;
    }
    fe_mul_ttt(&mut t2, &mut t3, &mut t2);
    fe_sq_tt(&mut t2, &mut t2);
    i = 1 as core::ffi::c_int;
    while i < 50 as core::ffi::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t1, &mut t1);
    i = 1 as core::ffi::c_int;
    while i < 5 as core::ffi::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
    }
    fe_mul_ttt(out, &mut t1, &mut t0);
}
unsafe extern "C" fn fe_invert(mut out: *mut fe, mut z: *const fe) {
    let mut l: fe_loose = fe_loose { v: [0; 10] };
    fe_copy_lt(&mut l, z);
    fe_loose_invert(out, &mut l);
}
unsafe extern "C" fn fe_isnonzero(mut f: *const fe_loose) -> core::ffi::c_int {
    let mut tight: fe = fe { v: [0; 10] };
    fe_carry(&mut tight, f);
    let mut s: [uint8_t; 32] = [0; 32];
    fe_tobytes(s.as_mut_ptr(), &mut tight);
    static mut zero: [uint8_t; 32] = [
        0 as core::ffi::c_int as uint8_t,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    return (CRYPTO_memcmp(
        s.as_mut_ptr() as *const core::ffi::c_void,
        zero.as_ptr() as *const core::ffi::c_void,
        core::mem::size_of::<[uint8_t; 32]>() as u32,
    ) != 0 as core::ffi::c_int) as core::ffi::c_int;
}
unsafe extern "C" fn fe_isnegative(mut f: *const fe) -> core::ffi::c_int {
    let mut s: [uint8_t; 32] = [0; 32];
    fe_tobytes(s.as_mut_ptr(), f);
    return s[0 as core::ffi::c_int as usize] as core::ffi::c_int & 1 as core::ffi::c_int;
}
unsafe extern "C" fn fe_sq2_tt(mut h: *mut fe, mut f: *const fe) {
    fe_sq_tt(h, f);
    let mut tmp: fe_loose = fe_loose { v: [0; 10] };
    fe_add(&mut tmp, h, h);
    fe_carry(h, &mut tmp);
}
unsafe extern "C" fn fe_pow22523(mut out: *mut fe, mut z: *const fe) {
    let mut t0: fe = fe { v: [0; 10] };
    let mut t1: fe = fe { v: [0; 10] };
    let mut t2: fe = fe { v: [0; 10] };
    let mut i: core::ffi::c_int = 0;
    fe_sq_tt(&mut t0, z);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as core::ffi::c_int;
    while i < 2 as core::ffi::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
    }
    fe_mul_ttt(&mut t1, z, &mut t1);
    fe_mul_ttt(&mut t0, &mut t0, &mut t1);
    fe_sq_tt(&mut t0, &mut t0);
    fe_mul_ttt(&mut t0, &mut t1, &mut t0);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as core::ffi::c_int;
    while i < 5 as core::ffi::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
    }
    fe_mul_ttt(&mut t0, &mut t1, &mut t0);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as core::ffi::c_int;
    while i < 10 as core::ffi::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
    }
    fe_mul_ttt(&mut t1, &mut t1, &mut t0);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as core::ffi::c_int;
    while i < 20 as core::ffi::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t1, &mut t1);
    i = 1 as core::ffi::c_int;
    while i < 10 as core::ffi::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
    }
    fe_mul_ttt(&mut t0, &mut t1, &mut t0);
    fe_sq_tt(&mut t1, &mut t0);
    i = 1 as core::ffi::c_int;
    while i < 50 as core::ffi::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
    }
    fe_mul_ttt(&mut t1, &mut t1, &mut t0);
    fe_sq_tt(&mut t2, &mut t1);
    i = 1 as core::ffi::c_int;
    while i < 100 as core::ffi::c_int {
        fe_sq_tt(&mut t2, &mut t2);
        i += 1;
    }
    fe_mul_ttt(&mut t1, &mut t2, &mut t1);
    fe_sq_tt(&mut t1, &mut t1);
    i = 1 as core::ffi::c_int;
    while i < 50 as core::ffi::c_int {
        fe_sq_tt(&mut t1, &mut t1);
        i += 1;
    }
    fe_mul_ttt(&mut t0, &mut t1, &mut t0);
    fe_sq_tt(&mut t0, &mut t0);
    i = 1 as core::ffi::c_int;
    while i < 2 as core::ffi::c_int {
        fe_sq_tt(&mut t0, &mut t0);
        i += 1;
    }
    fe_mul_ttt(out, &mut t0, z);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_frombytes_vartime(
    mut h: *mut ge_p3,
    mut s: *const uint8_t,
) -> core::ffi::c_int {
    let mut u: fe = fe { v: [0; 10] };
    let mut v: fe_loose = fe_loose { v: [0; 10] };
    let mut w: fe = fe { v: [0; 10] };
    let mut vxx: fe = fe { v: [0; 10] };
    let mut check: fe_loose = fe_loose { v: [0; 10] };
    fe_frombytes(&mut (*h).Y, s);
    fe_1(&mut (*h).Z);
    fe_sq_tt(&mut w, &mut (*h).Y);
    fe_mul_ttt(&mut vxx, &mut w, &d);
    fe_sub(&mut v, &mut w, &mut (*h).Z);
    fe_carry(&mut u, &mut v);
    fe_add(&mut v, &mut vxx, &mut (*h).Z);
    fe_mul_ttl(&mut w, &mut u, &mut v);
    fe_pow22523(&mut (*h).X, &mut w);
    fe_mul_ttt(&mut (*h).X, &mut (*h).X, &mut u);
    fe_sq_tt(&mut vxx, &mut (*h).X);
    fe_mul_ttl(&mut vxx, &mut vxx, &mut v);
    fe_sub(&mut check, &mut vxx, &mut u);
    if fe_isnonzero(&mut check) != 0 {
        fe_add(&mut check, &mut vxx, &mut u);
        if fe_isnonzero(&mut check) != 0 {
            return 0 as core::ffi::c_int;
        }
        fe_mul_ttt(&mut (*h).X, &mut (*h).X, &sqrtm1);
    }
    if fe_isnegative(&mut (*h).X)
        != *s.offset(31 as core::ffi::c_int as isize) as core::ffi::c_int >> 7 as core::ffi::c_int
    {
        let mut t: fe_loose = fe_loose { v: [0; 10] };
        fe_neg(&mut t, &mut (*h).X);
        fe_carry(&mut (*h).X, &mut t);
    }
    fe_mul_ttt(&mut (*h).T, &mut (*h).X, &mut (*h).Y);
    return 1 as core::ffi::c_int;
}
unsafe extern "C" fn ge_p2_0(mut h: *mut ge_p2) {
    fe_0(&mut (*h).X);
    fe_1(&mut (*h).Y);
    fe_1(&mut (*h).Z);
}
unsafe extern "C" fn ge_p3_0(mut h: *mut ge_p3) {
    fe_0(&mut (*h).X);
    fe_1(&mut (*h).Y);
    fe_1(&mut (*h).Z);
    fe_0(&mut (*h).T);
}
unsafe extern "C" fn ge_precomp_0(mut h: *mut ge_precomp) {
    fe_loose_1(&mut (*h).yplusx);
    fe_loose_1(&mut (*h).yminusx);
    fe_loose_0(&mut (*h).xy2d);
}
unsafe extern "C" fn ge_p3_to_p2(mut r: *mut ge_p2, mut p: *const ge_p3) {
    fe_copy(&mut (*r).X, &(*p).X);
    fe_copy(&mut (*r).Y, &(*p).Y);
    fe_copy(&mut (*r).Z, &(*p).Z);
}
unsafe extern "C" fn x25519_ge_p3_to_cached(mut r: *mut ge_cached, mut p: *const ge_p3) {
    fe_add(&mut (*r).YplusX, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).YminusX, &(*p).Y, &(*p).X);
    fe_copy_lt(&mut (*r).Z, &(*p).Z);
    fe_mul_ltt(&mut (*r).T2d, &(*p).T, &d2);
}
unsafe extern "C" fn x25519_ge_p1p1_to_p2(mut r: *mut ge_p2, mut p: *const ge_p1p1) {
    fe_mul_tll(&mut (*r).X, &(*p).X, &(*p).T);
    fe_mul_tll(&mut (*r).Y, &(*p).Y, &(*p).Z);
    fe_mul_tll(&mut (*r).Z, &(*p).Z, &(*p).T);
}
unsafe extern "C" fn x25519_ge_p1p1_to_p3(mut r: *mut ge_p3, mut p: *const ge_p1p1) {
    fe_mul_tll(&mut (*r).X, &(*p).X, &(*p).T);
    fe_mul_tll(&mut (*r).Y, &(*p).Y, &(*p).Z);
    fe_mul_tll(&mut (*r).Z, &(*p).Z, &(*p).T);
    fe_mul_tll(&mut (*r).T, &(*p).X, &(*p).Y);
}
unsafe extern "C" fn ge_p2_dbl(mut r: *mut ge_p1p1, mut p: *const ge_p2) {
    let mut trX: fe = fe { v: [0; 10] };
    let mut trZ: fe = fe { v: [0; 10] };
    let mut trT: fe = fe { v: [0; 10] };
    let mut t0: fe = fe { v: [0; 10] };
    fe_sq_tt(&mut trX, &(*p).X);
    fe_sq_tt(&mut trZ, &(*p).Y);
    fe_sq2_tt(&mut trT, &(*p).Z);
    fe_add(&mut (*r).Y, &(*p).X, &(*p).Y);
    fe_sq_tl(&mut t0, &mut (*r).Y);
    fe_add(&mut (*r).Y, &mut trZ, &mut trX);
    fe_sub(&mut (*r).Z, &mut trZ, &mut trX);
    fe_carry(&mut trZ, &mut (*r).Y);
    fe_sub(&mut (*r).X, &mut t0, &mut trZ);
    fe_carry(&mut trZ, &mut (*r).Z);
    fe_sub(&mut (*r).T, &mut trT, &mut trZ);
}
unsafe extern "C" fn ge_p3_dbl(mut r: *mut ge_p1p1, mut p: *const ge_p3) {
    let mut q: ge_p2 = ge_p2 {
        X: fe { v: [0; 10] },
        Y: fe { v: [0; 10] },
        Z: fe { v: [0; 10] },
    };
    ge_p3_to_p2(&mut q, p);
    ge_p2_dbl(r, &mut q);
}
unsafe extern "C" fn ge_madd(mut r: *mut ge_p1p1, mut p: *const ge_p3, mut q: *const ge_precomp) {
    let mut trY: fe = fe { v: [0; 10] };
    let mut trZ: fe = fe { v: [0; 10] };
    let mut trT: fe = fe { v: [0; 10] };
    fe_add(&mut (*r).X, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).Y, &(*p).Y, &(*p).X);
    fe_mul_tll(&mut trZ, &mut (*r).X, &(*q).yplusx);
    fe_mul_tll(&mut trY, &mut (*r).Y, &(*q).yminusx);
    fe_mul_tlt(&mut trT, &(*q).xy2d, &(*p).T);
    fe_add(&mut (*r).T, &(*p).Z, &(*p).Z);
    fe_sub(&mut (*r).X, &mut trZ, &mut trY);
    fe_add(&mut (*r).Y, &mut trZ, &mut trY);
    fe_carry(&mut trZ, &mut (*r).T);
    fe_add(&mut (*r).Z, &mut trZ, &mut trT);
    fe_sub(&mut (*r).T, &mut trZ, &mut trT);
}
unsafe extern "C" fn ge_msub(mut r: *mut ge_p1p1, mut p: *const ge_p3, mut q: *const ge_precomp) {
    let mut trY: fe = fe { v: [0; 10] };
    let mut trZ: fe = fe { v: [0; 10] };
    let mut trT: fe = fe { v: [0; 10] };
    fe_add(&mut (*r).X, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).Y, &(*p).Y, &(*p).X);
    fe_mul_tll(&mut trZ, &mut (*r).X, &(*q).yminusx);
    fe_mul_tll(&mut trY, &mut (*r).Y, &(*q).yplusx);
    fe_mul_tlt(&mut trT, &(*q).xy2d, &(*p).T);
    fe_add(&mut (*r).T, &(*p).Z, &(*p).Z);
    fe_sub(&mut (*r).X, &mut trZ, &mut trY);
    fe_add(&mut (*r).Y, &mut trZ, &mut trY);
    fe_carry(&mut trZ, &mut (*r).T);
    fe_sub(&mut (*r).Z, &mut trZ, &mut trT);
    fe_add(&mut (*r).T, &mut trZ, &mut trT);
}
unsafe extern "C" fn x25519_ge_add(
    mut r: *mut ge_p1p1,
    mut p: *const ge_p3,
    mut q: *const ge_cached,
) {
    let mut trX: fe = fe { v: [0; 10] };
    let mut trY: fe = fe { v: [0; 10] };
    let mut trZ: fe = fe { v: [0; 10] };
    let mut trT: fe = fe { v: [0; 10] };
    fe_add(&mut (*r).X, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).Y, &(*p).Y, &(*p).X);
    fe_mul_tll(&mut trZ, &mut (*r).X, &(*q).YplusX);
    fe_mul_tll(&mut trY, &mut (*r).Y, &(*q).YminusX);
    fe_mul_tlt(&mut trT, &(*q).T2d, &(*p).T);
    fe_mul_ttl(&mut trX, &(*p).Z, &(*q).Z);
    fe_add(&mut (*r).T, &mut trX, &mut trX);
    fe_sub(&mut (*r).X, &mut trZ, &mut trY);
    fe_add(&mut (*r).Y, &mut trZ, &mut trY);
    fe_carry(&mut trZ, &mut (*r).T);
    fe_add(&mut (*r).Z, &mut trZ, &mut trT);
    fe_sub(&mut (*r).T, &mut trZ, &mut trT);
}
unsafe extern "C" fn x25519_ge_sub(
    mut r: *mut ge_p1p1,
    mut p: *const ge_p3,
    mut q: *const ge_cached,
) {
    let mut trX: fe = fe { v: [0; 10] };
    let mut trY: fe = fe { v: [0; 10] };
    let mut trZ: fe = fe { v: [0; 10] };
    let mut trT: fe = fe { v: [0; 10] };
    fe_add(&mut (*r).X, &(*p).Y, &(*p).X);
    fe_sub(&mut (*r).Y, &(*p).Y, &(*p).X);
    fe_mul_tll(&mut trZ, &mut (*r).X, &(*q).YminusX);
    fe_mul_tll(&mut trY, &mut (*r).Y, &(*q).YplusX);
    fe_mul_tlt(&mut trT, &(*q).T2d, &(*p).T);
    fe_mul_ttl(&mut trX, &(*p).Z, &(*q).Z);
    fe_add(&mut (*r).T, &mut trX, &mut trX);
    fe_sub(&mut (*r).X, &mut trZ, &mut trY);
    fe_add(&mut (*r).Y, &mut trZ, &mut trY);
    fe_carry(&mut trZ, &mut (*r).T);
    fe_sub(&mut (*r).Z, &mut trZ, &mut trT);
    fe_add(&mut (*r).T, &mut trZ, &mut trT);
}
unsafe extern "C" fn cmov(mut t: *mut ge_precomp, mut u: *const ge_precomp, mut b: uint8_t) {
    fe_cmov(&mut (*t).yplusx, &(*u).yplusx, b as fe_limb_t);
    fe_cmov(&mut (*t).yminusx, &(*u).yminusx, b as fe_limb_t);
    fe_cmov(&mut (*t).xy2d, &(*u).xy2d, b as fe_limb_t);
}
unsafe extern "C" fn x25519_ge_scalarmult_small_precomp(
    mut h: *mut ge_p3,
    mut a: *const uint8_t,
    mut precomp_table: *const uint8_t,
) {
    let mut multiples: [ge_precomp; 15] = [ge_precomp {
        yplusx: fe_loose { v: [0; 10] },
        yminusx: fe_loose { v: [0; 10] },
        xy2d: fe_loose { v: [0; 10] },
    }; 15];
    let mut i: core::ffi::c_uint = 0;
    i = 0 as core::ffi::c_int as core::ffi::c_uint;
    while i < 15 as core::ffi::c_int as core::ffi::c_uint {
        let mut bytes: *const uint8_t = &*precomp_table.offset(
            i.wrapping_mul((2 as core::ffi::c_int * 32 as core::ffi::c_int) as core::ffi::c_uint)
                as isize,
        ) as *const uint8_t;
        let mut x: fe = fe { v: [0; 10] };
        let mut y: fe = fe { v: [0; 10] };
        fe_frombytes_strict(&mut x, bytes);
        fe_frombytes_strict(&mut y, bytes.offset(32 as core::ffi::c_int as isize));
        let mut out: *mut ge_precomp =
            &mut *multiples.as_mut_ptr().offset(i as isize) as *mut ge_precomp;
        fe_add(&mut (*out).yplusx, &mut y, &mut x);
        fe_sub(&mut (*out).yminusx, &mut y, &mut x);
        fe_mul_ltt(&mut (*out).xy2d, &mut x, &mut y);
        fe_mul_llt(&mut (*out).xy2d, &mut (*out).xy2d, &d2);
        i = i.wrapping_add(1);
    }
    ge_p3_0(h);
    i = 63 as core::ffi::c_int as core::ffi::c_uint;
    while i < 64 as core::ffi::c_int as core::ffi::c_uint {
        let mut j: core::ffi::c_uint = 0;
        let mut index: core::ffi::c_schar = 0 as core::ffi::c_int as core::ffi::c_schar;
        j = 0 as core::ffi::c_int as core::ffi::c_uint;
        while j < 4 as core::ffi::c_int as core::ffi::c_uint {
            let bit: uint8_t = (1 as core::ffi::c_int
                & *a.offset(
                    (8 as core::ffi::c_int as core::ffi::c_uint)
                        .wrapping_mul(j)
                        .wrapping_add(i.wrapping_div(8 as core::ffi::c_int as core::ffi::c_uint))
                        as isize,
                ) as core::ffi::c_int
                    >> (i & 7 as core::ffi::c_int as core::ffi::c_uint))
                as uint8_t;
            index =
                (index as core::ffi::c_int | (bit as core::ffi::c_int) << j) as core::ffi::c_schar;
            j = j.wrapping_add(1);
        }
        let mut e: ge_precomp = ge_precomp {
            yplusx: fe_loose { v: [0; 10] },
            yminusx: fe_loose { v: [0; 10] },
            xy2d: fe_loose { v: [0; 10] },
        };
        ge_precomp_0(&mut e);
        j = 1 as core::ffi::c_int as core::ffi::c_uint;
        while j < 16 as core::ffi::c_int as core::ffi::c_uint {
            cmov(
                &mut e,
                &mut *multiples
                    .as_mut_ptr()
                    .offset(j.wrapping_sub(1 as core::ffi::c_int as core::ffi::c_uint) as isize),
                (1 as core::ffi::c_int as core::ffi::c_uint
                    & constant_time_eq_w(index as crypto_word_t, j)) as uint8_t,
            );
            j = j.wrapping_add(1);
        }
        let mut cached: ge_cached = ge_cached {
            YplusX: fe_loose { v: [0; 10] },
            YminusX: fe_loose { v: [0; 10] },
            Z: fe_loose { v: [0; 10] },
            T2d: fe_loose { v: [0; 10] },
        };
        let mut r: ge_p1p1 = ge_p1p1 {
            X: fe_loose { v: [0; 10] },
            Y: fe_loose { v: [0; 10] },
            Z: fe_loose { v: [0; 10] },
            T: fe_loose { v: [0; 10] },
        };
        x25519_ge_p3_to_cached(&mut cached, h);
        x25519_ge_add(&mut r, h, &mut cached);
        x25519_ge_p1p1_to_p3(h, &mut r);
        ge_madd(&mut r, h, &mut e);
        x25519_ge_p1p1_to_p3(h, &mut r);
        i = i.wrapping_sub(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_scalarmult_base(
    mut h: *mut ge_p3,
    mut a: *const uint8_t,
    mut use_adx: core::ffi::c_int,
) {
    x25519_ge_scalarmult_small_precomp(h, a, k25519SmallPrecomp.as_ptr());
}
unsafe extern "C" fn slide(mut r: *mut core::ffi::c_schar, mut a: *const uint8_t) {
    let mut i: core::ffi::c_int = 0;
    let mut b: core::ffi::c_int = 0;
    let mut k: core::ffi::c_int = 0;
    i = 0 as core::ffi::c_int;
    while i < 256 as core::ffi::c_int {
        *r.offset(i as isize) = (1 as core::ffi::c_int
            & *a.offset((i >> 3 as core::ffi::c_int) as isize) as core::ffi::c_int
                >> (i & 7 as core::ffi::c_int))
            as core::ffi::c_schar;
        i += 1;
    }
    i = 0 as core::ffi::c_int;
    while i < 256 as core::ffi::c_int {
        if *r.offset(i as isize) != 0 {
            b = 1 as core::ffi::c_int;
            while b <= 6 as core::ffi::c_int && i + b < 256 as core::ffi::c_int {
                if *r.offset((i + b) as isize) != 0 {
                    if *r.offset(i as isize) as core::ffi::c_int
                        + ((*r.offset((i + b) as isize) as core::ffi::c_int) << b)
                        <= 15 as core::ffi::c_int
                    {
                        let ref mut fresh3 = *r.offset(i as isize);
                        *fresh3 = (*fresh3 as core::ffi::c_int
                            + ((*r.offset((i + b) as isize) as core::ffi::c_int) << b))
                            as core::ffi::c_schar;
                        *r.offset((i + b) as isize) = 0 as core::ffi::c_int as core::ffi::c_schar;
                    } else {
                        if !(*r.offset(i as isize) as core::ffi::c_int
                            - ((*r.offset((i + b) as isize) as core::ffi::c_int) << b)
                            >= -(15 as core::ffi::c_int))
                        {
                            break;
                        }
                        let ref mut fresh4 = *r.offset(i as isize);
                        *fresh4 = (*fresh4 as core::ffi::c_int
                            - ((*r.offset((i + b) as isize) as core::ffi::c_int) << b))
                            as core::ffi::c_schar;
                        k = i + b;
                        while k < 256 as core::ffi::c_int {
                            if *r.offset(k as isize) == 0 {
                                *r.offset(k as isize) = 1 as core::ffi::c_int as core::ffi::c_schar;
                                break;
                            } else {
                                *r.offset(k as isize) = 0 as core::ffi::c_int as core::ffi::c_schar;
                                k += 1;
                            }
                        }
                    }
                }
                b += 1;
            }
        }
        i += 1;
    }
}
unsafe extern "C" fn ge_double_scalarmult_vartime(
    mut r: *mut ge_p2,
    mut a: *const uint8_t,
    mut A: *const ge_p3,
    mut b: *const uint8_t,
) {
    let mut aslide: [core::ffi::c_schar; 256] = [0; 256];
    let mut bslide: [core::ffi::c_schar; 256] = [0; 256];
    let mut Ai: [ge_cached; 8] = [ge_cached {
        YplusX: fe_loose { v: [0; 10] },
        YminusX: fe_loose { v: [0; 10] },
        Z: fe_loose { v: [0; 10] },
        T2d: fe_loose { v: [0; 10] },
    }; 8];
    let mut t: ge_p1p1 = ge_p1p1 {
        X: fe_loose { v: [0; 10] },
        Y: fe_loose { v: [0; 10] },
        Z: fe_loose { v: [0; 10] },
        T: fe_loose { v: [0; 10] },
    };
    let mut u: ge_p3 = ge_p3 {
        X: fe { v: [0; 10] },
        Y: fe { v: [0; 10] },
        Z: fe { v: [0; 10] },
        T: fe { v: [0; 10] },
    };
    let mut A2: ge_p3 = ge_p3 {
        X: fe { v: [0; 10] },
        Y: fe { v: [0; 10] },
        Z: fe { v: [0; 10] },
        T: fe { v: [0; 10] },
    };
    let mut i: core::ffi::c_int = 0;
    slide(aslide.as_mut_ptr(), a);
    slide(bslide.as_mut_ptr(), b);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(0 as core::ffi::c_int as isize),
        A,
    );
    ge_p3_dbl(&mut t, A);
    x25519_ge_p1p1_to_p3(&mut A2, &mut t);
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(0 as core::ffi::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(1 as core::ffi::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(1 as core::ffi::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(2 as core::ffi::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(2 as core::ffi::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(3 as core::ffi::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(3 as core::ffi::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(4 as core::ffi::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(4 as core::ffi::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(5 as core::ffi::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(5 as core::ffi::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(6 as core::ffi::c_int as isize),
        &mut u,
    );
    x25519_ge_add(
        &mut t,
        &mut A2,
        &mut *Ai.as_mut_ptr().offset(6 as core::ffi::c_int as isize),
    );
    x25519_ge_p1p1_to_p3(&mut u, &mut t);
    x25519_ge_p3_to_cached(
        &mut *Ai.as_mut_ptr().offset(7 as core::ffi::c_int as isize),
        &mut u,
    );
    ge_p2_0(r);
    i = 255 as core::ffi::c_int;
    while i >= 0 as core::ffi::c_int {
        if aslide[i as usize] as core::ffi::c_int != 0
            || bslide[i as usize] as core::ffi::c_int != 0
        {
            break;
        }
        i -= 1;
    }
    while i >= 0 as core::ffi::c_int {
        ge_p2_dbl(&mut t, r);
        if aslide[i as usize] as core::ffi::c_int > 0 as core::ffi::c_int {
            x25519_ge_p1p1_to_p3(&mut u, &mut t);
            x25519_ge_add(
                &mut t,
                &mut u,
                &mut *Ai.as_mut_ptr().offset(
                    (*aslide.as_mut_ptr().offset(i as isize) as core::ffi::c_int
                        / 2 as core::ffi::c_int) as isize,
                ),
            );
        } else if (aslide[i as usize] as core::ffi::c_int) < 0 as core::ffi::c_int {
            x25519_ge_p1p1_to_p3(&mut u, &mut t);
            x25519_ge_sub(
                &mut t,
                &mut u,
                &mut *Ai.as_mut_ptr().offset(
                    (-(*aslide.as_mut_ptr().offset(i as isize) as core::ffi::c_int)
                        / 2 as core::ffi::c_int) as isize,
                ),
            );
        }
        if bslide[i as usize] as core::ffi::c_int > 0 as core::ffi::c_int {
            x25519_ge_p1p1_to_p3(&mut u, &mut t);
            ge_madd(
                &mut t,
                &mut u,
                &*Bi.as_ptr().offset(
                    (*bslide.as_mut_ptr().offset(i as isize) as core::ffi::c_int
                        / 2 as core::ffi::c_int) as isize,
                ),
            );
        } else if (bslide[i as usize] as core::ffi::c_int) < 0 as core::ffi::c_int {
            x25519_ge_p1p1_to_p3(&mut u, &mut t);
            ge_msub(
                &mut t,
                &mut u,
                &*Bi.as_ptr().offset(
                    (-(*bslide.as_mut_ptr().offset(i as isize) as core::ffi::c_int)
                        / 2 as core::ffi::c_int) as isize,
                ),
            );
        }
        x25519_ge_p1p1_to_p2(r, &mut t);
        i -= 1;
    }
}
#[inline]
unsafe extern "C" fn int64_lshift21(mut a: int64_t) -> int64_t {
    return ((a as uint64_t) << 21 as core::ffi::c_int) as int64_t;
}
#[no_mangle]
pub unsafe extern "C" fn x25519_sc_reduce(mut s: *mut uint8_t) {
    let mut s0: int64_t =
        (2097151 as core::ffi::c_int as u64 & load_3(s as *const uint8_t)) as int64_t;
    let mut s1: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(2 as core::ffi::c_int as isize) as *const uint8_t)
            >> 5 as core::ffi::c_int) as int64_t;
    let mut s2: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(5 as core::ffi::c_int as isize) as *const uint8_t)
            >> 2 as core::ffi::c_int) as int64_t;
    let mut s3: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(7 as core::ffi::c_int as isize) as *const uint8_t)
            >> 7 as core::ffi::c_int) as int64_t;
    let mut s4: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(10 as core::ffi::c_int as isize) as *const uint8_t)
            >> 4 as core::ffi::c_int) as int64_t;
    let mut s5: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(13 as core::ffi::c_int as isize) as *const uint8_t)
            >> 1 as core::ffi::c_int) as int64_t;
    let mut s6: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(15 as core::ffi::c_int as isize) as *const uint8_t)
            >> 6 as core::ffi::c_int) as int64_t;
    let mut s7: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(18 as core::ffi::c_int as isize) as *const uint8_t)
            >> 3 as core::ffi::c_int) as int64_t;
    let mut s8: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(21 as core::ffi::c_int as isize) as *const uint8_t))
        as int64_t;
    let mut s9: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(23 as core::ffi::c_int as isize) as *const uint8_t)
            >> 5 as core::ffi::c_int) as int64_t;
    let mut s10: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(26 as core::ffi::c_int as isize) as *const uint8_t)
            >> 2 as core::ffi::c_int) as int64_t;
    let mut s11: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(28 as core::ffi::c_int as isize) as *const uint8_t)
            >> 7 as core::ffi::c_int) as int64_t;
    let mut s12: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(31 as core::ffi::c_int as isize) as *const uint8_t)
            >> 4 as core::ffi::c_int) as int64_t;
    let mut s13: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(34 as core::ffi::c_int as isize) as *const uint8_t)
            >> 1 as core::ffi::c_int) as int64_t;
    let mut s14: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(36 as core::ffi::c_int as isize) as *const uint8_t)
            >> 6 as core::ffi::c_int) as int64_t;
    let mut s15: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(39 as core::ffi::c_int as isize) as *const uint8_t)
            >> 3 as core::ffi::c_int) as int64_t;
    let mut s16: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(42 as core::ffi::c_int as isize) as *const uint8_t))
        as int64_t;
    let mut s17: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(44 as core::ffi::c_int as isize) as *const uint8_t)
            >> 5 as core::ffi::c_int) as int64_t;
    let mut s18: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(47 as core::ffi::c_int as isize) as *const uint8_t)
            >> 2 as core::ffi::c_int) as int64_t;
    let mut s19: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(49 as core::ffi::c_int as isize) as *const uint8_t)
            >> 7 as core::ffi::c_int) as int64_t;
    let mut s20: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(52 as core::ffi::c_int as isize) as *const uint8_t)
            >> 4 as core::ffi::c_int) as int64_t;
    let mut s21: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(s.offset(55 as core::ffi::c_int as isize) as *const uint8_t)
            >> 1 as core::ffi::c_int) as int64_t;
    let mut s22: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(s.offset(57 as core::ffi::c_int as isize) as *const uint8_t)
            >> 6 as core::ffi::c_int) as int64_t;
    let mut s23: int64_t = (load_4(s.offset(60 as core::ffi::c_int as isize) as *const uint8_t)
        >> 3 as core::ffi::c_int) as int64_t;
    let mut carry0: int64_t = 0;
    let mut carry1: int64_t = 0;
    let mut carry2: int64_t = 0;
    let mut carry3: int64_t = 0;
    let mut carry4: int64_t = 0;
    let mut carry5: int64_t = 0;
    let mut carry6: int64_t = 0;
    let mut carry7: int64_t = 0;
    let mut carry8: int64_t = 0;
    let mut carry9: int64_t = 0;
    let mut carry10: int64_t = 0;
    let mut carry11: int64_t = 0;
    let mut carry12: int64_t = 0;
    let mut carry13: int64_t = 0;
    let mut carry14: int64_t = 0;
    let mut carry15: int64_t = 0;
    let mut carry16: int64_t = 0;
    s11 += s23 * 666643 as core::ffi::c_int as i64;
    s12 += s23 * 470296 as core::ffi::c_int as i64;
    s13 += s23 * 654183 as core::ffi::c_int as i64;
    s14 -= s23 * 997805 as core::ffi::c_int as i64;
    s15 += s23 * 136657 as core::ffi::c_int as i64;
    s16 -= s23 * 683901 as core::ffi::c_int as i64;
    s23 = 0 as core::ffi::c_int as int64_t;
    s10 += s22 * 666643 as core::ffi::c_int as i64;
    s11 += s22 * 470296 as core::ffi::c_int as i64;
    s12 += s22 * 654183 as core::ffi::c_int as i64;
    s13 -= s22 * 997805 as core::ffi::c_int as i64;
    s14 += s22 * 136657 as core::ffi::c_int as i64;
    s15 -= s22 * 683901 as core::ffi::c_int as i64;
    s22 = 0 as core::ffi::c_int as int64_t;
    s9 += s21 * 666643 as core::ffi::c_int as i64;
    s10 += s21 * 470296 as core::ffi::c_int as i64;
    s11 += s21 * 654183 as core::ffi::c_int as i64;
    s12 -= s21 * 997805 as core::ffi::c_int as i64;
    s13 += s21 * 136657 as core::ffi::c_int as i64;
    s14 -= s21 * 683901 as core::ffi::c_int as i64;
    s21 = 0 as core::ffi::c_int as int64_t;
    s8 += s20 * 666643 as core::ffi::c_int as i64;
    s9 += s20 * 470296 as core::ffi::c_int as i64;
    s10 += s20 * 654183 as core::ffi::c_int as i64;
    s11 -= s20 * 997805 as core::ffi::c_int as i64;
    s12 += s20 * 136657 as core::ffi::c_int as i64;
    s13 -= s20 * 683901 as core::ffi::c_int as i64;
    s20 = 0 as core::ffi::c_int as int64_t;
    s7 += s19 * 666643 as core::ffi::c_int as i64;
    s8 += s19 * 470296 as core::ffi::c_int as i64;
    s9 += s19 * 654183 as core::ffi::c_int as i64;
    s10 -= s19 * 997805 as core::ffi::c_int as i64;
    s11 += s19 * 136657 as core::ffi::c_int as i64;
    s12 -= s19 * 683901 as core::ffi::c_int as i64;
    s19 = 0 as core::ffi::c_int as int64_t;
    s6 += s18 * 666643 as core::ffi::c_int as i64;
    s7 += s18 * 470296 as core::ffi::c_int as i64;
    s8 += s18 * 654183 as core::ffi::c_int as i64;
    s9 -= s18 * 997805 as core::ffi::c_int as i64;
    s10 += s18 * 136657 as core::ffi::c_int as i64;
    s11 -= s18 * 683901 as core::ffi::c_int as i64;
    s18 = 0 as core::ffi::c_int as int64_t;
    carry6 =
        s6 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 =
        s8 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 =
        s10 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 =
        s12 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 =
        s14 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 =
        s16 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);
    carry7 =
        s7 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 =
        s9 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 =
        s11 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 =
        s13 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 =
        s15 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);
    s5 += s17 * 666643 as core::ffi::c_int as i64;
    s6 += s17 * 470296 as core::ffi::c_int as i64;
    s7 += s17 * 654183 as core::ffi::c_int as i64;
    s8 -= s17 * 997805 as core::ffi::c_int as i64;
    s9 += s17 * 136657 as core::ffi::c_int as i64;
    s10 -= s17 * 683901 as core::ffi::c_int as i64;
    s17 = 0 as core::ffi::c_int as int64_t;
    s4 += s16 * 666643 as core::ffi::c_int as i64;
    s5 += s16 * 470296 as core::ffi::c_int as i64;
    s6 += s16 * 654183 as core::ffi::c_int as i64;
    s7 -= s16 * 997805 as core::ffi::c_int as i64;
    s8 += s16 * 136657 as core::ffi::c_int as i64;
    s9 -= s16 * 683901 as core::ffi::c_int as i64;
    s16 = 0 as core::ffi::c_int as int64_t;
    s3 += s15 * 666643 as core::ffi::c_int as i64;
    s4 += s15 * 470296 as core::ffi::c_int as i64;
    s5 += s15 * 654183 as core::ffi::c_int as i64;
    s6 -= s15 * 997805 as core::ffi::c_int as i64;
    s7 += s15 * 136657 as core::ffi::c_int as i64;
    s8 -= s15 * 683901 as core::ffi::c_int as i64;
    s15 = 0 as core::ffi::c_int as int64_t;
    s2 += s14 * 666643 as core::ffi::c_int as i64;
    s3 += s14 * 470296 as core::ffi::c_int as i64;
    s4 += s14 * 654183 as core::ffi::c_int as i64;
    s5 -= s14 * 997805 as core::ffi::c_int as i64;
    s6 += s14 * 136657 as core::ffi::c_int as i64;
    s7 -= s14 * 683901 as core::ffi::c_int as i64;
    s14 = 0 as core::ffi::c_int as int64_t;
    s1 += s13 * 666643 as core::ffi::c_int as i64;
    s2 += s13 * 470296 as core::ffi::c_int as i64;
    s3 += s13 * 654183 as core::ffi::c_int as i64;
    s4 -= s13 * 997805 as core::ffi::c_int as i64;
    s5 += s13 * 136657 as core::ffi::c_int as i64;
    s6 -= s13 * 683901 as core::ffi::c_int as i64;
    s13 = 0 as core::ffi::c_int as int64_t;
    s0 += s12 * 666643 as core::ffi::c_int as i64;
    s1 += s12 * 470296 as core::ffi::c_int as i64;
    s2 += s12 * 654183 as core::ffi::c_int as i64;
    s3 -= s12 * 997805 as core::ffi::c_int as i64;
    s4 += s12 * 136657 as core::ffi::c_int as i64;
    s5 -= s12 * 683901 as core::ffi::c_int as i64;
    s12 = 0 as core::ffi::c_int as int64_t;
    carry0 =
        s0 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 =
        s2 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 =
        s4 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 =
        s6 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 =
        s8 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 =
        s10 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry1 =
        s1 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 =
        s3 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 =
        s5 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 =
        s7 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 =
        s9 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 =
        s11 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    s0 += s12 * 666643 as core::ffi::c_int as i64;
    s1 += s12 * 470296 as core::ffi::c_int as i64;
    s2 += s12 * 654183 as core::ffi::c_int as i64;
    s3 -= s12 * 997805 as core::ffi::c_int as i64;
    s4 += s12 * 136657 as core::ffi::c_int as i64;
    s5 -= s12 * 683901 as core::ffi::c_int as i64;
    s12 = 0 as core::ffi::c_int as int64_t;
    carry0 = s0 >> 21 as core::ffi::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21 as core::ffi::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21 as core::ffi::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21 as core::ffi::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21 as core::ffi::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21 as core::ffi::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21 as core::ffi::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21 as core::ffi::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21 as core::ffi::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21 as core::ffi::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21 as core::ffi::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry11 = s11 >> 21 as core::ffi::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    s0 += s12 * 666643 as core::ffi::c_int as i64;
    s1 += s12 * 470296 as core::ffi::c_int as i64;
    s2 += s12 * 654183 as core::ffi::c_int as i64;
    s3 -= s12 * 997805 as core::ffi::c_int as i64;
    s4 += s12 * 136657 as core::ffi::c_int as i64;
    s5 -= s12 * 683901 as core::ffi::c_int as i64;
    s12 = 0 as core::ffi::c_int as int64_t;
    carry0 = s0 >> 21 as core::ffi::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21 as core::ffi::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21 as core::ffi::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21 as core::ffi::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21 as core::ffi::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21 as core::ffi::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21 as core::ffi::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21 as core::ffi::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21 as core::ffi::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21 as core::ffi::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21 as core::ffi::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    *s.offset(0 as core::ffi::c_int as isize) = (s0 >> 0 as core::ffi::c_int) as uint8_t;
    *s.offset(1 as core::ffi::c_int as isize) = (s0 >> 8 as core::ffi::c_int) as uint8_t;
    *s.offset(2 as core::ffi::c_int as isize) =
        (s0 >> 16 as core::ffi::c_int | s1 << 5 as core::ffi::c_int) as uint8_t;
    *s.offset(3 as core::ffi::c_int as isize) = (s1 >> 3 as core::ffi::c_int) as uint8_t;
    *s.offset(4 as core::ffi::c_int as isize) = (s1 >> 11 as core::ffi::c_int) as uint8_t;
    *s.offset(5 as core::ffi::c_int as isize) =
        (s1 >> 19 as core::ffi::c_int | s2 << 2 as core::ffi::c_int) as uint8_t;
    *s.offset(6 as core::ffi::c_int as isize) = (s2 >> 6 as core::ffi::c_int) as uint8_t;
    *s.offset(7 as core::ffi::c_int as isize) =
        (s2 >> 14 as core::ffi::c_int | s3 << 7 as core::ffi::c_int) as uint8_t;
    *s.offset(8 as core::ffi::c_int as isize) = (s3 >> 1 as core::ffi::c_int) as uint8_t;
    *s.offset(9 as core::ffi::c_int as isize) = (s3 >> 9 as core::ffi::c_int) as uint8_t;
    *s.offset(10 as core::ffi::c_int as isize) =
        (s3 >> 17 as core::ffi::c_int | s4 << 4 as core::ffi::c_int) as uint8_t;
    *s.offset(11 as core::ffi::c_int as isize) = (s4 >> 4 as core::ffi::c_int) as uint8_t;
    *s.offset(12 as core::ffi::c_int as isize) = (s4 >> 12 as core::ffi::c_int) as uint8_t;
    *s.offset(13 as core::ffi::c_int as isize) =
        (s4 >> 20 as core::ffi::c_int | s5 << 1 as core::ffi::c_int) as uint8_t;
    *s.offset(14 as core::ffi::c_int as isize) = (s5 >> 7 as core::ffi::c_int) as uint8_t;
    *s.offset(15 as core::ffi::c_int as isize) =
        (s5 >> 15 as core::ffi::c_int | s6 << 6 as core::ffi::c_int) as uint8_t;
    *s.offset(16 as core::ffi::c_int as isize) = (s6 >> 2 as core::ffi::c_int) as uint8_t;
    *s.offset(17 as core::ffi::c_int as isize) = (s6 >> 10 as core::ffi::c_int) as uint8_t;
    *s.offset(18 as core::ffi::c_int as isize) =
        (s6 >> 18 as core::ffi::c_int | s7 << 3 as core::ffi::c_int) as uint8_t;
    *s.offset(19 as core::ffi::c_int as isize) = (s7 >> 5 as core::ffi::c_int) as uint8_t;
    *s.offset(20 as core::ffi::c_int as isize) = (s7 >> 13 as core::ffi::c_int) as uint8_t;
    *s.offset(21 as core::ffi::c_int as isize) = (s8 >> 0 as core::ffi::c_int) as uint8_t;
    *s.offset(22 as core::ffi::c_int as isize) = (s8 >> 8 as core::ffi::c_int) as uint8_t;
    *s.offset(23 as core::ffi::c_int as isize) =
        (s8 >> 16 as core::ffi::c_int | s9 << 5 as core::ffi::c_int) as uint8_t;
    *s.offset(24 as core::ffi::c_int as isize) = (s9 >> 3 as core::ffi::c_int) as uint8_t;
    *s.offset(25 as core::ffi::c_int as isize) = (s9 >> 11 as core::ffi::c_int) as uint8_t;
    *s.offset(26 as core::ffi::c_int as isize) =
        (s9 >> 19 as core::ffi::c_int | s10 << 2 as core::ffi::c_int) as uint8_t;
    *s.offset(27 as core::ffi::c_int as isize) = (s10 >> 6 as core::ffi::c_int) as uint8_t;
    *s.offset(28 as core::ffi::c_int as isize) =
        (s10 >> 14 as core::ffi::c_int | s11 << 7 as core::ffi::c_int) as uint8_t;
    *s.offset(29 as core::ffi::c_int as isize) = (s11 >> 1 as core::ffi::c_int) as uint8_t;
    *s.offset(30 as core::ffi::c_int as isize) = (s11 >> 9 as core::ffi::c_int) as uint8_t;
    *s.offset(31 as core::ffi::c_int as isize) = (s11 >> 17 as core::ffi::c_int) as uint8_t;
}
unsafe extern "C" fn sc_muladd(
    mut s: *mut uint8_t,
    mut a: *const uint8_t,
    mut b: *const uint8_t,
    mut c: *const uint8_t,
) {
    let mut a0: int64_t = (2097151 as core::ffi::c_int as u64 & load_3(a)) as int64_t;
    let mut a1: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(a.offset(2 as core::ffi::c_int as isize)) >> 5 as core::ffi::c_int)
        as int64_t;
    let mut a2: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(a.offset(5 as core::ffi::c_int as isize)) >> 2 as core::ffi::c_int)
        as int64_t;
    let mut a3: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(a.offset(7 as core::ffi::c_int as isize)) >> 7 as core::ffi::c_int)
        as int64_t;
    let mut a4: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(a.offset(10 as core::ffi::c_int as isize)) >> 4 as core::ffi::c_int)
        as int64_t;
    let mut a5: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(a.offset(13 as core::ffi::c_int as isize)) >> 1 as core::ffi::c_int)
        as int64_t;
    let mut a6: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(a.offset(15 as core::ffi::c_int as isize)) >> 6 as core::ffi::c_int)
        as int64_t;
    let mut a7: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(a.offset(18 as core::ffi::c_int as isize)) >> 3 as core::ffi::c_int)
        as int64_t;
    let mut a8: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(a.offset(21 as core::ffi::c_int as isize))) as int64_t;
    let mut a9: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(a.offset(23 as core::ffi::c_int as isize)) >> 5 as core::ffi::c_int)
        as int64_t;
    let mut a10: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(a.offset(26 as core::ffi::c_int as isize)) >> 2 as core::ffi::c_int)
        as int64_t;
    let mut a11: int64_t =
        (load_4(a.offset(28 as core::ffi::c_int as isize)) >> 7 as core::ffi::c_int) as int64_t;
    let mut b0: int64_t = (2097151 as core::ffi::c_int as u64 & load_3(b)) as int64_t;
    let mut b1: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(b.offset(2 as core::ffi::c_int as isize)) >> 5 as core::ffi::c_int)
        as int64_t;
    let mut b2: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(b.offset(5 as core::ffi::c_int as isize)) >> 2 as core::ffi::c_int)
        as int64_t;
    let mut b3: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(b.offset(7 as core::ffi::c_int as isize)) >> 7 as core::ffi::c_int)
        as int64_t;
    let mut b4: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(b.offset(10 as core::ffi::c_int as isize)) >> 4 as core::ffi::c_int)
        as int64_t;
    let mut b5: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(b.offset(13 as core::ffi::c_int as isize)) >> 1 as core::ffi::c_int)
        as int64_t;
    let mut b6: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(b.offset(15 as core::ffi::c_int as isize)) >> 6 as core::ffi::c_int)
        as int64_t;
    let mut b7: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(b.offset(18 as core::ffi::c_int as isize)) >> 3 as core::ffi::c_int)
        as int64_t;
    let mut b8: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(b.offset(21 as core::ffi::c_int as isize))) as int64_t;
    let mut b9: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(b.offset(23 as core::ffi::c_int as isize)) >> 5 as core::ffi::c_int)
        as int64_t;
    let mut b10: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(b.offset(26 as core::ffi::c_int as isize)) >> 2 as core::ffi::c_int)
        as int64_t;
    let mut b11: int64_t =
        (load_4(b.offset(28 as core::ffi::c_int as isize)) >> 7 as core::ffi::c_int) as int64_t;
    let mut c0: int64_t = (2097151 as core::ffi::c_int as u64 & load_3(c)) as int64_t;
    let mut c1: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(c.offset(2 as core::ffi::c_int as isize)) >> 5 as core::ffi::c_int)
        as int64_t;
    let mut c2: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(c.offset(5 as core::ffi::c_int as isize)) >> 2 as core::ffi::c_int)
        as int64_t;
    let mut c3: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(c.offset(7 as core::ffi::c_int as isize)) >> 7 as core::ffi::c_int)
        as int64_t;
    let mut c4: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(c.offset(10 as core::ffi::c_int as isize)) >> 4 as core::ffi::c_int)
        as int64_t;
    let mut c5: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(c.offset(13 as core::ffi::c_int as isize)) >> 1 as core::ffi::c_int)
        as int64_t;
    let mut c6: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(c.offset(15 as core::ffi::c_int as isize)) >> 6 as core::ffi::c_int)
        as int64_t;
    let mut c7: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(c.offset(18 as core::ffi::c_int as isize)) >> 3 as core::ffi::c_int)
        as int64_t;
    let mut c8: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(c.offset(21 as core::ffi::c_int as isize))) as int64_t;
    let mut c9: int64_t = (2097151 as core::ffi::c_int as u64
        & load_4(c.offset(23 as core::ffi::c_int as isize)) >> 5 as core::ffi::c_int)
        as int64_t;
    let mut c10: int64_t = (2097151 as core::ffi::c_int as u64
        & load_3(c.offset(26 as core::ffi::c_int as isize)) >> 2 as core::ffi::c_int)
        as int64_t;
    let mut c11: int64_t =
        (load_4(c.offset(28 as core::ffi::c_int as isize)) >> 7 as core::ffi::c_int) as int64_t;
    let mut s0: int64_t = 0;
    let mut s1: int64_t = 0;
    let mut s2: int64_t = 0;
    let mut s3: int64_t = 0;
    let mut s4: int64_t = 0;
    let mut s5: int64_t = 0;
    let mut s6: int64_t = 0;
    let mut s7: int64_t = 0;
    let mut s8: int64_t = 0;
    let mut s9: int64_t = 0;
    let mut s10: int64_t = 0;
    let mut s11: int64_t = 0;
    let mut s12: int64_t = 0;
    let mut s13: int64_t = 0;
    let mut s14: int64_t = 0;
    let mut s15: int64_t = 0;
    let mut s16: int64_t = 0;
    let mut s17: int64_t = 0;
    let mut s18: int64_t = 0;
    let mut s19: int64_t = 0;
    let mut s20: int64_t = 0;
    let mut s21: int64_t = 0;
    let mut s22: int64_t = 0;
    let mut s23: int64_t = 0;
    let mut carry0: int64_t = 0;
    let mut carry1: int64_t = 0;
    let mut carry2: int64_t = 0;
    let mut carry3: int64_t = 0;
    let mut carry4: int64_t = 0;
    let mut carry5: int64_t = 0;
    let mut carry6: int64_t = 0;
    let mut carry7: int64_t = 0;
    let mut carry8: int64_t = 0;
    let mut carry9: int64_t = 0;
    let mut carry10: int64_t = 0;
    let mut carry11: int64_t = 0;
    let mut carry12: int64_t = 0;
    let mut carry13: int64_t = 0;
    let mut carry14: int64_t = 0;
    let mut carry15: int64_t = 0;
    let mut carry16: int64_t = 0;
    let mut carry17: int64_t = 0;
    let mut carry18: int64_t = 0;
    let mut carry19: int64_t = 0;
    let mut carry20: int64_t = 0;
    let mut carry21: int64_t = 0;
    let mut carry22: int64_t = 0;
    s0 = c0 + a0 * b0;
    s1 = c1 + a0 * b1 + a1 * b0;
    s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    s8 = c8
        + a0 * b8
        + a1 * b7
        + a2 * b6
        + a3 * b5
        + a4 * b4
        + a5 * b3
        + a6 * b2
        + a7 * b1
        + a8 * b0;
    s9 = c9
        + a0 * b9
        + a1 * b8
        + a2 * b7
        + a3 * b6
        + a4 * b5
        + a5 * b4
        + a6 * b3
        + a7 * b2
        + a8 * b1
        + a9 * b0;
    s10 = c10
        + a0 * b10
        + a1 * b9
        + a2 * b8
        + a3 * b7
        + a4 * b6
        + a5 * b5
        + a6 * b4
        + a7 * b3
        + a8 * b2
        + a9 * b1
        + a10 * b0;
    s11 = c11
        + a0 * b11
        + a1 * b10
        + a2 * b9
        + a3 * b8
        + a4 * b7
        + a5 * b6
        + a6 * b5
        + a7 * b4
        + a8 * b3
        + a9 * b2
        + a10 * b1
        + a11 * b0;
    s12 = a1 * b11
        + a2 * b10
        + a3 * b9
        + a4 * b8
        + a5 * b7
        + a6 * b6
        + a7 * b5
        + a8 * b4
        + a9 * b3
        + a10 * b2
        + a11 * b1;
    s13 = a2 * b11
        + a3 * b10
        + a4 * b9
        + a5 * b8
        + a6 * b7
        + a7 * b6
        + a8 * b5
        + a9 * b4
        + a10 * b3
        + a11 * b2;
    s14 =
        a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
    s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    s20 = a9 * b11 + a10 * b10 + a11 * b9;
    s21 = a10 * b11 + a11 * b10;
    s22 = a11 * b11;
    s23 = 0 as core::ffi::c_int as int64_t;
    carry0 =
        s0 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 =
        s2 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 =
        s4 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 =
        s6 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 =
        s8 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 =
        s10 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 =
        s12 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 =
        s14 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 =
        s16 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);
    carry18 =
        s18 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s19 += carry18;
    s18 -= int64_lshift21(carry18);
    carry20 =
        s20 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s21 += carry20;
    s20 -= int64_lshift21(carry20);
    carry22 =
        s22 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s23 += carry22;
    s22 -= int64_lshift21(carry22);
    carry1 =
        s1 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 =
        s3 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 =
        s5 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 =
        s7 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 =
        s9 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 =
        s11 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 =
        s13 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 =
        s15 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);
    carry17 =
        s17 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s18 += carry17;
    s17 -= int64_lshift21(carry17);
    carry19 =
        s19 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s20 += carry19;
    s19 -= int64_lshift21(carry19);
    carry21 =
        s21 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s22 += carry21;
    s21 -= int64_lshift21(carry21);
    s11 += s23 * 666643 as core::ffi::c_int as i64;
    s12 += s23 * 470296 as core::ffi::c_int as i64;
    s13 += s23 * 654183 as core::ffi::c_int as i64;
    s14 -= s23 * 997805 as core::ffi::c_int as i64;
    s15 += s23 * 136657 as core::ffi::c_int as i64;
    s16 -= s23 * 683901 as core::ffi::c_int as i64;
    s23 = 0 as core::ffi::c_int as int64_t;
    s10 += s22 * 666643 as core::ffi::c_int as i64;
    s11 += s22 * 470296 as core::ffi::c_int as i64;
    s12 += s22 * 654183 as core::ffi::c_int as i64;
    s13 -= s22 * 997805 as core::ffi::c_int as i64;
    s14 += s22 * 136657 as core::ffi::c_int as i64;
    s15 -= s22 * 683901 as core::ffi::c_int as i64;
    s22 = 0 as core::ffi::c_int as int64_t;
    s9 += s21 * 666643 as core::ffi::c_int as i64;
    s10 += s21 * 470296 as core::ffi::c_int as i64;
    s11 += s21 * 654183 as core::ffi::c_int as i64;
    s12 -= s21 * 997805 as core::ffi::c_int as i64;
    s13 += s21 * 136657 as core::ffi::c_int as i64;
    s14 -= s21 * 683901 as core::ffi::c_int as i64;
    s21 = 0 as core::ffi::c_int as int64_t;
    s8 += s20 * 666643 as core::ffi::c_int as i64;
    s9 += s20 * 470296 as core::ffi::c_int as i64;
    s10 += s20 * 654183 as core::ffi::c_int as i64;
    s11 -= s20 * 997805 as core::ffi::c_int as i64;
    s12 += s20 * 136657 as core::ffi::c_int as i64;
    s13 -= s20 * 683901 as core::ffi::c_int as i64;
    s20 = 0 as core::ffi::c_int as int64_t;
    s7 += s19 * 666643 as core::ffi::c_int as i64;
    s8 += s19 * 470296 as core::ffi::c_int as i64;
    s9 += s19 * 654183 as core::ffi::c_int as i64;
    s10 -= s19 * 997805 as core::ffi::c_int as i64;
    s11 += s19 * 136657 as core::ffi::c_int as i64;
    s12 -= s19 * 683901 as core::ffi::c_int as i64;
    s19 = 0 as core::ffi::c_int as int64_t;
    s6 += s18 * 666643 as core::ffi::c_int as i64;
    s7 += s18 * 470296 as core::ffi::c_int as i64;
    s8 += s18 * 654183 as core::ffi::c_int as i64;
    s9 -= s18 * 997805 as core::ffi::c_int as i64;
    s10 += s18 * 136657 as core::ffi::c_int as i64;
    s11 -= s18 * 683901 as core::ffi::c_int as i64;
    s18 = 0 as core::ffi::c_int as int64_t;
    carry6 =
        s6 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 =
        s8 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 =
        s10 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 =
        s12 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 =
        s14 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 =
        s16 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);
    carry7 =
        s7 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 =
        s9 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 =
        s11 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 =
        s13 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 =
        s15 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);
    s5 += s17 * 666643 as core::ffi::c_int as i64;
    s6 += s17 * 470296 as core::ffi::c_int as i64;
    s7 += s17 * 654183 as core::ffi::c_int as i64;
    s8 -= s17 * 997805 as core::ffi::c_int as i64;
    s9 += s17 * 136657 as core::ffi::c_int as i64;
    s10 -= s17 * 683901 as core::ffi::c_int as i64;
    s17 = 0 as core::ffi::c_int as int64_t;
    s4 += s16 * 666643 as core::ffi::c_int as i64;
    s5 += s16 * 470296 as core::ffi::c_int as i64;
    s6 += s16 * 654183 as core::ffi::c_int as i64;
    s7 -= s16 * 997805 as core::ffi::c_int as i64;
    s8 += s16 * 136657 as core::ffi::c_int as i64;
    s9 -= s16 * 683901 as core::ffi::c_int as i64;
    s16 = 0 as core::ffi::c_int as int64_t;
    s3 += s15 * 666643 as core::ffi::c_int as i64;
    s4 += s15 * 470296 as core::ffi::c_int as i64;
    s5 += s15 * 654183 as core::ffi::c_int as i64;
    s6 -= s15 * 997805 as core::ffi::c_int as i64;
    s7 += s15 * 136657 as core::ffi::c_int as i64;
    s8 -= s15 * 683901 as core::ffi::c_int as i64;
    s15 = 0 as core::ffi::c_int as int64_t;
    s2 += s14 * 666643 as core::ffi::c_int as i64;
    s3 += s14 * 470296 as core::ffi::c_int as i64;
    s4 += s14 * 654183 as core::ffi::c_int as i64;
    s5 -= s14 * 997805 as core::ffi::c_int as i64;
    s6 += s14 * 136657 as core::ffi::c_int as i64;
    s7 -= s14 * 683901 as core::ffi::c_int as i64;
    s14 = 0 as core::ffi::c_int as int64_t;
    s1 += s13 * 666643 as core::ffi::c_int as i64;
    s2 += s13 * 470296 as core::ffi::c_int as i64;
    s3 += s13 * 654183 as core::ffi::c_int as i64;
    s4 -= s13 * 997805 as core::ffi::c_int as i64;
    s5 += s13 * 136657 as core::ffi::c_int as i64;
    s6 -= s13 * 683901 as core::ffi::c_int as i64;
    s13 = 0 as core::ffi::c_int as int64_t;
    s0 += s12 * 666643 as core::ffi::c_int as i64;
    s1 += s12 * 470296 as core::ffi::c_int as i64;
    s2 += s12 * 654183 as core::ffi::c_int as i64;
    s3 -= s12 * 997805 as core::ffi::c_int as i64;
    s4 += s12 * 136657 as core::ffi::c_int as i64;
    s5 -= s12 * 683901 as core::ffi::c_int as i64;
    s12 = 0 as core::ffi::c_int as int64_t;
    carry0 =
        s0 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 =
        s2 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 =
        s4 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 =
        s6 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 =
        s8 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 =
        s10 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry1 =
        s1 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 =
        s3 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 =
        s5 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 =
        s7 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 =
        s9 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 =
        s11 + ((1 as core::ffi::c_int) << 20 as core::ffi::c_int) as i64 >> 21 as core::ffi::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    s0 += s12 * 666643 as core::ffi::c_int as i64;
    s1 += s12 * 470296 as core::ffi::c_int as i64;
    s2 += s12 * 654183 as core::ffi::c_int as i64;
    s3 -= s12 * 997805 as core::ffi::c_int as i64;
    s4 += s12 * 136657 as core::ffi::c_int as i64;
    s5 -= s12 * 683901 as core::ffi::c_int as i64;
    s12 = 0 as core::ffi::c_int as int64_t;
    carry0 = s0 >> 21 as core::ffi::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21 as core::ffi::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21 as core::ffi::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21 as core::ffi::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21 as core::ffi::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21 as core::ffi::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21 as core::ffi::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21 as core::ffi::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21 as core::ffi::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21 as core::ffi::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21 as core::ffi::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry11 = s11 >> 21 as core::ffi::c_int;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    s0 += s12 * 666643 as core::ffi::c_int as i64;
    s1 += s12 * 470296 as core::ffi::c_int as i64;
    s2 += s12 * 654183 as core::ffi::c_int as i64;
    s3 -= s12 * 997805 as core::ffi::c_int as i64;
    s4 += s12 * 136657 as core::ffi::c_int as i64;
    s5 -= s12 * 683901 as core::ffi::c_int as i64;
    s12 = 0 as core::ffi::c_int as int64_t;
    carry0 = s0 >> 21 as core::ffi::c_int;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21 as core::ffi::c_int;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21 as core::ffi::c_int;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21 as core::ffi::c_int;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21 as core::ffi::c_int;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21 as core::ffi::c_int;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21 as core::ffi::c_int;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21 as core::ffi::c_int;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21 as core::ffi::c_int;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21 as core::ffi::c_int;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21 as core::ffi::c_int;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    *s.offset(0 as core::ffi::c_int as isize) = (s0 >> 0 as core::ffi::c_int) as uint8_t;
    *s.offset(1 as core::ffi::c_int as isize) = (s0 >> 8 as core::ffi::c_int) as uint8_t;
    *s.offset(2 as core::ffi::c_int as isize) =
        (s0 >> 16 as core::ffi::c_int | s1 << 5 as core::ffi::c_int) as uint8_t;
    *s.offset(3 as core::ffi::c_int as isize) = (s1 >> 3 as core::ffi::c_int) as uint8_t;
    *s.offset(4 as core::ffi::c_int as isize) = (s1 >> 11 as core::ffi::c_int) as uint8_t;
    *s.offset(5 as core::ffi::c_int as isize) =
        (s1 >> 19 as core::ffi::c_int | s2 << 2 as core::ffi::c_int) as uint8_t;
    *s.offset(6 as core::ffi::c_int as isize) = (s2 >> 6 as core::ffi::c_int) as uint8_t;
    *s.offset(7 as core::ffi::c_int as isize) =
        (s2 >> 14 as core::ffi::c_int | s3 << 7 as core::ffi::c_int) as uint8_t;
    *s.offset(8 as core::ffi::c_int as isize) = (s3 >> 1 as core::ffi::c_int) as uint8_t;
    *s.offset(9 as core::ffi::c_int as isize) = (s3 >> 9 as core::ffi::c_int) as uint8_t;
    *s.offset(10 as core::ffi::c_int as isize) =
        (s3 >> 17 as core::ffi::c_int | s4 << 4 as core::ffi::c_int) as uint8_t;
    *s.offset(11 as core::ffi::c_int as isize) = (s4 >> 4 as core::ffi::c_int) as uint8_t;
    *s.offset(12 as core::ffi::c_int as isize) = (s4 >> 12 as core::ffi::c_int) as uint8_t;
    *s.offset(13 as core::ffi::c_int as isize) =
        (s4 >> 20 as core::ffi::c_int | s5 << 1 as core::ffi::c_int) as uint8_t;
    *s.offset(14 as core::ffi::c_int as isize) = (s5 >> 7 as core::ffi::c_int) as uint8_t;
    *s.offset(15 as core::ffi::c_int as isize) =
        (s5 >> 15 as core::ffi::c_int | s6 << 6 as core::ffi::c_int) as uint8_t;
    *s.offset(16 as core::ffi::c_int as isize) = (s6 >> 2 as core::ffi::c_int) as uint8_t;
    *s.offset(17 as core::ffi::c_int as isize) = (s6 >> 10 as core::ffi::c_int) as uint8_t;
    *s.offset(18 as core::ffi::c_int as isize) =
        (s6 >> 18 as core::ffi::c_int | s7 << 3 as core::ffi::c_int) as uint8_t;
    *s.offset(19 as core::ffi::c_int as isize) = (s7 >> 5 as core::ffi::c_int) as uint8_t;
    *s.offset(20 as core::ffi::c_int as isize) = (s7 >> 13 as core::ffi::c_int) as uint8_t;
    *s.offset(21 as core::ffi::c_int as isize) = (s8 >> 0 as core::ffi::c_int) as uint8_t;
    *s.offset(22 as core::ffi::c_int as isize) = (s8 >> 8 as core::ffi::c_int) as uint8_t;
    *s.offset(23 as core::ffi::c_int as isize) =
        (s8 >> 16 as core::ffi::c_int | s9 << 5 as core::ffi::c_int) as uint8_t;
    *s.offset(24 as core::ffi::c_int as isize) = (s9 >> 3 as core::ffi::c_int) as uint8_t;
    *s.offset(25 as core::ffi::c_int as isize) = (s9 >> 11 as core::ffi::c_int) as uint8_t;
    *s.offset(26 as core::ffi::c_int as isize) =
        (s9 >> 19 as core::ffi::c_int | s10 << 2 as core::ffi::c_int) as uint8_t;
    *s.offset(27 as core::ffi::c_int as isize) = (s10 >> 6 as core::ffi::c_int) as uint8_t;
    *s.offset(28 as core::ffi::c_int as isize) =
        (s10 >> 14 as core::ffi::c_int | s11 << 7 as core::ffi::c_int) as uint8_t;
    *s.offset(29 as core::ffi::c_int as isize) = (s11 >> 1 as core::ffi::c_int) as uint8_t;
    *s.offset(30 as core::ffi::c_int as isize) = (s11 >> 9 as core::ffi::c_int) as uint8_t;
    *s.offset(31 as core::ffi::c_int as isize) = (s11 >> 17 as core::ffi::c_int) as uint8_t;
}
#[no_mangle]
pub unsafe extern "C" fn x25519_scalar_mult_generic_masked(
    mut out: *mut uint8_t,
    mut scalar_masked: *const uint8_t,
    mut point: *const uint8_t,
) {
    let mut x1: fe = fe { v: [0; 10] };
    let mut x2: fe = fe { v: [0; 10] };
    let mut z2: fe = fe { v: [0; 10] };
    let mut x3: fe = fe { v: [0; 10] };
    let mut z3: fe = fe { v: [0; 10] };
    let mut tmp0: fe = fe { v: [0; 10] };
    let mut tmp1: fe = fe { v: [0; 10] };
    let mut x2l: fe_loose = fe_loose { v: [0; 10] };
    let mut z2l: fe_loose = fe_loose { v: [0; 10] };
    let mut x3l: fe_loose = fe_loose { v: [0; 10] };
    let mut tmp0l: fe_loose = fe_loose { v: [0; 10] };
    let mut tmp1l: fe_loose = fe_loose { v: [0; 10] };
    let mut e: [uint8_t; 32] = [0; 32];
    OPENSSL_memcpy(
        e.as_mut_ptr() as *mut core::ffi::c_void,
        scalar_masked as *const core::ffi::c_void,
        32 as core::ffi::c_int as size_t,
    );
    fe_frombytes(&mut x1, point);
    fe_1(&mut x2);
    fe_0(&mut z2);
    fe_copy(&mut x3, &mut x1);
    fe_1(&mut z3);
    let mut swap: core::ffi::c_uint = 0 as core::ffi::c_int as core::ffi::c_uint;
    let mut pos: core::ffi::c_int = 0;
    pos = 254 as core::ffi::c_int;
    while pos >= 0 as core::ffi::c_int {
        let mut b: core::ffi::c_uint = (1 as core::ffi::c_int
            & e[(pos / 8 as core::ffi::c_int) as usize] as core::ffi::c_int
                >> (pos & 7 as core::ffi::c_int))
            as core::ffi::c_uint;
        swap ^= b;
        fe_cswap(&mut x2, &mut x3, swap);
        fe_cswap(&mut z2, &mut z3, swap);
        swap = b;
        fe_sub(&mut tmp0l, &mut x3, &mut z3);
        fe_sub(&mut tmp1l, &mut x2, &mut z2);
        fe_add(&mut x2l, &mut x2, &mut z2);
        fe_add(&mut z2l, &mut x3, &mut z3);
        fe_mul_tll(&mut z3, &mut tmp0l, &mut x2l);
        fe_mul_tll(&mut z2, &mut z2l, &mut tmp1l);
        fe_sq_tl(&mut tmp0, &mut tmp1l);
        fe_sq_tl(&mut tmp1, &mut x2l);
        fe_add(&mut x3l, &mut z3, &mut z2);
        fe_sub(&mut z2l, &mut z3, &mut z2);
        fe_mul_ttt(&mut x2, &mut tmp1, &mut tmp0);
        fe_sub(&mut tmp1l, &mut tmp1, &mut tmp0);
        fe_sq_tl(&mut z2, &mut z2l);
        fe_mul121666(&mut z3, &mut tmp1l);
        fe_sq_tl(&mut x3, &mut x3l);
        fe_add(&mut tmp0l, &mut tmp0, &mut z3);
        fe_mul_ttt(&mut z3, &mut x1, &mut z2);
        fe_mul_tll(&mut z2, &mut tmp1l, &mut tmp0l);
        pos -= 1;
    }
    fe_cswap(&mut x2, &mut x3, swap);
    fe_cswap(&mut z2, &mut z3, swap);
    fe_invert(&mut z2, &mut z2);
    fe_mul_ttt(&mut x2, &mut x2, &mut z2);
    fe_tobytes(out, &mut x2);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_public_from_private_generic_masked(
    mut out_public_value: *mut uint8_t,
    mut private_key_masked: *const uint8_t,
    mut use_adx: core::ffi::c_int,
) {
    let mut e: [uint8_t; 32] = [0; 32];
    OPENSSL_memcpy(
        e.as_mut_ptr() as *mut core::ffi::c_void,
        private_key_masked as *const core::ffi::c_void,
        32 as core::ffi::c_int as size_t,
    );
    let mut A: ge_p3 = ge_p3 {
        X: fe { v: [0; 10] },
        Y: fe { v: [0; 10] },
        Z: fe { v: [0; 10] },
        T: fe { v: [0; 10] },
    };
    x25519_ge_scalarmult_base(&mut A, e.as_mut_ptr() as *const uint8_t, use_adx);
    let mut zplusy: fe_loose = fe_loose { v: [0; 10] };
    let mut zminusy: fe_loose = fe_loose { v: [0; 10] };
    let mut zminusy_inv: fe = fe { v: [0; 10] };
    fe_add(&mut zplusy, &mut A.Z, &mut A.Y);
    fe_sub(&mut zminusy, &mut A.Z, &mut A.Y);
    fe_loose_invert(&mut zminusy_inv, &mut zminusy);
    fe_mul_tlt(&mut zminusy_inv, &mut zplusy, &mut zminusy_inv);
    fe_tobytes(out_public_value, &mut zminusy_inv);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_fe_invert(mut out: *mut fe, mut z: *const fe) {
    fe_invert(out, z);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_fe_isnegative(mut f: *const fe) -> uint8_t {
    return fe_isnegative(f) as uint8_t;
}
#[no_mangle]
pub unsafe extern "C" fn x25519_fe_mul_ttt(mut h: *mut fe, mut f: *const fe, mut g: *const fe) {
    fe_mul_ttt(h, f, g);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_fe_neg(mut f: *mut fe) {
    let mut t: fe_loose = fe_loose { v: [0; 10] };
    fe_neg(&mut t, f);
    fe_carry(f, &mut t);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_fe_tobytes(mut s: *mut uint8_t, mut h: *const fe) {
    fe_tobytes(s, h);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_ge_double_scalarmult_vartime(
    mut r: *mut ge_p2,
    mut a: *const uint8_t,
    mut A: *const ge_p3,
    mut b: *const uint8_t,
) {
    ge_double_scalarmult_vartime(r, a, A, b);
}
#[no_mangle]
pub unsafe extern "C" fn x25519_sc_mask(mut a: *mut uint8_t) {
    let ref mut fresh5 = *a.offset(0 as core::ffi::c_int as isize);
    *fresh5 = (*fresh5 as core::ffi::c_int & 248 as core::ffi::c_int) as uint8_t;
    let ref mut fresh6 = *a.offset(31 as core::ffi::c_int as isize);
    *fresh6 = (*fresh6 as core::ffi::c_int & 127 as core::ffi::c_int) as uint8_t;
    let ref mut fresh7 = *a.offset(31 as core::ffi::c_int as isize);
    *fresh7 = (*fresh7 as core::ffi::c_int | 64 as core::ffi::c_int) as uint8_t;
}
#[no_mangle]
pub unsafe extern "C" fn x25519_sc_muladd(
    mut s: *mut uint8_t,
    mut a: *const uint8_t,
    mut b: *const uint8_t,
    mut c: *const uint8_t,
) {
    sc_muladd(s, a, b, c);
}

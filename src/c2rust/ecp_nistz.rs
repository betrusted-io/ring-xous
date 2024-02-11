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
pub type __uint8_t = core::ffi::c_uchar;
pub type __uint32_t = core::ffi::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type crypto_word_t = uint32_t;
pub type Limb = crypto_word_t;
#[no_mangle]
pub unsafe extern "C" fn little_endian_bytes_from_scalar(
    str: *mut uint8_t,
    str_len: size_t,
    scalar: *const Limb,
    num_limbs: size_t,
) {
    if str_len
        == num_limbs
            .wrapping_mul(core::mem::size_of::<Limb>() as u32)
            .wrapping_add(1 as core::ffi::c_int as core::ffi::c_uint)
    {
    } else {
        __assert_fail(
            b"str_len == (num_limbs * sizeof(Limb)) + 1\0" as *const u8 as *const core::ffi::c_char,
            b"crypto/fipsmodule/ec/ecp_nistz.c\0" as *const u8 as *const core::ffi::c_char,
            31 as core::ffi::c_int as core::ffi::c_uint,
            (*core::mem::transmute::<&[u8; 78], &[core::ffi::c_char; 78]>(
                b"void little_endian_bytes_from_scalar(uint8_t *, size_t, const Limb *, size_t)\0",
            ))
            .as_ptr(),
        );
    }
    let mut i: size_t;
    i = 0 as core::ffi::c_int as size_t;
    while i < num_limbs.wrapping_mul(core::mem::size_of::<Limb>() as u32) {
        let mut d: Limb =
            *scalar.offset(i.wrapping_div(core::mem::size_of::<Limb>() as u32) as isize);
        *str.offset(i.wrapping_add(0 as core::ffi::c_int as core::ffi::c_uint) as isize) =
            (d & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
        *str.offset(i.wrapping_add(1 as core::ffi::c_int as core::ffi::c_uint) as isize) =
            (d >> 8 as core::ffi::c_int & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
        *str.offset(i.wrapping_add(2 as core::ffi::c_int as core::ffi::c_uint) as isize) =
            (d >> 16 as core::ffi::c_int & 0xff as core::ffi::c_int as core::ffi::c_uint)
                as uint8_t;
        d >>= 24 as core::ffi::c_int;
        *str.offset(i.wrapping_add(3 as core::ffi::c_int as core::ffi::c_uint) as isize) =
            (d & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
        if core::mem::size_of::<Limb>() as u32 == 8 as core::ffi::c_int as core::ffi::c_uint {
            d >>= 8 as core::ffi::c_int;
            *str.offset(i.wrapping_add(4 as core::ffi::c_int as core::ffi::c_uint) as isize) =
                (d & 0xff as core::ffi::c_int as core::ffi::c_uint) as uint8_t;
            *str.offset(i.wrapping_add(5 as core::ffi::c_int as core::ffi::c_uint) as isize) =
                (d >> 8 as core::ffi::c_int & 0xff as core::ffi::c_int as core::ffi::c_uint)
                    as uint8_t;
            *str.offset(i.wrapping_add(6 as core::ffi::c_int as core::ffi::c_uint) as isize) =
                (d >> 16 as core::ffi::c_int & 0xff as core::ffi::c_int as core::ffi::c_uint)
                    as uint8_t;
            *str.offset(i.wrapping_add(7 as core::ffi::c_int as core::ffi::c_uint) as isize) =
                (d >> 24 as core::ffi::c_int & 0xff as core::ffi::c_int as core::ffi::c_uint)
                    as uint8_t;
        }
        i = (i as core::ffi::c_uint).wrapping_add(core::mem::size_of::<Limb>() as u32) as size_t
            as size_t;
    }
    while i < str_len {
        *str.offset(i as isize) = 0 as core::ffi::c_int as uint8_t;
        i = i.wrapping_add(1);
    }
}

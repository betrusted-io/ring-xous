#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub type size_t = core::ffi::c_uint;
pub type __uint8_t = core::ffi::c_uchar;
pub type uint8_t = __uint8_t;
pub type aliasing_uint8_t = core::ffi::c_uchar;
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_memcmp(
    in_a: *const core::ffi::c_void,
    in_b: *const core::ffi::c_void,
    len: size_t,
) -> core::ffi::c_int {
    let a: *const aliasing_uint8_t = in_a as *const aliasing_uint8_t;
    let b: *const aliasing_uint8_t = in_b as *const aliasing_uint8_t;
    let mut x: uint8_t = 0 as core::ffi::c_int as uint8_t;
    let mut i: size_t = 0 as core::ffi::c_int as size_t;
    while i < len {
        x = (x as core::ffi::c_int
            | *a.offset(i as isize) as core::ffi::c_int ^ *b.offset(i as isize) as core::ffi::c_int)
            as uint8_t;
        i = i.wrapping_add(1);
    }
    return x as core::ffi::c_int;
}

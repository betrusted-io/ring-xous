#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![register_tool(c2rust)]
#![feature(label_break_value, register_tool)]
extern "C" {
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
pub type crypto_word_t = uint32_t;
pub type Limb = crypto_word_t;
#[no_mangle]
pub unsafe extern "C" fn little_endian_bytes_from_scalar(
    mut str: *mut uint8_t,
    mut str_len: size_t,
    mut scalar: *const Limb,
    mut num_limbs: size_t,
) {
    if str_len
        == num_limbs
            .wrapping_mul(::std::mem::size_of::<Limb>() as libc::c_ulong)
            .wrapping_add(1 as libc::c_int as libc::c_uint)
    {} else {
        __assert_fail(
            b"str_len == (num_limbs * sizeof(Limb)) + 1\0" as *const u8
                as *const libc::c_char,
            b"crypto/fipsmodule/ec/ecp_nistz.c\0" as *const u8 as *const libc::c_char,
            31 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 78],
                &[libc::c_char; 78],
            >(
                b"void little_endian_bytes_from_scalar(uint8_t *, size_t, const Limb *, size_t)\0",
            ))
                .as_ptr(),
        );
    }
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < num_limbs.wrapping_mul(::std::mem::size_of::<Limb>() as libc::c_ulong) {
        let mut d: Limb = *scalar
            .offset(
                i.wrapping_div(::std::mem::size_of::<Limb>() as libc::c_ulong) as isize,
            );
        *str
            .offset(
                i.wrapping_add(0 as libc::c_int as libc::c_uint) as isize,
            ) = (d & 0xff as libc::c_int as libc::c_uint) as uint8_t;
        *str
            .offset(
                i.wrapping_add(1 as libc::c_int as libc::c_uint) as isize,
            ) = (d >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
        *str
            .offset(
                i.wrapping_add(2 as libc::c_int as libc::c_uint) as isize,
            ) = (d >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint)
            as uint8_t;
        d >>= 24 as libc::c_int;
        *str
            .offset(
                i.wrapping_add(3 as libc::c_int as libc::c_uint) as isize,
            ) = (d & 0xff as libc::c_int as libc::c_uint) as uint8_t;
        if ::std::mem::size_of::<Limb>() as libc::c_ulong
            == 8 as libc::c_int as libc::c_uint
        {
            d >>= 8 as libc::c_int;
            *str
                .offset(
                    i.wrapping_add(4 as libc::c_int as libc::c_uint) as isize,
                ) = (d & 0xff as libc::c_int as libc::c_uint) as uint8_t;
            *str
                .offset(
                    i.wrapping_add(5 as libc::c_int as libc::c_uint) as isize,
                ) = (d >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint)
                as uint8_t;
            *str
                .offset(
                    i.wrapping_add(6 as libc::c_int as libc::c_uint) as isize,
                ) = (d >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint)
                as uint8_t;
            *str
                .offset(
                    i.wrapping_add(7 as libc::c_int as libc::c_uint) as isize,
                ) = (d >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint)
                as uint8_t;
        }
        i = (i as libc::c_uint)
            .wrapping_add(::std::mem::size_of::<Limb>() as libc::c_ulong) as size_t
            as size_t;
    }
    while i < str_len {
        *str.offset(i as isize) = 0 as libc::c_int as uint8_t;
        i = i.wrapping_add(1);
    }
}

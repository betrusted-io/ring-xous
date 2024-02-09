#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub type __uint32_t = core::ffi::c_uint;
pub type uint32_t = __uint32_t;
#[no_mangle]
pub static mut OPENSSL_ia32cap_P: [uint32_t; 4] = [0 as core::ffi::c_int as uint32_t, 0, 0, 0];

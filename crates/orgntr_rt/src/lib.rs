pub mod abi;

use abi::{FardVal, TAG_INT};

/// Stage I: Boxed Addition via Caller-Provided Output Pointer (sret-style)
#[no_mangle]
pub extern "C" fn fard_add_boxed_out(out: *mut FardVal, a: FardVal, b: FardVal) {
    unsafe {
        if a.tag != TAG_INT || b.tag != TAG_INT {
            std::process::abort();
        }
        *out = FardVal::int(a.as_i64().wrapping_add(b.as_i64()));
    }
}

/// Stage I: Boxed Multiplication via Caller-Provided Output Pointer (sret-style)
#[no_mangle]
pub extern "C" fn fard_mul_boxed_out(out: *mut FardVal, a: FardVal, b: FardVal) {
    unsafe {
        if a.tag != TAG_INT || b.tag != TAG_INT {
            std::process::abort();
        }
        *out = FardVal::int(a.as_i64().wrapping_mul(b.as_i64()));
    }
}

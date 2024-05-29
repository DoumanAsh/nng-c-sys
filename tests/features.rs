use core::ffi::CStr;
use core::ptr;

use nng_c_sys::nng_http_req_alloc;
use nng_c_sys::nng_tls_engine_name;

#[test]
fn should_verify_tls_feature_enabled() {
    let result = unsafe {
        CStr::from_ptr(nng_tls_engine_name())
            .to_str()
            .expect("unicode")
    };
    #[cfg(not(feature = "tls"))]
    assert_eq!(result, "none");
    #[cfg(feature = "tls")]
    assert_eq!(result, "mbed");
}

#[test]
fn should_verify_http_feature_enabled() {
    let mut req = ptr::null_mut();
    let result = unsafe { nng_http_req_alloc(&mut req, ptr::null()) };
    #[cfg(not(feature = "http"))]
    assert_eq!(result, nng_c_sys::nng_errno_enum::NNG_ENOTSUP);
    #[cfg(feature = "http")]
    {
        assert_eq!(result, 0);
        unsafe {
            nng_c_sys::nng_http_req_free(req);
        }
    }
}

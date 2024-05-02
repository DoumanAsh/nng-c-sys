use nng_c_sys::nng_http_req_alloc;
use core::ptr;

#[test]
fn should_verify_http_feature_enabled() {
    let mut req = ptr::null_mut();
    let result = unsafe {
        nng_http_req_alloc(&mut req, ptr::null())
    };
    #[cfg(not(feature = "http"))]
    assert_eq!(result, nng_c_sys::nng_errno_enum::NNG_ENOTSUP);
    #[cfg(feature = "http")]
    assert_eq!(result, 0);

    #[cfg(feature = "http")]
    unsafe {
        nng_c_sys::nng_http_req_free(req);
    }
}

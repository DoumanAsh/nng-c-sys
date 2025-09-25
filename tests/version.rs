use nng_c_sys::nng_version;
use core::ffi::CStr;

#[test]
fn should_verify_version() {
    let version = unsafe {
        CStr::from_ptr(
            nng_version()
        )
    };
    let version = version.to_str().expect("utf-8");
    assert_eq!(version, "1.11.0");
}

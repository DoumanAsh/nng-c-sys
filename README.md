# nng-c-sys

[![Actions Status](https://github.com/DoumanAsh/nng-c-sys/workflows/Rust/badge.svg)](https://github.com/DoumanAsh/nng-c-sys/actions)
[![Crates.io](https://img.shields.io/crates/v/nng-c-sys.svg)](https://crates.io/crates/nng-c-sys)
[![Documentation](https://docs.rs/nng-c-sys/badge.svg)](https://docs.rs/crate/nng-c-sys/)

Bindings to [nng](https://github.com/nanomsg/nng).

Version corresponds to C library

High level bindings: [nng-c](https://github.com/DoumanAsh/nng-c)

## Features

- `http` - Builds with http code ON
- `websocket` - Builds with websocket code ON. Enables `http` alongside
- `tls` - Builds with TLS using vendored [mbedtls](./mbedtls-3.6.7)
- `tls-no-vendored` - Builds with TLS, but assume `mbedtls` is available as dynamic library in default paths (e.g. `/usr/lib64`)
- `tls-pkg-config` - Builds with TLS, but use `pkg-config` to discover `mbedtls`
- `stats` - Builds with statistics collection. See [this](https://nng.nanomsg.org/man/v1.10.0/nng_stat.5.html) for details.

### TLS

When `tls` feature is enabled this crate compiles vendored mbedtls to bundle it together with `nng`
To avoid that consider using alternative `tls-*` features to let cmake discover installed mbedtls

## Cross compilation

### Android

Specify environment variable `ANDROID_NDK_HOME` which points too root of NDK installation where to look for toolchain file


## C code update

1. Download new version extracting only `cmake/`, `include/`, `src/`, `CMakeLists.txt` and `LICENSE.txt`
2. Apply [nng.patch](./nng.patch) to ensure build correctness
3. Ensure constants `NNG_OPT_*` end with `\0` character in [lib.rs](./src/lib.rs)
4. Due to buggy [bindgen](https://github.com/rust-lang/rust-bindgen/issues/2711) it will generate incorrect enum type. While standard doesn't mandate it to be `int`, it is most often than not is most assumed choice for developers, so you need to ensure that all `pub type Type =` definitions within enum modules are defined as `pub type Type = core::ffi::c_int` rather than `c_uint`

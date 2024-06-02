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
- `tls` - Builds with TLS code ON
- `stats` - Builds with statistics collection. See [this](https://nng.nanomsg.org/man/v1.8.0/nng_stat.5.html) for details.

### TLS

When `tls` feature is enabled this crate compiles mbedtls 2.28.8 to bundle it together with `nng`

## Cross compilation

### Android

Specify environment variable `ANDROID_NDK_HOME` which points too root of NDK installation where to look for toolchain file

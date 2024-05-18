# nng-c-sys

[![Actions Status](https://github.com/DoumanAsh/nng-c-sys/workflows/Rust/badge.svg)](https://github.com/DoumanAsh/nng-c-sys/actions)
[![Crates.io](https://img.shields.io/crates/v/nng-c-sys.svg)](https://crates.io/crates/nng-c-sys)
[![Documentation](https://docs.rs/nng-c-sys/badge.svg)](https://docs.rs/crate/nng-c-sys/)

Bindings to [nng](https://github.com/nanomsg/nng).

Version corresponds to C library

## Features

- `http` - Builds with http code ON
- `tls` - Builds with TLS code ON

### TLS

When `tls` feature is enabled `nng` will try to look for mbedTLS installation in `/usr/local`

If regular installation is not an option, you can specify environment variable `NNG_MBEDTLS_ROOT_DIR` with path to the library.

Which means on windows you're always required to supply this variable

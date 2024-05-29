use std::env;
use std::path::PathBuf;
use std::process::Command;

const INCLUDE_PATH: &str = "nng/include";

#[cfg(feature = "build-bindgen")]
fn generate_lib() {
    println!("Generates bindings...");

    #[derive(Debug)]
    struct ParseCallbacks;

    impl bindgen::callbacks::ParseCallbacks for ParseCallbacks {
        fn int_macro(&self, name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
            if name.starts_with("NNG") {
                Some(bindgen::callbacks::IntKind::Int)
            } else {
                None
            }
        }
    }

    use std::path::PathBuf;

    const PREPEND_LIB: &'static str = "
#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub const NNG_OPT_SOCKNAME: &[u8] = b\"socket-name\0\";
pub const NNG_OPT_RAW: &[u8] = b\"raw\0\";
pub const NNG_OPT_PROTO: &[u8] = b\"protocol\0\";
pub const NNG_OPT_PROTONAME: &[u8] = b\"protocol-name\0\";
pub const NNG_OPT_PEER: &[u8] = b\"peer\0\";
pub const NNG_OPT_PEERNAME: &[u8] = b\"peer-name\0\";
pub const NNG_OPT_RECVBUF: &[u8] = b\"recv-buffer\0\";
pub const NNG_OPT_SENDBUF: &[u8] = b\"send-buffer\0\";
pub const NNG_OPT_RECVFD: &[u8] = b\"recv-fd\0\";
pub const NNG_OPT_SENDFD: &[u8] = b\"send-fd\0\";
pub const NNG_OPT_RECVTIMEO: &[u8] = b\"recv-timeout\0\";
pub const NNG_OPT_SENDTIMEO: &[u8] = b\"send-timeout\0\";
pub const NNG_OPT_LOCADDR: &[u8] = b\"local-address\0\";
pub const NNG_OPT_REMADDR: &[u8] = b\"remote-address\0\";
pub const NNG_OPT_URL: &[u8] = b\"url\0\";
pub const NNG_OPT_MAXTTL: &[u8] = b\"ttl-max\0\";
pub const NNG_OPT_RECVMAXSZ: &[u8] = b\"recv-size-max\0\";
pub const NNG_OPT_RECONNMINT: &[u8] = b\"reconnect-time-min\0\";
pub const NNG_OPT_RECONNMAXT: &[u8] = b\"reconnect-time-max\0\";
pub const NNG_OPT_PEER_GID: &[u8] = b\"ipc:peer-gid\0\";
pub const NNG_OPT_PEER_PID: &[u8] = b\"ipc:peer-pid\0\";
pub const NNG_OPT_PEER_UID: &[u8] = b\"ipc:peer-uid\0\";
pub const NNG_OPT_PEER_ZONEID: &[u8] = b\"ipc:peer-zoneid\0\";

pub const NNG_OPT_SUB_SUBSCRIBE: &[u8] = b\"sub:subscribe\0\";
pub const NNG_OPT_SUB_UNSUBSCRIBE: &[u8] = b\"sub:unsubscribe\0\";
pub const NNG_OPT_SUB_PREFNEW: &[u8] = b\"sub:prefnew\0\";

pub const NNG_OPT_PAIR1_POLY: &[u8] = b\"pair1:polyamorous\0\";

pub const NNG_OPT_REQ_RESENDTIME: &[u8] = b\"req:resend-time\0\";
pub const NNG_OPT_REQ_RESENDTICK: &[u8] = b\"req:resend-tick\0\";

pub const NNG_OPT_SURVEYOR_SURVEYTIME: &[u8] = b\"surveyor:survey-time\0\";

pub const NNG_OPT_TLS_AUTH_MODE: &[u8] = b\"tls-authmode\0\";
pub const NNG_OPT_TLS_CA_FILE: &[u8] = b\"tls-ca-file\0\";
pub const NNG_OPT_TLS_CERT_KEY_FILE: &[u8] = b\"tls-cert-key-file\0\";
pub const NNG_OPT_TLS_CONFIG: &[u8] = b\"tls-config\0\";
pub const NNG_OPT_TLS_SERVER_NAME: &[u8] = b\"tls-server-name\0\";
pub const NNG_OPT_TLS_VERIFIED: &[u8] = b\"tls-verified\0\";
pub const NNG_OPT_TLS_PEER_CN: &[u8] = b\"tls-peer-cn\0\";
pub const NNG_OPT_TLS_PEER_ALT_NAMES: &[u8] = b\"tls-peer-alt-names\0\";

pub const NNG_FLAG_ALLOC: core::ffi::c_int = 1;
pub const NNG_FLAG_NONBLOCK: core::ffi::c_int = 2;
";

    let out = PathBuf::new().join("src").join("lib.rs");

    let mut builder = bindgen::Builder::default();
    let paths = [
        //main header
        "nng.h",
        //protocols
        "protocol/bus0/bus.h",
        "protocol/pair0/pair.h",
        "protocol/pair1/pair.h",
        "protocol/pipeline0/pull.h",
        "protocol/pipeline0/push.h",
        "protocol/pubsub0/pub.h",
        "protocol/pubsub0/sub.h",
        "protocol/reqrep0/rep.h",
        "protocol/reqrep0/req.h",
        "protocol/survey0/respond.h",
        "protocol/survey0/survey.h",
        //transports
        "transport/inproc/inproc.h",
        "transport/ipc/ipc.h",
        "transport/tcp/tcp.h",
        "transport/tls/tls.h",
        "transport/ws/websocket.h",
        "supplemental/http/http.h",
        "supplemental/tls/tls.h",
        //Utils
        "supplemental/util/platform.h",
        //Experimental features
        //"nng/transport/zerotier/zerotier.h",
    ];

    for path in paths {
        builder = builder.header(format!("{INCLUDE_PATH}/nng/{path}"));
    }

    let bindings = builder
        .raw_line(PREPEND_LIB)
        .ctypes_prefix("core::ffi")
        .use_core()
        .generate_comments(false)
        .layout_tests(false)
        .size_t_is_usize(true)
        .sort_semantically(true)
        .merge_extern_blocks(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .allowlist_type("nng.+")
        .allowlist_function("nng.+")
        .clang_arg(format!("-I{INCLUDE_PATH}"))
        .parse_callbacks(Box::new(ParseCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out)
        .expect("Couldn't write bindings!");
}

#[cfg(not(feature = "build-bindgen"))]
fn generate_lib() {}

fn get_android_vars() -> Option<(PathBuf, &'static str)> {
    if let Ok(android_ndk) = env::var("ANDROID_NDK_HOME") {
        let mut toolchain_file = PathBuf::new();
        toolchain_file.push(android_ndk);
        toolchain_file.push("build");
        toolchain_file.push("cmake");
        toolchain_file.push("android.toolchain.cmake");

        let target = env::var("TARGET").unwrap();
        let abi = match target.as_str() {
            "armv7-linux-androideabi" => "armeabi-v7a",
            "aarch64-linux-android" => "arm64-v8a",
            "i686-linux-android" => "x86",
            "x86_64-linux-android" => "x86_64",
            _ => return None,
        };

        Some((toolchain_file, abi))
    } else {
        None
    }
}

fn set_cmake_define_if_present(config: &mut cmake::Config, name: &str) {
    if let Ok(value) = env::var(name) {
        config.define(name, value);
    } else if let Ok(value) = env::var(format!("CARGO_NDK_{}", name)) {
        config.define(name, value);
    } else {
        println!("cargo:warning=Unable to find Android env variable '{}'. Hope for good default...", name);
    }
}

#[cfg(feature = "tls")]
fn build_mbedtls(nng: &mut cmake::Config, is_ninja: bool) {
    const MBEDTLS: &str = "mbedtls-2.28.8";
    let mut config = cmake::Config::new(MBEDTLS);

    if let Some((toolchain_file, abi)) = get_android_vars() {
        config.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);
        config.define("ANDROID_ABI", abi);

        set_cmake_define_if_present(&mut config, "ANDROID_PLATFORM");
        set_cmake_define_if_present(&mut config, "ANDROID_STL");
        set_cmake_define_if_present(&mut config, "ANDROID_ARM_MODE");
        set_cmake_define_if_present(&mut config, "ANDROID_ARM_NEON");
    }

    if is_ninja {
        config.generator("Ninja");
    }
    config.define("ENABLE_PROGRAMS", "OFF");
    config.define("ENABLE_TESTING", "OFF");

    let mut dest = config.build();

    nng.define("MBEDTLS_ROOT_DIR", &dest);

    dest.push("lib");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-search=native={}", dest.display());
}

fn build() {
    let abs_include =
        std::fs::canonicalize(INCLUDE_PATH).expect("To get absolute path to brotlie include");
    let is_ninja = Command::new("ninja")
        .arg("--version")
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    println!("cargo:include={}", abs_include.display());

    let mut config = cmake::Config::new("nng");

    if let Some((toolchain_file, abi)) = get_android_vars() {
        config.define("CMAKE_TOOLCHAIN_FILE", toolchain_file);
        config.define("ANDROID_ABI", abi);

        set_cmake_define_if_present(&mut config, "ANDROID_PLATFORM");
        set_cmake_define_if_present(&mut config, "ANDROID_STL");
        set_cmake_define_if_present(&mut config, "ANDROID_ARM_MODE");
        set_cmake_define_if_present(&mut config, "ANDROID_ARM_NEON");
    }

    //Use ninja if present on system
    if is_ninja {
        config.generator("Ninja");
    }

    config.define("NNG_TESTS", "OFF");
    config.define("NNG_ENABLE_COMPAT", "OFF");
    //File descriptor is experimental transport so don't use it
    //idk why it is ON by default
    config.define("NNG_TRANSPORT_FDC", "OFF");

    #[cfg(not(feature = "stats"))]
    config.define("NNG_ENABLE_STATS", "OFF");
    #[cfg(feature = "stats")]
    config.define("NNG_ENABLE_STATS", "ON");

    #[cfg(not(feature = "http"))]
    config.define("NNG_ENABLE_HTTP", "OFF");
    #[cfg(feature = "http")]
    config.define("NNG_ENABLE_HTTP", "ON");

    #[cfg(not(feature = "websocket"))]
    {
        config.define("NNG_TRANSPORT_WS", "OFF");
        config.define("NNG_TRANSPORT_WSS", "OFF");
    }

    #[cfg(feature = "websocket")]
    {
        config.define("NNG_TRANSPORT_WS", "ON");
        #[cfg(feature = "tls")]
        config.define("NNG_TRANSPORT_WSS", "ON");
    }

    #[cfg(not(feature = "tls"))]
    {
        config.define("NNG_TRANSPORT_TLS", "OFF");
        config.define("NNG_ENABLE_TLS", "OFF");
    }
    #[cfg(feature = "tls")]
    {
        build_mbedtls(&mut config, is_ninja);

        config.define("NNG_TRANSPORT_TLS", "ON");
        config.define("NNG_ENABLE_TLS", "ON");
    }

    println!("cargo:rustc-link-lib=static=nng");
    let mut dest = config.build();
    dest.push("lib");
    println!("cargo:rustc-link-search=native={}", dest.display());
}

fn main() {
    generate_lib();
    build();
}

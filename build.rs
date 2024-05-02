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

        //Utils
        "supplemental/util/platform.h",

        //Experimental features
        //"nng/transport/zerotier/zerotier.h",
    ];

    for path in paths {
        builder = builder.header(format!("{INCLUDE_PATH}/nng/{path}"));
    }

    let bindings = builder.raw_line(PREPEND_LIB)
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

    bindings.write_to_file(out).expect("Couldn't write bindings!");
}

#[cfg(not(feature = "build-bindgen"))]
fn generate_lib() {
}

fn build() {
    let abs_include = std::fs::canonicalize(INCLUDE_PATH).expect("To get absolute path to brotlie include");
    println!("cargo:include={}", abs_include.display());

    let mut config = cmake::Config::new("nng");
    config.define("NNG_TESTS", "OFF");
    config.define("NNG_ENABLE_COMPAT", "OFF");
    config.define("NNG_TRANSPORT_WS", "OFF");
    //File descriptor is experimental transport so don't use it
    //idk why it is ON by default
    config.define("NNG_TRANSPORT_FDC", "OFF");

    #[cfg(not(feature = "http"))]
    config.define("NNG_ENABLE_HTTP", "OFF");
    #[cfg(feature = "http")]
    config.define("NNG_ENABLE_HTTP", "ON");

    println!("cargo:rustc-link-lib=static=nng");
    let mut dest = config.build();
    dest.push("lib");
    println!("cargo:rustc-link-search=native={}", dest.display());
}

fn main() {
    generate_lib();
    build();
}

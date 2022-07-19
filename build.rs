use std::path::Path;

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_feature = match std::env::var("CARGO_CFG_TARGET_FEATURE") {
        Ok(tf) => tf,
        Err(_) => String::new(),
    };
    // ignoring lib sodium on target features argument
    if target_feature.contains("crt-static") {
        return;
    }
    // Do not build bindgen if feature libsodium is not present
    if std::env::var("CARGO_FEATURE_LIBSODIUM").is_err() {
        return;
    }

    // ignoring build for WASM arch or Windows OS.
    if target_arch == "wasm32" || target_os == "windows" {
        return;
    }
    // Write the bindings to the $OUT_DIR/bindings.rs File.
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let header = match std::env::var("LIBSODIUM_PATH") {
        Ok(path) => path + "/sodium.h",
        Err(_) => match target_os.as_str() {
            "macos" => "/usr/local/include/sodium.h",
            _ => "/usr/include/sodium.h",
        }
        .to_string(),
    };

    if !Path::new(&header).exists() {
        return;
    }

    // generate our FFI code for the C API
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header(header)
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings for lib sodium");
    bindings
        .write_to_file(out_path.join("sodium_bindings.rs"))
        .expect("Couldn't write bindings for sodium!");

    println!("cargo:rustc-link-lib=dylib=sodium");
}

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/bpf/wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("src/bpf/map_structs.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file("src/bpf/bindings.rs")
        .expect("Couldn't write bindings!");
}

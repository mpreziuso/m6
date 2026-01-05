fn main() {
    // Tell cargo to pass the linker script to the linker
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{}/kernel.ld", manifest_dir);

    // Rerun if linker script changes
    println!("cargo:rerun-if-changed=kernel.ld");
}
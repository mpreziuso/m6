fn main() {
    // Tell cargo to pass the linker script to the linker
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{}/kernel.ld", manifest_dir);

    // KASLR: build the kernel as a position-independent executable so the
    // bootloader can load it at a random virtual base. lld emits the absolute
    // data relocations as R_AARCH64_RELATIVE entries in .rela.dyn, which the
    // early self-relocation trampoline in _start applies before any absolute
    // reference is used. `-z notext` permits text relocations (the kernel
    // relocates before it enforces W^X); `--no-dynamic-linker` marks the image
    // as freestanding (no interpreter).
    println!("cargo:rustc-link-arg=-pie");
    println!("cargo:rustc-link-arg=-znotext");
    println!("cargo:rustc-link-arg=--no-dynamic-linker");

    // Rerun if linker script changes
    println!("cargo:rerun-if-changed=kernel.ld");
}

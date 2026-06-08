fn main() {
    // Enable zerocopy IntoBytes derive for unions.
    println!("cargo::rustc-cfg=zerocopy_derive_union_into_bytes");
}

fn main() {
    #[cfg(feature = "sve_backend")]
    compile_sve_backend();
}

#[cfg(feature = "sve_backend")]
fn compile_sve_backend() {
    println!("cargo:rerun-if-changed=sve/src/sve_inv_sbox.c");
    println!("cargo:rerun-if-changed=sve/src/sve_inv_sbox.h");
    println!("cargo:rerun-if-changed=sve/src/inv_sbox.h");
    println!("cargo:rerun-if-changed=sve/src/inv_sbox.h");

    cc::Build::new()
        .file("sve/src/sve_inv_sbox.c")
        .file("sve/src/inv_sbox.c")
        .flag("-march=armv8-a+sve")
        .compile("sve");
}

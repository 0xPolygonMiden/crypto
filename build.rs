fn main() {
    #[cfg(feature = "arch-arm64-sve")]
    compile_arch_arm64_sve();
}

#[cfg(feature = "arch-arm64-sve")]
fn compile_arch_arm64_sve() {
    println!("cargo:rerun-if-changed=arch/arm64-sve/rpo/library.c");
    println!("cargo:rerun-if-changed=arch/arm64-sve/rpo/library.h");
    println!("cargo:rerun-if-changed=arch/arm64-sve/rpo/rpo_hash.h");

    cc::Build::new()
        .file("arch/arm64-sve/rpo/library.c")
        .flag("-march=armv8-a+sve")
        .flag("-O3")
        .compile("rpo_sve");
}

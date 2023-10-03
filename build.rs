fn main() {
    #[cfg(feature = "std")]
    compile_rpo_falcon();

    #[cfg(feature = "arch-arm64-sve")]
    compile_arch_arm64_sve();
}

#[cfg(feature = "std")]
fn compile_rpo_falcon() {
    use std::path::PathBuf;

    let target_dir: PathBuf = ["PQClean", "crypto_sign", "falcon-512", "clean"].iter().collect();
    let common_dir: PathBuf = ["PQClean", "common"].iter().collect();
    let rpo_dir: PathBuf = ["src", "dsa", "rpo_falcon512", "falcon_c"].iter().collect();

    let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
    let common_files = glob::glob(common_dir.join("*.c").to_str().unwrap()).unwrap();
    let rpo_files = glob::glob(rpo_dir.join("*.c").to_str().unwrap()).unwrap();

    cc::Build::new()
        .include(&common_dir)
        .include(target_dir)
        .files(scheme_files.into_iter().map(|p| p.unwrap().to_string_lossy().into_owned()))
        .files(common_files.into_iter().map(|p| p.unwrap().to_string_lossy().into_owned()))
        .files(rpo_files.into_iter().map(|p| p.unwrap().to_string_lossy().into_owned()))
        .compile("falcon-512_clean");
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

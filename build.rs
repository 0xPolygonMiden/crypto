fn main() {
    #[cfg(feature = "std")]
    compile_rpo_falcon();

    #[cfg(target_feature = "sve")]
    compile_arch_arm64_sve();
}

#[cfg(feature = "std")]
fn compile_rpo_falcon() {
    use std::path::PathBuf;

    const RPO_FALCON_PATH: &str = "src/dsa/rpo_falcon512/falcon_c";

    println!("cargo:rerun-if-changed={RPO_FALCON_PATH}/falcon.h");
    println!("cargo:rerun-if-changed={RPO_FALCON_PATH}/falcon.c");
    println!("cargo:rerun-if-changed={RPO_FALCON_PATH}/rpo.h");
    println!("cargo:rerun-if-changed={RPO_FALCON_PATH}/rpo.c");

    let target_dir: PathBuf = ["PQClean", "crypto_sign", "falcon-512", "clean"].iter().collect();
    let common_dir: PathBuf = ["PQClean", "common"].iter().collect();

    let scheme_files = glob::glob(target_dir.join("*.c").to_str().unwrap()).unwrap();
    let common_files = glob::glob(common_dir.join("*.c").to_str().unwrap()).unwrap();

    cc::Build::new()
        .include(&common_dir)
        .include(target_dir)
        .files(scheme_files.into_iter().map(|p| p.unwrap().to_string_lossy().into_owned()))
        .files(common_files.into_iter().map(|p| p.unwrap().to_string_lossy().into_owned()))
        .file(format!("{RPO_FALCON_PATH}/falcon.c"))
        .file(format!("{RPO_FALCON_PATH}/rpo.c"))
        .flag("-O3")
        .compile("rpo_falcon512");
}

#[cfg(target_feature = "sve")]
fn compile_arch_arm64_sve() {
    const RPO_SVE_PATH: &str = "arch/arm64-sve/rpo";

    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/library.c");
    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/library.h");
    println!("cargo:rerun-if-changed={RPO_SVE_PATH}/rpo_hash.h");

    cc::Build::new()
        .file(format!("{RPO_SVE_PATH}/library.c"))
        .flag("-march=armv8-a+sve")
        .flag("-O3")
        .compile("rpo_sve");
}

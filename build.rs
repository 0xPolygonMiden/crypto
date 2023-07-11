fn main() {
    let src = [
        "src/dsa/falcon/falcon_c/codec.c",
        "src/dsa/falcon/falcon_c/common.c",
        "src/dsa/falcon/falcon_c/falcon.c",
        "src/dsa/falcon/falcon_c/fft.c",
        "src/dsa/falcon/falcon_c/fpr.c",
        "src/dsa/falcon/falcon_c/keygen.c",
        "src/dsa/falcon/falcon_c/rng.c",
        "src/dsa/falcon/falcon_c/shake.c",
        "src/dsa/falcon/falcon_c/rpo.c",
        "src/dsa/falcon/falcon_c/sign.c",
        "src/dsa/falcon/falcon_c/vrfy.c",
    ];
    let mut builder = cc::Build::new();

    let build = builder.files(src.iter()).include("falcon_c").flag("-Wno-unused-parameter");

    build.compile("falcon");
}

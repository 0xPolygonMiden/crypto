pub mod falcon;

#[test]
fn test_falcon_verification() {
    let keypair = falcon::KeyPair::keygen();

    let message = "Hello world!".as_bytes();

    let signature = keypair.secret_key.sign(message);
    assert!(keypair.public_key.verify_c(message, &signature));
    assert!(keypair.public_key.verify_rs(message, &signature));
}

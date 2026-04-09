use bitaiir_crypto::{Address, PrivateKey, signature, wif};

fn main() {
    let priv_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    let bytes: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
    let private_key = PrivateKey::from_bytes(&bytes).expect("valid scalar");
    let public_key = private_key.public_key();

    let wif_c = wif::encode(&private_key, true);
    let address = Address::from_compressed_public_key(&public_key);

    println!("Address: {address}");
    println!("WIF:     {wif_c}");

    let message = "Hello from BitAiir";
    let signed = signature::sign_message(&wif_c, message).expect("signing ok");
    println!("\nSigned message: {message:?}");
    println!("Signature:      {}", signed.signature);

    let outcome =
        signature::verify_message(signed.address.as_str(), &signed.message, &signed.signature)
            .expect("verify ok");
    println!("Verified:       {}", outcome.verified);
}

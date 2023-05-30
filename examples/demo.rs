//! This demo is used in `README.md`.

use cosmian_crypto_core::{
    asymmetric_crypto::DhKeyPair,
    kdf,
    reexport::rand_core::SeedableRng,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, key::SymmetricKey, Dem},
    CsRng, FixedSizeKey,
};

fn main() {
    // // The random generator should be instantiated at the highest possible
    // // level since its creation is relatively costly.
    // let mut rng = CsRng::from_entropy();

    // // Secret message we want to transmit privately.
    // let plaintext = b"My secret message";

    // // Publicly known information. It can be used to enforce context separation.
    // let additional_data = Some(b"Some public tag".as_slice());

    // // Setting of the asymmetric keys
    // let bob_keypair = R25519KeyPair::new(&mut rng);
    // let alice_keypair = R25519KeyPair::new(&mut rng);

    // // In real world applications, DHKEX is often used to derive a symmetric key.
    // let shared_secret = bob_keypair.public_key() * alice_keypair.private_key();

    // // Derivation of a secret key from the DHKEX shared secret.
    // const KEY_DERIVATION_INFO: &[u8] = b"Curve25519 KDF derivation";
    // const KEY_LENGTH: usize = Aes256GcmCrypto::KEY_LENGTH;
    // let symmetric_key = SymmetricKey::<KEY_LENGTH>::try_from_bytes(kdf!(
    //     KEY_LENGTH,
    //     &shared_secret.to_bytes(),
    //     KEY_DERIVATION_INFO
    // ))
    // .expect("invalid KDF length");

    // // DEM encapsulation using AES256-GCM. In order to prevent nonce reuse,
    // // the nonce is managed internally.
    // let c = Aes256GcmCrypto::encrypt(&mut rng, &symmetric_key, plaintext, additional_data).unwrap();

    // // DEM decryption using AES256-GCM. The additional data used should be the
    // // same as the one given for encryption.
    // let res = Aes256GcmCrypto::decrypt(&symmetric_key, &c, additional_data).unwrap();

    // assert_eq!(res, plaintext, "Decryption failed!");

    // println!("Message has been privately and successfully transmitted!");
}

use std::sync::{Arc, Mutex};

use rand_chacha::rand_core::SeedableRng;

use crate::CsRng;

use super::{
    ecies::Ecies,
    ristretto_25519::{EciesR25519Aes256gcmSha256Xof, R25519KeyPair},
    DhKeyPair,
};

#[test]
fn ecies_r25519_aes256gcm_sha256_xof_test() {
    let arc_rng = Arc::new(Mutex::new(CsRng::from_entropy()));
    let ecies = EciesR25519Aes256gcmSha256Xof::new_from_rng(arc_rng.clone());
    // generate a key pair
    let keypair = {
        let mut rng = arc_rng.lock().unwrap();
        R25519KeyPair::new(&mut *rng)
    };
    // encrypt
    let plaintext = b"Hello World!";
    let ciphertext = ecies.encrypt(&keypair.public_key(), plaintext).unwrap();
    // decrypt
    let plaintext2 = ecies.decrypt(&keypair.private_key(), &ciphertext).unwrap();
    // assert
    assert_eq!(plaintext, &plaintext2[..]);
}

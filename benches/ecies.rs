use std::sync::{Arc, Mutex};

use cosmian_crypto_core::{
    asymmetric_crypto::{
        ecies::Ecies,
        ristretto_25519::{EciesR25519Aes256gcmSha256Xof, R25519KeyPair},
        DhKeyPair,
    },
    CsRng,
};
use criterion::Criterion;
use rand_chacha::rand_core::SeedableRng;

pub fn bench_ecies_r25519_aes256gcm_sha256_xof_encrypt(c: &mut Criterion) {
    let arc_rng = Arc::new(Mutex::new(CsRng::from_entropy()));
    let ecies = EciesR25519Aes256gcmSha256Xof::new_from_rng(arc_rng.clone());
    // generate a key pair
    let keypair = {
        let mut rng = arc_rng.lock().unwrap();
        R25519KeyPair::new(&mut *rng)
    };
    // encrypt
    let plaintext = b"Hello World!";
    c.bench_function(
        "Bench ECIES encryption using the Ristretto Curve 25519",
        |b| b.iter(|| ecies.encrypt(&keypair.public_key(), plaintext).unwrap()),
    );
}

pub fn bench_ecies_r25519_aes256gcm_sha256_xof_decrypt(c: &mut Criterion) {
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
    c.bench_function(
        "Bench ECIES decryption using the Ristretto Curve 25519",
        |b| b.iter(|| ecies.decrypt(&keypair.private_key(), &ciphertext).unwrap()),
    );
}

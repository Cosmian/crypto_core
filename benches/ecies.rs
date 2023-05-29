use std::sync::{Arc, Mutex};

use cosmian_crypto_core::{
    asymmetric_crypto::{
        DhKeyPair, Ecies, EciesR25519Aes256gcmSha256Xof, EciesSalsaSealBox, R25519KeyPair,
        X25519PrivateKey, X25519PublicKey,
    },
    CsRng, SecretKey,
};
use criterion::{black_box, Criterion};
use rand_chacha::rand_core::SeedableRng;

pub fn ecies_r25519_aes256gcm_sha256_xof_bench(c: &mut Criterion) {
    let arc_rng = Arc::new(Mutex::new(CsRng::from_entropy()));
    let ecies = EciesR25519Aes256gcmSha256Xof::new_from_rng(arc_rng.clone());
    // generate a key pair
    let keypair = {
        let mut rng = arc_rng.lock().unwrap();
        R25519KeyPair::new(&mut *rng)
    };
    // encrypt
    let plaintext = b"Hello World!";

    c.bench_function("ECIES r25519_aes256gcm_sha256_xof encrypt", |b| {
        b.iter(|| {
            let ciphertext = ecies.encrypt(&keypair.public_key(), plaintext).unwrap();
            black_box(ciphertext);
        });
    });

    let ciphertext = ecies.encrypt(&keypair.public_key(), plaintext).unwrap();

    // decrypt
    c.bench_function("ECIES r25519_aes256gcm_sha256_xof decrypt", |b| {
        b.iter(|| {
            let plaintext2 = ecies.decrypt(&keypair.private_key(), &ciphertext).unwrap();
            black_box(plaintext2);
        });
    });
}

pub fn ecies_salsa_seal_box(c: &mut Criterion) {
    let arc_rng = Arc::new(Mutex::new(CsRng::from_entropy()));
    let ecies = EciesSalsaSealBox::new_from_rng(arc_rng.clone());
    // generate a key pair
    let private_key = {
        let mut rng = arc_rng.lock().unwrap();
        X25519PrivateKey::new(&mut *rng)
    };
    let public_key = X25519PublicKey::from(&private_key);
    // encrypt
    let plaintext = b"Hello World!";

    c.bench_function("ECIES salsa_sealbox encrypt", |b| {
        b.iter(|| {
            let ciphertext = ecies.encrypt(&public_key, plaintext).unwrap();
            black_box(ciphertext);
        });
    });

    let ciphertext = ecies.encrypt(&public_key, plaintext).unwrap();

    // decrypt
    c.bench_function("ECIES salsa_sealbox decrypt", |b| {
        b.iter(|| {
            let plaintext2 = ecies.decrypt(&private_key, &ciphertext).unwrap();
            black_box(plaintext2);
        });
    });
}

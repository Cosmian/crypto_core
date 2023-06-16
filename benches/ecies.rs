use cosmian_crypto_core::{
    CsRng, Ecies, EciesR25519Aes128, EciesSalsaSealBox, EciesX25519XChaCha20, R25519PrivateKey,
    R25519PublicKey, RandomFixedSizeCBytes, X25519PrivateKey, X25519PublicKey,
};
use criterion::Criterion;
use rand_chacha::rand_core::SeedableRng;

pub fn ecies_r25519_aes128gcm_bench(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    // generate a key pair
    let private_key = R25519PrivateKey::new(&mut rng);
    let public_key = R25519PublicKey::from(&private_key);
    // encrypt
    let plaintext = b"Hello World!";

    c.bench_function("ECIES r25519_aes128gcm encrypt", |b| {
        b.iter(|| {
            EciesR25519Aes128::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
        });
    });

    let ciphertext = EciesR25519Aes128::encrypt(&mut rng, &public_key, plaintext, None).unwrap();

    // decrypt
    c.bench_function("ECIES r25519_aes128gcm decrypt", |b| {
        b.iter(|| {
            EciesR25519Aes128::decrypt(&private_key, &ciphertext, None).unwrap();
        });
    });
}

pub fn ecies_salsa_seal_box(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    // generate a key pair
    let private_key = X25519PrivateKey::new(&mut rng);
    let public_key = X25519PublicKey::from(&private_key);
    // encrypt
    let plaintext = b"Hello World!";

    c.bench_function("ECIES salsa_sealbox encrypt", |b| {
        b.iter(|| {
            EciesSalsaSealBox::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
        });
    });

    let ciphertext = EciesSalsaSealBox::encrypt(&mut rng, &public_key, plaintext, None).unwrap();

    // decrypt
    c.bench_function("ECIES salsa_sealbox decrypt", |b| {
        b.iter(|| {
            EciesSalsaSealBox::decrypt(&private_key, &ciphertext, None).unwrap();
        });
    });
}

pub fn ecies_x25519_xchacha20(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    // generate a key pair
    let private_key = X25519PrivateKey::new(&mut rng);
    let public_key = X25519PublicKey::from(&private_key);
    // encrypt
    let plaintext = b"Hello World!";

    c.bench_function("ECIES X25519 XChaCha20 Poly1305 encrypt", |b| {
        b.iter(|| {
            EciesX25519XChaCha20::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
        });
    });

    let ciphertext = EciesX25519XChaCha20::encrypt(&mut rng, &public_key, plaintext, None).unwrap();

    // decrypt
    c.bench_function("ECIES X25519 XChaCha20 Poly1305 decrypt", |b| {
        b.iter(|| {
            EciesX25519XChaCha20::decrypt(&private_key, &ciphertext, None).unwrap();
        });
    });
}

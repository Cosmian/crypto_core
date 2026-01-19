#![allow(dead_code)]
#![cfg(feature = "default")]
use cosmian_crypto_core::{
    CsRng, Ecies, EciesAes128, EciesEcPrivateKey, EciesEcPublicKey, EciesR25519Aes128,
    EciesSalsaSealBox, EciesX25519Aes128, EciesX25519XChaCha20, R25519CurvePoint, R25519PrivateKey,
    X25519CurvePoint, X25519PrivateKey,
};
use criterion::Criterion;
use rand_chacha::rand_core::SeedableRng;

pub(crate) fn ecies_r25519_aes128gcm_bench(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    // generate a key pair
    let private_key = R25519PrivateKey::new(&mut rng);
    let public_key = R25519CurvePoint::from(&private_key);
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

pub(crate) fn ecies_salsa_seal_box(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    // generate a key pair
    let private_key = X25519PrivateKey::new(&mut rng);
    let public_key = X25519CurvePoint::from(&private_key);
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

pub(crate) fn ecies_x25519_xchacha20(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    // generate a key pair
    let private_key = X25519PrivateKey::new(&mut rng);
    let public_key = X25519CurvePoint::from(&private_key);
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

pub(crate) fn ecies_x25519_aes128(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    // generate a key pair
    let private_key = X25519PrivateKey::new(&mut rng);
    let public_key = X25519CurvePoint::from(&private_key);
    // encrypt
    let plaintext = b"Hello World!";

    c.bench_function("ECIES X25519 Aes128 GCM encrypt", |b| {
        b.iter(|| {
            EciesX25519Aes128::encrypt(&mut rng, &public_key, plaintext, None).unwrap();
        });
    });

    let ciphertext = EciesX25519Aes128::encrypt(&mut rng, &public_key, plaintext, None).unwrap();

    // decrypt
    c.bench_function("ECIES X25519 Aes128 GCM decrypt", |b| {
        b.iter(|| {
            EciesX25519Aes128::decrypt(&private_key, &ciphertext, None).unwrap();
        });
    });
}

fn ecies_aes218<
    const PRIVATE_KEY_LENGTH: usize,
    const PUBLIC_KEY_LENGTH: usize,
    PublicKey: EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH>,
>(
    curve_name: &str,
    c: &mut Criterion,
) {
    let mut rng = CsRng::from_entropy();
    // generate a key pair
    let private_key = PublicKey::PrivateKey::new(&mut rng);
    let public_key = PublicKey::from_private_key(&private_key);

    // encrypt
    let plaintext = b"Hello World!";

    c.bench_function(&format!("ECIES {curve_name} AES 128 GCM encrypt"), |b| {
        b.iter(|| {
            EciesAes128::<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>::encrypt(
                &mut rng,
                &public_key,
                plaintext,
                None,
            )
            .unwrap();
        });
    });

    let ciphertext = EciesAes128::<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>::encrypt(
        &mut rng,
        &public_key,
        plaintext,
        None,
    )
    .unwrap();

    c.bench_function(&format!("ECIES {curve_name} AES 128 GCM decrypt"), |b| {
        b.iter(|| {
            EciesAes128::<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, PublicKey>::decrypt(
                &private_key,
                &ciphertext,
                None,
            )
            .unwrap();
        });
    });
}

pub(crate) fn ecies_nist_aes128(c: &mut Criterion) {
    ecies_aes218::<
        { cosmian_crypto_core::P192_PRIVATE_KEY_LENGTH },
        { cosmian_crypto_core::P192_PUBLIC_KEY_LENGTH },
        cosmian_crypto_core::P192PublicKey,
    >("P192", c);
    ecies_aes218::<
        { cosmian_crypto_core::P224_PRIVATE_KEY_LENGTH },
        { cosmian_crypto_core::P224_PUBLIC_KEY_LENGTH },
        cosmian_crypto_core::P224PublicKey,
    >("P224", c);
    ecies_aes218::<
        { cosmian_crypto_core::P256_PRIVATE_KEY_LENGTH },
        { cosmian_crypto_core::P256_PUBLIC_KEY_LENGTH },
        cosmian_crypto_core::P256PublicKey,
    >("P256", c);
    ecies_aes218::<
        { cosmian_crypto_core::P384_PRIVATE_KEY_LENGTH },
        { cosmian_crypto_core::P384_PUBLIC_KEY_LENGTH },
        cosmian_crypto_core::P384PublicKey,
    >("P384", c);
}

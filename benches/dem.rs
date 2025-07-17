#![allow(dead_code)]
#![cfg(feature = "default")]
use cosmian_crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, CsRng, Dem, DemInPlace, Instantiable, Nonce,
    RandomFixedSizeCBytes, SymmetricKey, XChaCha20Poly1305,
};
use criterion::Criterion;

/// Size of the message used in the benchmarks
const MSG_LENGTH: usize = 2048;

pub(crate) fn bench_symmetric_encryption_combined(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    // keys
    let key16 = SymmetricKey::new(&mut rng);
    let key32 = SymmetricKey::new(&mut rng);

    // message
    let mut msg = [0; MSG_LENGTH];
    rng.fill_bytes(&mut msg);

    //nonce
    let nonce = Nonce::new(&mut rng);

    c.bench_function("AES 128 GCM instantiation", |b| {
        b.iter(|| Aes128Gcm::new(&key16));
    });

    //AES 128 GCM
    let aes_128_gcm = Aes128Gcm::new(&key16);

    c.bench_function(
        "AES 128 GCM DEM encryption combined of a 2048-bytes message without additional data",
        |b| b.iter(|| aes_128_gcm.encrypt(&nonce, &msg, None).unwrap()),
    );

    c.bench_function("AES 256 GCM instantiation", |b| {
        b.iter(|| Aes256Gcm::new(&key32));
    });

    // AES 256 GCM
    let aes_256_gcm = Aes256Gcm::new(&key32);
    c.bench_function(
        "AES 256 GCM DEM encryption combined of a 2048-bytes message without additional data",
        |b| b.iter(|| aes_256_gcm.encrypt(&nonce, &msg, None).unwrap()),
    );

    // Chacha20 Poly1305
    let chacha20_poly1305 = ChaCha20Poly1305::new(&key32);
    c.bench_function(
        "ChaCha20 Poly1305 DEM encryption combined of a 2048-bytes message without additional data",
        |b| b.iter(|| chacha20_poly1305.encrypt(&nonce, &msg, None).unwrap()),
    );

    // XChacha20 Poly1305
    let xchacha20_poly1305 = XChaCha20Poly1305::new(&key32);
    let nonce = Nonce::new(&mut rng);
    c.bench_function(
        "XChaCha20 Poly1305 DEM encryption combined of a 2048-bytes message without additional \
         data",
        |b| b.iter(|| xchacha20_poly1305.encrypt(&nonce, &msg, None).unwrap()),
    );
}

pub(crate) fn bench_symmetric_decryption_combined(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    // keys
    let key16 = SymmetricKey::new(&mut rng);
    let key32 = SymmetricKey::new(&mut rng);

    // message
    let mut msg = [0; MSG_LENGTH];
    rng.fill_bytes(&mut msg);

    //nonce
    let nonce = Nonce::new(&mut rng);

    //AES 128 GCM
    let aes_128_gcm = Aes128Gcm::new(&key16);

    let enc_aes_128_gcm = aes_128_gcm.encrypt(&nonce, &msg, None).unwrap();
    c.bench_function(
        "AES 128 GCM DEM decryption combined of a 2048-bytes message without additional data",
        |b| b.iter(|| aes_128_gcm.decrypt(&nonce, &enc_aes_128_gcm, None).unwrap()),
    );

    // AES 256 GCM
    let aes_256_gcm = Aes256Gcm::new(&key32);

    let enc_aes_256_gcm = aes_256_gcm.encrypt(&nonce, &msg, None).unwrap();
    c.bench_function(
        "AES 256 GCM DEM decryption combined of a 2048-bytes message without additional data",
        |b| b.iter(|| aes_256_gcm.decrypt(&nonce, &enc_aes_256_gcm, None).unwrap()),
    );

    // Chacha20 Poly1305
    let chacha20_poly1305 = ChaCha20Poly1305::new(&key32);
    let enc_chacha20_poly1305 = chacha20_poly1305.encrypt(&nonce, &msg, None).unwrap();
    c.bench_function(
        "ChaCha20 Poly1305 DEM decryption combined of a 2048-bytes message without additional data",
        |b| {
            b.iter(|| {
                chacha20_poly1305
                    .decrypt(&nonce, &enc_chacha20_poly1305, None)
                    .unwrap()
            });
        },
    );

    // XChacha20 Poly1305
    let xchacha20_poly1305 = XChaCha20Poly1305::new(&key32);
    let nonce = Nonce::new(&mut rng);
    let enc_xchacha20_poly1305 = xchacha20_poly1305.encrypt(&nonce, &msg, None).unwrap();
    c.bench_function(
        "XChaCha20 Poly1305 DEM decryption combined of a 2048-bytes message without additional \
         data",
        |b| {
            b.iter(|| {
                xchacha20_poly1305
                    .decrypt(&nonce, &enc_xchacha20_poly1305, None)
                    .unwrap()
            });
        },
    );
}

pub(crate) fn bench_symmetric_encryption_in_place(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    // keys
    let key16 = SymmetricKey::new(&mut rng);
    let key32 = SymmetricKey::new(&mut rng);

    // message
    let mut msg = [0; MSG_LENGTH];
    rng.fill_bytes(&mut msg);

    //nonce
    let nonce = Nonce::new(&mut rng);

    c.bench_function("AES 128 GCM instantiation", |b| {
        b.iter(|| Aes128Gcm::new(&key16));
    });

    //AES 128 GCM
    let aes_128_gcm = Aes128Gcm::new(&key16);

    c.bench_function(
        "AES 128 GCM DEM encryption in place of a 2048-bytes message without additional data",
        |b| {
            b.iter(|| {
                aes_128_gcm
                    .encrypt_in_place_detached(&nonce, &mut msg, None)
                    .unwrap()
            });
        },
    );

    c.bench_function("AES 256 GCM instantiation", |b| {
        b.iter(|| Aes256Gcm::new(&key32));
    });

    // AES 256 GCM
    let aes_256_gcm = Aes256Gcm::new(&key32);
    c.bench_function(
        "AES 256 GCM DEM encryption in place of a 2048-bytes message without additional data",
        |b| {
            b.iter(|| {
                aes_256_gcm
                    .encrypt_in_place_detached(&nonce, &mut msg, None)
                    .unwrap()
            });
        },
    );

    // Chacha20 Poly1305
    let chacha20_poly1305 = ChaCha20Poly1305::new(&key32);
    c.bench_function(
        "ChaCha20 Poly1305 DEM encryption in place of a 2048-bytes message without additional data",
        |b| {
            b.iter(|| {
                chacha20_poly1305
                    .encrypt_in_place_detached(&nonce, &mut msg, None)
                    .unwrap()
            });
        },
    );

    // XChacha20 Poly1305
    let xchacha20_poly1305 = XChaCha20Poly1305::new(&key32);
    let nonce = Nonce::new(&mut rng);
    c.bench_function(
        "XChaCha20 Poly1305 DEM encryption in place of a 2048-bytes message without additional \
         data",
        |b| {
            b.iter(|| {
                xchacha20_poly1305
                    .encrypt_in_place_detached(&nonce, &mut msg, None)
                    .unwrap()
            });
        },
    );
}

pub(crate) fn bench_symmetric_decryption_in_place(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    // keys
    let key16 = SymmetricKey::new(&mut rng);
    let key32 = SymmetricKey::new(&mut rng);

    // message
    let mut bytes = [0; MSG_LENGTH];
    rng.fill_bytes(&mut bytes);

    //nonce
    let nonce = Nonce::new(&mut rng);

    //AES 128 GCM
    let aes_128_gcm = Aes128Gcm::new(&key16);

    let tag_aes_128_gcm = aes_128_gcm
        .encrypt_in_place_detached(&nonce, &mut bytes, None)
        .unwrap();
    c.bench_function(
        "AES 128 GCM DEM decryption in place of a 2048-bytes message without additional data",
        |b| {
            b.iter_batched(
                || bytes,
                |mut bytes| {
                    aes_128_gcm
                        .decrypt_in_place_detached(&nonce, &mut bytes, &tag_aes_128_gcm, None)
                        .unwrap();
                },
                criterion::BatchSize::SmallInput,
            );
        },
    );

    // AES 256 GCM
    let aes_256_gcm = Aes256Gcm::new(&key32);

    let tag_aes_256_gcm = aes_256_gcm
        .encrypt_in_place_detached(&nonce, &mut bytes, None)
        .unwrap();
    c.bench_function(
        "AES 256 GCM DEM decryption in place of a 2048-bytes message without additional data",
        |b| {
            b.iter_batched(
                || bytes,
                |mut bytes| {
                    aes_256_gcm
                        .decrypt_in_place_detached(&nonce, &mut bytes, &tag_aes_256_gcm, None)
                        .unwrap();
                },
                criterion::BatchSize::SmallInput,
            );
        },
    );

    // Chacha20 Poly1305
    let chacha20_poly1305 = ChaCha20Poly1305::new(&key32);
    let tag_chacha20_poly1305 = chacha20_poly1305
        .encrypt_in_place_detached(&nonce, &mut bytes, None)
        .unwrap();
    c.bench_function(
        "ChaCha20 Poly1305 DEM decryption in place of a 2048-bytes message without additional data",
        |b| {
            b.iter_batched(
                || bytes,
                |mut bytes| {
                    chacha20_poly1305
                        .decrypt_in_place_detached(&nonce, &mut bytes, &tag_chacha20_poly1305, None)
                        .unwrap();
                },
                criterion::BatchSize::SmallInput,
            );
        },
    );

    // XChacha20 Poly1305
    let xchacha20_poly1305 = XChaCha20Poly1305::new(&key32);
    let nonce = Nonce::new(&mut rng);
    let tag_xchacha20_poly1305 = xchacha20_poly1305
        .encrypt_in_place_detached(&nonce, &mut bytes, None)
        .unwrap();
    c.bench_function(
        "XChaCha20 Poly1305 DEM decryption in place of a 2048-bytes message without additional \
         data",
        |b| {
            b.iter_batched(
                || bytes,
                |mut bytes| {
                    xchacha20_poly1305
                        .decrypt_in_place_detached(
                            &nonce,
                            &mut bytes,
                            &tag_xchacha20_poly1305,
                            None,
                        )
                        .unwrap();
                },
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

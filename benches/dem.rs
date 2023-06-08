/// Size of the message used in the benchmarks
use cosmian_crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    symmetric_crypto::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, Dem, Nonce, SymmetricKey},
    CsRng, RandomFixedSizeCBytes,
};
use criterion::Criterion;

const MSG_LENGTH: usize = 2048;

pub fn bench_symmetric_encryption(c: &mut Criterion) {
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
        b.iter(|| Aes128Gcm::new(&key16))
    });

    //AES 128 GCM
    let aes_128_gcm = Aes128Gcm::new(&key16);

    c.bench_function(
        "AES 128 GCM DEM encryption of a 2048-bytes message without additional data",
        |b| b.iter(|| aes_128_gcm.encrypt(&nonce, &msg, None).unwrap()),
    );

    c.bench_function("AES 256 GCM instantiation", |b| {
        b.iter(|| Aes256Gcm::new(&key32))
    });

    // AES 256 GCM
    let aes_256_gcm = Aes256Gcm::new(&key32);

    c.bench_function(
        "AES 256 GCM DEM encryption of a 2048-bytes message without additional data",
        |b| b.iter(|| aes_256_gcm.encrypt(&nonce, &msg, None).unwrap()),
    );

    // Chacha20 Poly1305
    let chacha20_poly1305 = ChaCha20Poly1305::new(&key32);

    c.bench_function(
        "ChaCha20 Poly1305 DEM encryption of a 2048-bytes message without additional data",
        |b| b.iter(|| chacha20_poly1305.encrypt(&nonce, &msg, None).unwrap()),
    );
}

pub fn bench_symmetric_decryption(c: &mut Criterion) {
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
        "AES 128 GCM DEM decryption of a 2048-bytes message without additional data",
        |b| b.iter(|| aes_128_gcm.decrypt(&nonce, &enc_aes_128_gcm, None).unwrap()),
    );

    // AES 256 GCM
    let aes_256_gcm = Aes256Gcm::new(&key32);

    let enc_aes_256_gcm = aes_256_gcm.encrypt(&nonce, &msg, None).unwrap();
    c.bench_function(
        "AES 256 GCM DEM decryption of a 2048-bytes message without additional data",
        |b| b.iter(|| aes_256_gcm.decrypt(&nonce, &enc_aes_256_gcm, None).unwrap()),
    );

    // Chacha20 Poly1305
    let chacha20_poly1305 = ChaCha20Poly1305::new(&key32);
    let enc_chacha20_poly1305 = chacha20_poly1305.encrypt(&nonce, &msg, None).unwrap();
    c.bench_function(
        "ChaCha20 Poly1305 DEM decryption of a 2048-bytes message without additional data",
        |b| {
            b.iter(|| {
                chacha20_poly1305
                    .decrypt(&nonce, &enc_chacha20_poly1305, None)
                    .unwrap()
            })
        },
    );
}

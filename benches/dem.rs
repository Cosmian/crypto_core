/// Size of the message used in the benchmarks
use cosmian_crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    symmetric_crypto::{aes_128_gcm::Aes128Gcm, aes_256_gcm::Aes256Gcm, key::SymmetricKey, Dem},
    CsRng, SecretKey,
};
use criterion::Criterion;

const MSG_LENGTH: usize = 2048;

pub fn bench_symmetric_encryption(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let key16 = SymmetricKey::new(&mut rng);
    let key32 = SymmetricKey::new(&mut rng);
    let mut msg = [0; MSG_LENGTH];
    rng.fill_bytes(&mut msg);

    c.bench_function(
        "Bench the AES 128 GCM DEM encryption of a 2048-bytes message without additional data",
        |b| b.iter(|| Aes128Gcm::encrypt(&mut rng, &key16, &msg, None).unwrap()),
    );

    c.bench_function(
        "Bench the AES 256 GCM DEM encryption of a 2048-bytes message without additional data",
        |b| b.iter(|| Aes256Gcm::encrypt(&mut rng, &key32, &msg, None).unwrap()),
    );
}

pub fn bench_symmetric_decryption(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let key16 = SymmetricKey::new(&mut rng);
    let key32 = SymmetricKey::new(&mut rng);
    let mut msg = [0; MSG_LENGTH];
    rng.fill_bytes(&mut msg);

    let enc_aes_128_gcm = Aes256Gcm::encrypt(&mut rng, &key16, &msg, None).unwrap();
    c.bench_function(
        "Bench the AES 128 GCM DEM decryption of a 2048-bytes message without additional data",
        |b| b.iter(|| Aes256Gcm::decrypt(&key16, &enc_aes_128_gcm, None).unwrap()),
    );

    let enc_aes_256_gcm = Aes256Gcm::encrypt(&mut rng, &key32, &msg, None).unwrap();
    c.bench_function(
        "Bench the AES 256 GCM DEM decryption of a 2048-bytes message without additional data",
        |b| b.iter(|| Aes256Gcm::decrypt(&key32, &enc_aes_256_gcm, None).unwrap()),
    );
}

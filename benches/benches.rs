use cosmian_crypto_core::{
    asymmetric_crypto::{R25519PrivateKey, R25519PublicKey},
    kdf128, kdf256,
    reexport::rand_core::{RngCore, SeedableRng},
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, key::SymmetricKey, Dem},
    CsRng, SecretKey,
};
use criterion::{criterion_group, criterion_main, Criterion};

mod ecies;

/// Bench the Group-Scalar multiplication on which is based the
/// Diffie-Hellman key exchange. This gives an indication on how fast
/// asymmetric schemes can be.
fn bench_dh_r25519(c: &mut Criterion) {
    let private_key = {
        let mut rng = CsRng::from_entropy();
        R25519PrivateKey::new(&mut rng)
    };
    let public_key = R25519PublicKey::from(&private_key);
    c.bench_function(
        "Bench R25519 Group-Scalar multiplication on which is based the Diffie-Hellman key exchange",
        |b| b.iter(|| &public_key * &private_key),
    );
}

/// Size of the message used in the benchmarks
const MSG_LENGTH: usize = 2048;

fn bench_symmetric_encryption(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let key = SymmetricKey::new(&mut rng);
    let mut msg = [0; MSG_LENGTH];
    rng.fill_bytes(&mut msg);
    c.bench_function(
        "Bench the DEM encryption of a 2048-bytes message without additional data",
        |b| b.iter(|| Aes256GcmCrypto::encrypt(&mut rng, &key, &msg, None).unwrap()),
    );
}

fn bench_symmetric_decryption(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let key = SymmetricKey::new(&mut rng);
    let mut msg = [0; MSG_LENGTH];
    rng.fill_bytes(&mut msg);
    let enc = Aes256GcmCrypto::encrypt(&mut rng, &key, &msg, None).unwrap();
    c.bench_function(
        "Bench the DEM decryption of a 2048-bytes message without additional data",
        |b| b.iter(|| Aes256GcmCrypto::decrypt(&key, &enc, None).unwrap()),
    );
}

/// Bench the generation of a cryptographic RNG.
///
/// *WARNING*: the generation of a RNG is slower on an idle computer since the
/// OS needs to gather enough entropy.
fn bench_rng_generation(c: &mut Criterion) {
    c.bench_function("Bench the generation of a cryptographic RNG", |b| {
        b.iter(CsRng::from_entropy)
    });
}

fn bench_kdf(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let mut ikm_32 = [0; 32];
    rng.fill_bytes(&mut ikm_32);
    let mut ikm_64 = [0; 64];
    rng.fill_bytes(&mut ikm_64);
    c.bench_function(
        "Bench the KDF 128bit derivation of a 32-byte IKM into a 16-bytes key",
        |b| b.iter(|| kdf128!(16, &ikm_32, b"KDF derivation")),
    );
    c.bench_function(
        "Bench the KDF 256bit derivation of a 64-byte IKM into a 32-bytes key",
        |b| b.iter(|| kdf256!(32, &ikm_64, b"KDF derivation")),
    );
}

criterion_group!(
    name = asymmetric_crypto;
    config = Criterion::default().sample_size(5000);
    targets = bench_dh_r25519
);

criterion_group!(
    name = symmetric_crypto;
    config = Criterion::default().sample_size(5000);
    targets = bench_symmetric_encryption, bench_symmetric_decryption
);

criterion_group!(
    name = cs_rng;
    config = Criterion::default().sample_size(5000);
    targets = bench_rng_generation
);

criterion_group!(
    name = kdf;
    config = Criterion::default().sample_size(5000);
    targets = bench_kdf
);

criterion_group!(
    name = ecies;
    config = Criterion::default().sample_size(5000);
    targets =  ecies::ecies_r25519_aes256gcm_sha256_xof_bench, ecies::ecies_salsa_seal_box
);

criterion_main!(asymmetric_crypto, symmetric_crypto, cs_rng, kdf, ecies);

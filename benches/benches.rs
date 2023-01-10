use cosmian_crypto_core::{
    asymmetric_crypto::{curve25519::X25519KeyPair, DhKeyPair},
    kdf,
    reexport::rand_core::{RngCore, SeedableRng},
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, key::Key, Dem},
    CsRng, KeyTrait,
};
use criterion::{criterion_group, criterion_main, Criterion};

/// Bench the Group-Scalar multiplication on which is based the
/// Diffie-Hellman key exchange. This gives an indication on how fast
/// asymmetric schemes can be.
fn bench_dh(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let dh_keypair = X25519KeyPair::new(&mut rng);
    c.bench_function(
        "Bench the Group-Scalar multiplication on which is based the Diffie-Hellman key exchange",
        |b| b.iter(|| dh_keypair.public_key() * dh_keypair.private_key()),
    );
}

/// Size of the message used in the benchmarks
const MSG_LENGTH: usize = 2048;

fn bench_symmetric_encryption(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let key = Key::new(&mut rng);
    let mut msg = [0; MSG_LENGTH];
    rng.fill_bytes(&mut msg);
    c.bench_function(
        "Bench the DEM encryption of a 2048-bytes message without additional data",
        |b| b.iter(|| Aes256GcmCrypto::encrypt(&mut rng, &key, &msg, None).unwrap()),
    );
}

fn bench_symmetric_decryption(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let key = Key::new(&mut rng);
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
    const LENGTH: usize = 64;
    let mut rng = CsRng::from_entropy();
    let mut ikm = [0; 32];
    rng.fill_bytes(&mut ikm);
    c.bench_function(
        "Bench the KDF derivation of a 32-bytes IKM into a 64-bytes key",
        |b| b.iter(|| kdf!(LENGTH, &ikm, b"KDF derivation")),
    );
}

criterion_group!(
    name = asymmetric_crypto;
    config = Criterion::default().sample_size(5000);
    targets = bench_dh
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

criterion_main!(asymmetric_crypto, symmetric_crypto, cs_rng, kdf);

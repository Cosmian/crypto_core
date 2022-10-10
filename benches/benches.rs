use cosmian_crypto_core::{
    asymmetric_crypto::{curve25519::X25519KeyPair, DhKeyPair},
    entropy::CsRng,
    kdf,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, key::Key, Dem},
    KeyTrait,
};
use criterion::{criterion_group, criterion_main, Criterion};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

/// Bench the Group-Scalar multiplication on which is based the
/// Diffie-Hellman key exchange. This gives an indication on how fast
/// asymmetric schemes can be.
fn bench_dh(c: &mut Criterion) {
    let mut rng = CsRng::new();
    let dh_keypair = X25519KeyPair::new(&mut rng);
    c.bench_function(
        "Bench the Group-Scalar multiplication on which is based the Diffie-Helman key exchange",
        |b| b.iter(|| dh_keypair.public_key() * dh_keypair.private_key()),
    );
}

/// Size of the message used in the benchmarks
const MSG_LENGTH: usize = 2048;

fn bench_symmetric_encryption(c: &mut Criterion) {
    let mut rng = CsRng::new();
    let key = Key::new(&mut rng);
    let msg = rng.generate_random_bytes::<MSG_LENGTH>();
    c.bench_function(
        "Bench the DEM encryption of a 2048-bytes message withou additional data",
        |b| b.iter(|| Aes256GcmCrypto::encrypt(&mut rng, &key, &msg, None).unwrap()),
    );
}

fn bench_symmetric_decryption(c: &mut Criterion) {
    let mut rng = CsRng::new();
    let key = Key::new(&mut rng);
    let msg = rng.generate_random_bytes::<MSG_LENGTH>();
    let enc = Aes256GcmCrypto::encrypt(&mut rng, &key, &msg, None).unwrap();
    c.bench_function(
        "Bench the DEM decryption of a 2048-bytes message withou additional data",
        |b| b.iter(|| Aes256GcmCrypto::decrypt(&key, &enc, None).unwrap()),
    );
}

/// Bench the generation of a cryptographic RNG.
///
/// *WARNING*: the generation of a RNG is slower on an idle computer since the
/// OS needs to gather enough entropy.
fn bench_rng_generation(c: &mut Criterion) {
    c.bench_function("Bench the generation of a cryptographic RNG", |b| {
        b.iter(CsRng::new)
    });
}

fn bench_kdf(c: &mut Criterion) {
    const LENGTH: usize = 64;
    let mut rng = CsRng::new();
    let ikm = rng.generate_random_bytes::<32>();
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

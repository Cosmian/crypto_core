use cosmian_crypto_core::{
    blake2b, blake2s, kdf128, kdf256,
    reexport::rand_core::{RngCore, SeedableRng},
    CryptoCoreError, CsRng, R25519PrivateKey, R25519PublicKey, RandomFixedSizeCBytes,
};
use criterion::{criterion_group, criterion_main, Criterion};
use dem::{
    bench_symmetric_decryption_combined, bench_symmetric_decryption_in_place,
    bench_symmetric_encryption_combined, bench_symmetric_encryption_in_place,
};

mod dem;
mod ecies;
mod signature;

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
        "R25519 Group-Scalar multiplication on which is based the Diffie-Hellman key exchange",
        |b| b.iter(|| &public_key * &private_key),
    );
}

/// Bench the generation of a cryptographic RNG.
///
/// *WARNING*: the generation of a RNG is slower on an idle computer since the
/// OS needs to gather enough entropy.
fn bench_rng_generation(c: &mut Criterion) {
    c.bench_function("generation of a cryptographic RNG", |b| {
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
        "Hashers: KDF 128bit derivation of a 32-byte IKM into a 16-bytes key",
        |b| b.iter(|| kdf128!(16, &ikm_32, b"KDF derivation")),
    );
    c.bench_function(
        "Hashers: KDF 256bit derivation of a 64-byte IKM into a 32-bytes key",
        |b| b.iter(|| kdf256!(32, &ikm_64, b"KDF derivation")),
    );
}

fn bench_blake2(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let mut ikm_32 = [0; 32];
    rng.fill_bytes(&mut ikm_32);
    let mut ikm_64 = [0; 64];
    rng.fill_bytes(&mut ikm_64);
    c.bench_function(
        "Hashers: Blake2s 256 derivation of a 32-byte IKM into a 16-bytes key",
        |b| b.iter(|| blake2s!(16, &ikm_32, b"Blake2 derivation")),
    );
    c.bench_function(
        "Hashers: Blake2b 512 derivation of a 64-byte IKM into a 32-bytes key",
        |b| b.iter(|| blake2b!(32, &ikm_64, b"Blake2 derivation")),
    );
}

criterion_group!(
    name = asymmetric_crypto;
    config = Criterion::default().sample_size(5000);
    targets = bench_dh_r25519
);

criterion_group!(
    name = dem;
    config = Criterion::default().sample_size(5000);
    targets = bench_symmetric_encryption_combined, bench_symmetric_encryption_in_place,
    bench_symmetric_decryption_combined,bench_symmetric_decryption_in_place
);

criterion_group!(
    name = cs_rng;
    config = Criterion::default().sample_size(5000);
    targets = bench_rng_generation
);

criterion_group!(
    name = hashers;
    config = Criterion::default().sample_size(5000);
    targets = bench_kdf, bench_blake2
);

criterion_group!(
    name = ecies;
    config = Criterion::default().sample_size(5000);
    targets =  ecies::ecies_r25519_aes128gcm_bench, ecies::ecies_salsa_seal_box,ecies::ecies_x25519_xchacha20
);

criterion_group!(
    name = signature;
    config = Criterion::default().sample_size(5000);
    targets =  signature::bench_ed25519_signature
);

criterion_main!(asymmetric_crypto, dem, cs_rng, hashers, ecies, signature);

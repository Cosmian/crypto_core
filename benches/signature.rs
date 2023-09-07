#![cfg(feature = "default")]
/// Size of the message used in the benchmarks
use cosmian_crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    Cached25519Signer, CsRng, Ed25519Keypair, Ed25519PrivateKey, Ed25519PublicKey,
};
use criterion::Criterion;
use signature::{Signer, Verifier};

const MSG_LENGTH: usize = 2048;

pub fn bench_ed25519_signature(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    let mut msg = [0; MSG_LENGTH];
    rng.fill_bytes(&mut msg);

    let private_key = Ed25519PrivateKey::new(&mut rng);

    c.bench_function("Ed25519 (direct) signature", |b| {
        b.iter(|| private_key.try_sign(&msg).unwrap());
    });

    c.bench_function("Ed25519 cached signer instantiation", |b| {
        b.iter(|| Cached25519Signer::try_from(&private_key).unwrap());
    });

    let cached_signer = Cached25519Signer::try_from(&private_key).unwrap();

    c.bench_function("Ed25519 cached signer signature", |b| {
        b.iter(|| cached_signer.try_sign(&msg).unwrap());
    });

    let signature = private_key.try_sign(&msg).unwrap();
    let public_key = Ed25519PublicKey::try_from(&private_key).unwrap();

    c.bench_function("Ed25519 signature verification", |b| {
        b.iter(|| public_key.verify(&msg, &signature).unwrap());
    });

    c.bench_function("Ed25519key key pair instantiation", |b| {
        b.iter(|| Ed25519Keypair::new(&mut rng));
    });

    let key_pair = Ed25519Keypair::new(&mut rng).unwrap();

    c.bench_function("Ed25519key key pair signature", |b| {
        b.iter(|| key_pair.try_sign(&msg).unwrap());
    });

    let signature = key_pair.try_sign(&msg).unwrap();

    c.bench_function("Ed25519 key pair signature verification", |b| {
        b.iter(|| key_pair.verify(&msg, &signature).unwrap());
    });
}

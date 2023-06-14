pub fn ed25519_static() {
    use cosmian_crypto_core::{
        reexport::{
            rand_core::SeedableRng,
            signature::{Signer, Verifier},
        },
        CsRng, Ed25519PrivateKey, Ed25519PublicKey, RandomFixedSizeCBytes,
    };

    // instantiate a random number generator
    let mut rng = CsRng::from_entropy();

    // the message to sign
    let message = b"Hello, world!";

    // sign the message with the private key
    let private_key = Ed25519PrivateKey::new(&mut rng);
    let signature = private_key.try_sign(message).unwrap();

    // verify the signature with the public key
    let public_key = Ed25519PublicKey::try_from(&private_key).unwrap();
    public_key.verify(message, &signature).unwrap();

    println!("Ed25519 static: OK")
}

pub fn ed25519_cached() {
    use cosmian_crypto_core::{
        reexport::{
            rand_core::SeedableRng,
            signature::{Signer, Verifier},
        },
        Cached25519Signer, CsRng, Ed25519PrivateKey, Ed25519PublicKey, RandomFixedSizeCBytes,
    };

    // instantiate a random number generator
    let mut rng = CsRng::from_entropy();

    // instantiate the cached signer
    let private_key = Ed25519PrivateKey::new(&mut rng);
    let cached_signer = Cached25519Signer::try_from(&private_key).unwrap();

    // verify the signatures
    let public_key = Ed25519PublicKey::try_from(&private_key).unwrap();

    let message = b"Hello, world!";
    let signature = cached_signer.try_sign(message).unwrap();
    public_key.verify(message, &signature).unwrap();

    let message = b"I'm sorry, Dave. I'm afraid I can't do that.";
    let signature = cached_signer.try_sign(message).unwrap();
    public_key.verify(message, &signature).unwrap();

    println!("Ed25519 cached: OK")
}

pub fn ed25519_keypair() {
    use cosmian_crypto_core::{
        reexport::{
            rand_core::SeedableRng,
            signature::{Signer, Verifier},
        },
        CsRng, Ed25519Keypair, FixedSizeCBytes,
    };
    let mut rng = CsRng::from_entropy();
    let message = b"Hello, world!";

    // generate a keypair
    let keypair = Ed25519Keypair::new(&mut rng).unwrap();

    // serialize the keypair
    let serialized_keypair = keypair.to_bytes();

    // deserialize the keypair
    let keypair = Ed25519Keypair::try_from_bytes(serialized_keypair).unwrap();

    //assert equality
    assert_eq!(keypair.to_bytes(), serialized_keypair);

    // sign the message using the keypair
    let signature = keypair.try_sign(message).unwrap();

    // verify the signature
    keypair.verify(message, &signature).unwrap();

    println!("Ed25519 keypair: OK")
}

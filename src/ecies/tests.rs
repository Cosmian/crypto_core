use std::sync::{Arc, Mutex};

use rand_chacha::rand_core::SeedableRng;

use crate::{
    asymmetric_crypto::{R25519PrivateKey, R25519PublicKey, X25519PrivateKey, X25519PublicKey},
    ecies::{ecies_ristretto_25519::EciesR25519Aes128, ecies_salsa_sealed_box::EciesSalsaSealBox},
    CsRng, Ecies, FixedSizeKey, SecretKey,
};

#[test]
fn ecies_r25519_aes256gcm_sha256_xof_test() {
    let arc_rng = Arc::new(Mutex::new(CsRng::from_entropy()));
    let ecies = EciesR25519Aes128::new_from_rng(arc_rng.clone());
    // generate a key pair
    let private_key = {
        let mut rng = arc_rng.lock().unwrap();
        R25519PrivateKey::new(&mut *rng)
    };
    let public_key = R25519PublicKey::from(&private_key);
    // encrypt
    let plaintext = b"Hello World!";
    let ciphertext = ecies.encrypt(&public_key, plaintext, None).unwrap();
    // check the size is the expected size
    assert_eq!(
        ciphertext.len(),
        plaintext.len() + EciesR25519Aes128::ENCRYPTION_OVERHEAD
    );
    // decrypt
    let plaintext_ = ecies.decrypt(&private_key, &ciphertext, None).unwrap();
    // assert
    assert_eq!(plaintext, &plaintext_[..]);
}

#[test]
fn ecies_salsa_seal_box() {
    let arc_rng = Arc::new(Mutex::new(CsRng::from_entropy()));
    let ecies = EciesSalsaSealBox::new_from_rng(arc_rng.clone());
    // generate a secret key
    let private_key = {
        let mut rng = arc_rng.lock().unwrap();
        X25519PrivateKey::new(&mut *rng)
    };
    let public_key = X25519PublicKey::from(&private_key);
    // encrypt
    let plaintext = b"Hello World!";
    let ciphertext = ecies.encrypt(&public_key, plaintext, None).unwrap();
    // check the size is the expected size
    assert_eq!(
        ciphertext.len(),
        plaintext.len() + EciesSalsaSealBox::ENCRYPTION_OVERHEAD
    );
    // decrypt
    let plaintext_ = ecies.decrypt(&private_key, &ciphertext, None).unwrap();
    // assert
    assert_eq!(plaintext, &plaintext_[..]);
}

#[test]
fn libsodium_compat() {
    let arc_rng = Arc::new(Mutex::new(CsRng::from_entropy()));
    let ecies = EciesSalsaSealBox::new_from_rng(arc_rng.clone());

    let message = b"Hello World!";
    let mut ciphertext: Vec<u8> =
        vec![0; libsodium_sys::crypto_box_SEALBYTES as usize + message.len()];

    let mut public_key_bytes = [0u8; libsodium_sys::crypto_box_PUBLICKEYBYTES as usize];
    let mut private_key_bytes = [0u8; libsodium_sys::crypto_box_SECRETKEYBYTES as usize];

    // encrypt using libsodium
    unsafe {
        // initialize the public and private key
        let public_key_ptr: *mut libc::c_uchar =
            public_key_bytes.as_mut_ptr() as *mut libc::c_uchar;
        let private_key_ptr: *mut libc::c_uchar =
            private_key_bytes.as_mut_ptr() as *mut libc::c_uchar;
        libsodium_sys::crypto_box_keypair(public_key_ptr, private_key_ptr);

        // encrypt using libsodium
        let message_ptr: *const libc::c_uchar = message.as_ptr() as *const libc::c_uchar;
        let ciphertext_ptr: *mut libc::c_uchar = ciphertext.as_mut_ptr() as *mut libc::c_uchar;
        libsodium_sys::crypto_box_seal(
            ciphertext_ptr,
            message_ptr,
            message.len() as u64,
            public_key_ptr,
        );
    }

    // decrypt using salsa_sealbox
    let private_key = X25519PrivateKey::try_from_bytes(private_key_bytes).unwrap();
    // decrypt
    let message_ = ecies.decrypt(&private_key, &ciphertext, None).unwrap();
    // assert
    assert_eq!(message, &message_[..]);

    // the other way round:
    //
    // encrypt using salsa_sealbox
    let public_key = X25519PublicKey::from(&private_key);
    let ciphertext = ecies.encrypt(&public_key, message, None).unwrap();

    //decrypt using libsodium
    let mut plaintext_: Vec<u8> = vec![0; message.len()];
    unsafe {
        let plaintext_ptr: *mut libc::c_uchar = plaintext_.as_mut_ptr() as *mut libc::c_uchar;
        let ciphertext_ptr: *const libc::c_uchar = ciphertext.as_ptr() as *const libc::c_uchar;
        let private_key_ptr: *const libc::c_uchar =
            private_key_bytes.as_ptr() as *const libc::c_uchar;
        let public_key_ptr: *const libc::c_uchar =
            public_key_bytes.as_ptr() as *const libc::c_uchar;

        libsodium_sys::crypto_box_seal_open(
            plaintext_ptr,
            ciphertext_ptr,
            ciphertext.len() as u64,
            public_key_ptr,
            private_key_ptr,
        );
    }

    assert_eq!(plaintext_, message);
}

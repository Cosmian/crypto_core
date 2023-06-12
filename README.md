<h1>CryptoCore</h1>

![Build status](https://github.com/Cosmian/crypto_core/actions/workflows/ci.yml/badge.svg)
![Build status](https://github.com/Cosmian/crypto_core/actions/workflows/audit.yml/badge.svg)
![latest version](https://img.shields.io/crates/v/cosmian_crypto_core.svg)

This crate implements the cryptographic primitives (modern encryption and signature schemes) used in many other Cosmian products, such as the Cloudproof libraries and the KMS.

- [Using](#using)
- [Example usages](#example-usages)
- [Building](#building)
- [Further improving performance](#further-improving-performance)
- [Running tests and benchmarks](#running-tests-and-benchmarks)
- [Symmetric key encryption](#symmetric-key-encryption)
  - [Symmetric key encryption of a vector of bytes in combined mode](#symmetric-key-encryption-of-a-vector-of-bytes-in-combined-mode)
  - [Symmetric key encryption of a vector of bytes in detached mode](#symmetric-key-encryption-of-a-vector-of-bytes-in-detached-mode)
  - [Symmetric key encryption of a stream of bytes](#symmetric-key-encryption-of-a-stream-of-bytes)
- [ECIES - Elliptic Curve Integrated Encryption Scheme](#ecies---elliptic-curve-integrated-encryption-scheme)
  - [ECIES encryption of a vector of bytes](#ecies-encryption-of-a-vector-of-bytes)
  - [ECIES encryption of a stream of bytes](#ecies-encryption-of-a-stream-of-bytes)
- [Signature](#signature)
  - [Static implementation](#static-implementation)
  - [Cached implementation](#cached-implementation)
  - [Using a Keypair](#using-a-keypair)
- [Cryptographically Secure Random Number Generator (CS-RNG)](#cryptographically-secure-random-number-generator-cs-rng)
- [Key Derivation Function (KDF)](#key-derivation-function-kdf)
- [Blake2 hashing](#blake2-hashing)
- [Code documentation](#code-documentation)

It is primarily a thin layer over the [RustCrypto](https://github.com/RustCrypto) libraries, exposing as far as possible more straightforward and more consistent Traits, for example:

- the lib hides all confusing GenericArray types and uses[u8; N] arrays only,
- provides a single representation of curves' private keys,
- ensures secrets are always wiped from memory after use,
- adds examples for usage,
- adds tests for `libsodium` compatibility,
- etc.

This crate may disappear in the future, as the RustCrypto libraries evolve.

## Using

To use Cosmian CryptoCore, add the dependency using Cargo:

```bash
cargo add cosmian_crypto_core
```

## Example usages

This document provides examples of the most common use cases.
All the examples are available in the [examples directory](./examples/examples/)

## Building

To install and build Cosmian CryptoCore, clone the repo:

```bash
git clone https://github.com/Cosmian/crypto_core.git
```

Build it with Cargo:

```bash
cargo build --release
```

## Further improving performance

Running the nightly backend with the following flags (SIMD instructions) will improve performance by about 33% on the Ristretto backend, 25% for AES GCM, and 15% on the ED25519 backend

```sh
  RUSTFLAGS='--cfg curve25519_dalek_backend="simd" -C target_cpu=native'
```

## Running tests and benchmarks

Run tests using:

```bash
cargo test --release
```

Run benchmarks using:

```bash
cargo bench
```

## Symmetric key encryption

This crate offers standardized authenticated encryption schemes: AES-GCM - with 128 and 256 keys -, Chacha20 Poly1305, and XChacha Poly1305.
All these primitives are available in three modes: vector-combined, vector-detached, and streaming.

In combined and detached modes, AES 256 GCM, Chacha20-Poly1305, and XChachaPoly1305 are compatible with their IETF equivalent in `libsodium`. Check this [documentation](https://doc.libsodium.org/secret-key_cryptography/aead) for details of the `libsodium` implementations.

The AES version uses AES-NI instructions when available, which is the case on most modern processors.
All these primitives are fast and encrypt a vector of bytes with authentication in an average of 2.5µs on a 2.6GHz Intel Core i7.

### Symmetric key encryption of a vector of bytes in combined mode

In combined mode, the primitive encrypts a plaintext as a single vector of bytes and allocates a new vector for the ciphertext that holds the encrypted data and the MAC.

```Rust
  use cosmian_crypto_core::XChaCha20Poly1305;
  use cosmian_crypto_core::{
      reexport::rand_core::SeedableRng, CsRng, Dem, FixedSizeCBytes, Instantiable, Nonce,
      RandomFixedSizeCBytes, SymmetricKey,
  };

  // Choose one of these DEMs depending on your use case
  // type SC = Aes128Gcm;
  // type SC = Aes256Gcm;
  // type SC = ChaCha20Poly1305;
  type SC = XChaCha20Poly1305;

  // A cryptographically secure random generator
  let mut rng = CsRng::from_entropy();

  // the message to encrypt
  let message = b"my secret message";
  // the secret key used to encrypt the message
  // which is shared between the sender and the recipient
  let secret_key = SymmetricKey::new(&mut rng);

  // the additional data shared between the sender and the recipient to authenticate the message
  let additional_data = Some(b"additional data".as_slice());

  // the sender generate a Nonce and encrypts the message
  let nonce = Nonce::new(&mut rng);
  let dem = SC::new(&secret_key);
  let ciphertext = dem.encrypt(&nonce, message, additional_data).unwrap();

  // to transmit the message, the sender can concatenate the nonce and the ciphertext
  // and send the concatenated result to the recipient
  let ciphertext = [nonce.as_bytes(), ciphertext.as_slice()].concat();

  // the ciphertext size is the message size plus the nonce size plus the authentication tag size
  assert_eq!(
      ciphertext.len(),
      message.len() + SC::NONCE_LENGTH + SC::MAC_LENGTH
  );

  // the recipient extracts the nonce and decrypts the message
  let nonce = Nonce::try_from_slice(&ciphertext[..SC::NONCE_LENGTH]).unwrap();
  let dem = SC::new(&secret_key);
  let plaintext = dem
      .decrypt(&nonce, &ciphertext[SC::NONCE_LENGTH..], additional_data)
      .unwrap();

  // assert the decrypted message is identical to the original plaintext
  assert_eq!(plaintext, message, "Decryption failed");
```

### Symmetric key encryption of a vector of bytes in detached mode

In combined mode, the primitive encrypts a plaintext as a single mutable vector of bytes in place; it returns the MAC tag on the encryption call.

```Rust
use cosmian_crypto_core::DemInPlace;
use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, FixedSizeCBytes, Instantiable, Nonce,
    RandomFixedSizeCBytes, SymmetricKey, XChaCha20Poly1305,
};

// Choose one of these DEMs depending on your use case
// type SC = Aes128Gcm;
// type SC = Aes256Gcm;
// type SC = ChaCha20Poly1305;
type SC = XChaCha20Poly1305;

// A cryptographically secure random generator
let mut rng = CsRng::from_entropy();

// the message to encrypt
let message = b"my secret message";
// the secret key used to encrypt the message
// which is shared between the sender and the recipient
let secret_key = SymmetricKey::new(&mut rng);

// the additional data shared between the sender and the recipient to authenticate the message
let additional_data = Some(b"additional data".as_slice());

// the sender generate a Nonce and encrypts the message in place
// the encryption method returns the tag/MAC
let mut bytes = message.to_vec();
let nonce = Nonce::new(&mut rng);
let dem = SC::new(&secret_key);
let tag = dem
    .encrypt_in_place_detached(&nonce, &mut bytes, additional_data)
    .unwrap();

// to transmit the message, the sender can concatenate the nonce, the encrypted data and the MAC
// then send the concatenated result to the recipient
let ciphertext = [nonce.as_bytes(), bytes.as_slice(), tag.as_slice()].concat();

// the ciphertext size is the message size plus the nonce size plus the authentication tag size
assert_eq!(
    ciphertext.len(),
    message.len() + SC::NONCE_LENGTH + SC::MAC_LENGTH
);

// the recipient extracts the nonce, message and the tag/MAC then decrypt the message in place
let nonce = Nonce::try_from_slice(&ciphertext[..SC::NONCE_LENGTH]).unwrap();
let mut bytes = ciphertext[SC::NONCE_LENGTH..ciphertext.len() - SC::MAC_LENGTH].to_vec();
let tag = ciphertext[ciphertext.len() - SC::MAC_LENGTH..].to_vec();

let dem = SC::new(&secret_key);
dem.decrypt_in_place_detached(&nonce, &mut bytes, &tag, additional_data)
    .unwrap();

// assert the decrypted message is identical to the original plaintext
assert_eq!(bytes.as_slice(), message, "Decryption failed");
```

### Symmetric key encryption of a stream of bytes

The library exposes the 2 streaming DEMs offered in the [RustCrypto AEAD](https://github.com/RustCrypto/traits/tree/master/aead) crate which are based on the authenticated encryption construction as described in the paper [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf)

```Rust
use cosmian_crypto_core::XChaCha20Poly1305;
use cosmian_crypto_core::{
    reexport::{aead::Payload, rand_core::SeedableRng},
    CsRng, DemStream, Instantiable, Nonce, RandomFixedSizeCBytes, SymmetricKey,
};

// Choose one of these streaming DEMs depending on your use case
// type SC = Aes128Gcm;
// type SC = Aes256Gcm;
// type SC = ChaCha20Poly1305;
type SC = XChaCha20Poly1305;

let message = b"Hello, World!";

// The message will be encrypted in 2 chunks, one of size 8 and one of size 5
// In real life, the block size should be much larger and typically a multiple of 4096
const BLOCK_SIZE: usize = 8;

// use some additional data to authenticate the message
let aad = b"the aad";

// generate a random key and nonce
let mut rng = CsRng::from_entropy();
let secret_key = SymmetricKey::new(&mut rng);
let nonce = Nonce::new(&mut rng);

// Instantiate a streaming encryptor
// Two streaming encryptor are available: EncryptorBE32 and EncryptorLE31
// Check the documentation of the DemStream trait for more details
let mut encryptor = SC::new(&secret_key).into_stream_encryptor_be32(&nonce);

// Encrypt the first chunk
// Encryption of all chunks except the last should use `encrypt_next`
let mut ciphertext = encryptor
    .encrypt_next(Payload {
        msg: &message[..BLOCK_SIZE],
        aad,
    })
    .unwrap();

// Encrypt the second and last chunk using `encrypt_last`
ciphertext.extend_from_slice(
    &encryptor
        .encrypt_last(Payload {
            msg: &message[BLOCK_SIZE..],
            aad,
        })
        .unwrap(),
);

// decryption

// Instantiate a streaming decryptor
let mut decryptor = SC::new(&secret_key).into_stream_decryptor_be32(&nonce);

// Decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
// Decryption of all chunks except the last should use `decrypt_next`
let mut plaintext = decryptor
    .decrypt_next(Payload {
        msg: &ciphertext[..BLOCK_SIZE + SC::MAC_LENGTH],
        aad,
    })
    .unwrap();

// decrypt the second and last chunk
plaintext.extend_from_slice(
    &decryptor
        .decrypt_last(Payload {
            msg: &ciphertext[BLOCK_SIZE + SC::MAC_LENGTH..],
            aad,
        })
        .unwrap(),
);

assert_eq!(
    message.as_slice(),
    plaintext.as_slice(),
    "Decryption failed"
);
```

## ECIES - Elliptic Curve Integrated Encryption Scheme

The library exposes 3 ECIES schemes based on the [Dalek implementation](https://github.com/dalek-cryptography/curve25519-dalek) of curve 25519

- `EciesX25519XChaCha20`: which uses the X25519 KEM and the XChaCha20 Poly1305 DEM; it uses HChaCha for the ephemeral symmetric key derivation and Blake2b for the nonce generation. In case of doubt, this is the recommended scheme.
- `EciesSalsaSealBox`: which uses the X25519 KEM and the Salsa20 Poly1305 DEM. This scheme is compatible with `libsodium` sealed boxes but does not offer support for additional data in the DEM authentication.
- `EciesR25519Aes128`: which KEM is based on the Ristretto group of curve 25519 and uses Aes 128 GCM as a DEM. Both the derivation of the ephemeral symmetric key and the generation of the nonce is performed using Shake 128.

All these implementations have similar performance (about 70µs for encryption/decryption on a 2.6GHz Intel Core i7) and security (128-bit classic security - no post-quantum resistance).

A later version offering a hybrid encryption scheme with post-quantum resistance will be released.

All these implementations use the same format for the Curve 25519 Private key; their public key implementations under the various representations (Edwards, Montgomery, and Ristretto)are available in the [`asymmetric_cypto`](./src/asymmetric_crypto/curve_25519/) folder.

### ECIES encryption of a vector of bytes

The following example shows how to encrypt a vector of bytes using ECIES X25519 (KEM) combined with XChaCha20 Poly1305 (DEM).
It also demonstrates the use of additional data in the DEM authentication.

Encryption is performed using the public key and decryption using the private key.

```Rust
use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, Ecies, EciesX25519XChaCha20,
    RandomFixedSizeCBytes, X25519PrivateKey, X25519PublicKey,
};

// A cryptographic random number generator
let mut rng = CsRng::from_entropy();

// Generate a key pair
let private_key = X25519PrivateKey::new(&mut rng);
let public_key = X25519PublicKey::from(&private_key);

// The plain text to encrypt
let plaintext = b"Hello, World!";

// Some optional authenticated data for theDEM scheme
let authenticated_data = b"Optional authenticated data";

// Encrypt the message with the public key using ECIES X25519 XChaCha20
let ciphertext =
    EciesX25519XChaCha20::encrypt(&mut rng, &public_key, plaintext, Some(authenticated_data))
        .unwrap();

// Decrypt the message using the private key
let plaintext_ =
    EciesX25519XChaCha20::decrypt(&private_key, &ciphertext, Some(authenticated_data)).unwrap();

// Check if the decrypted message is the same as the original message
assert_eq!(plaintext, &plaintext_[..]);
```

### ECIES encryption of a stream of bytes

The following example shows how to encrypt a stream of bytes using ECIES X25519 (KEM) combined with XChaCha20 Poly1305 (DEM).

```Rust
use aead::Payload;
use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, EciesStream, EciesX25519XChaCha20,
    FixedSizeCBytes, RandomFixedSizeCBytes, X25519PrivateKey, X25519PublicKey,
    XChaCha20Poly1305,
};

// generate a random key and nonce
let mut rng = CsRng::from_entropy();

// generate a key pair
let private_key = X25519PrivateKey::new(&mut rng);
let public_key = X25519PublicKey::from(&private_key);

// The plain text to encrypt
let message = b"Hello, World!";

// Some optional authenticated data for theDEM scheme
let authenticated_data = b"Optional authenticated data";

// there will be 2 chunks for the message, one of size 8 and one of size 5
const BLOCK_SIZE: usize = 8;

let (ephemeral_public_key, mut encryptor) =
    EciesX25519XChaCha20::get_dem_encryptor_be32(&mut rng, &public_key).unwrap();

// prepend the ciphertext with the ephemeral public key
let mut ciphertext = ephemeral_public_key.to_bytes().to_vec();

// encrypt the first chunk
ciphertext.extend(
    encryptor
        .encrypt_next(Payload {
            msg: &message[..BLOCK_SIZE],
            aad: authenticated_data,
        })
        .unwrap(),
);

// encrypt the second and last chunk
ciphertext.extend_from_slice(
    &encryptor
        .encrypt_last(Payload {
            msg: &message[BLOCK_SIZE..],
            aad: authenticated_data,
        })
        .unwrap(),
);

// decryption

//recover the ephemeral public key from the ciphertext
let ephemeral_public_key =
    X25519PublicKey::try_from_slice(&ciphertext[..X25519PublicKey::LENGTH]).unwrap();

// Instantiate a decryptor
let mut decryptor =
    EciesX25519XChaCha20::get_dem_decryptor_be32(&private_key, &ephemeral_public_key).unwrap();

// decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
let mut plaintext = decryptor
    .decrypt_next(Payload {
        msg: &ciphertext[X25519PublicKey::LENGTH
            ..X25519PublicKey::LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH],
        aad: authenticated_data,
    })
    .unwrap();

// decrypt the second and last chunk
plaintext.extend_from_slice(
    &decryptor
        .decrypt_last(Payload {
            msg: &ciphertext
                [X25519PublicKey::LENGTH + BLOCK_SIZE + XChaCha20Poly1305::MAC_LENGTH..],
            aad: authenticated_data,
        })
        .unwrap(),
);

assert_eq!(
    message.as_slice(),
    plaintext.as_slice(),
    "Decryption failed"
);
```

## Signature

The crate currently exposes the EdDSA (Ed25519) signature scheme.
More signature schemes will be exposed soon.

### Static implementation

Using the static signature implementation, signature and verification are performed in about 50µs on a 2.6 GHz Intel Core i7.

```Rust
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
let public_key = Ed25519PublicKey::from(&private_key);
public_key.verify(message, &signature).unwrap();
```

### Cached implementation

Using the cached signature implementation, the signature is performed in about 25µs, verification is still performed in about 50µs on a 2.6 GHz Intel Core i7.

```Rust
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
let public_key = Ed25519PublicKey::from(&private_key);

let message = b"Hello, world!";
let signature = cached_signer.try_sign(message).unwrap();
public_key.verify(message, &signature).unwrap();

let message = b"I'm sorry, Dave. I'm afraid I can't do that.";
let signature = cached_signer.try_sign(message).unwrap();
public_key.verify(message, &signature).unwrap();
```

### Using a Keypair

The signature API also exposes a `Keypair` compatible with that of the RustCrypto implementation.

```Rust
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
let keypair = Ed25519Keypair::new(&mut rng);

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
```

## Cryptographically Secure Random Number Generator (CS-RNG)

This crate exposes a cryptographically secure random number generator (CS-RNG) that uses the implementation of the CHACHA algorithm with 12 rounds from the [`rand_chacha`](https://rust-random.github.io/rand/rand_chacha/index.html).
It is 128 bits secure.

Performance: 1.7µs per instantiation. The next pseudo-random number is generated in nanoseconds.

```Rust
use cosmian_crypto_core::CsRng;
let mut rng = CsRng::from_entropy();
```

## Key Derivation Function (KDF)

This crate uses the pure rust implementation of the SHAKE algorithm from the
[sha3](https://docs.rs/sha3/latest/sha3) crate.
Two implementations are available:

- `kdf128` which is 128-bit secure (in the classic setting) for input sizes of at least 256 bits (32 bytes).
- `kdf256` which is 256-bit secure (in the classic setting) for input sizes of at least 512 bits (64 bytes).

Both algorithms run in less than 500ns on a 2.7GHz Intel Core i7.

```Rust
#[macro_use]
use cosmian_crypto_core::kdf256;

const KEY_LENGTH: usize = 32;

const ikm: &str = "asdf34@!dsa@grq5e$2ASGy5";

// derive a 32-bytes key
let key = kdf256!(KEY_LENGTH, ikm.as_bytes());

assert_eq!(KEY_LENGTH, key.len());
```

## Blake2 hashing

The crate exposes as macros two versions of Blake2 which is specified in [RFC 7693](https://tools.ietf.org/html/rfc7693)

- `blake2s`: is optimized for 8 to 32-bit platforms and produces digests of any size between 1 and 32 bytes (256 bits)
- `blake2b`: is optimized for 64-bit platforms and produces digests of any size between 1 and 64 bytes (512 bits)

Blake2 runs in less than 200ns, which is about 3 times faster than Sha3 and Shake on most hardware but may fail when used to generate hashes of variable length, in particular when the input length is too small.

```Rust
#[macro_use]
use cosmian_crypto_core::{blakebs, CryptoCoreError};

const LENGTH: usize = 12;

let msg1 = b"asdf34@!dsa@grq5e$2ASGy5";
let msg2 = b"oiu54%6uhg1@34";
let res = blake2b!(LENGTH, msg1, msg2).unwrap();

assert_eq!(LENGTH, res.len());
```

## Code documentation

The documentation can be generated using Cargo:

```bash
cargo docs
```

It is also available on [doc.rs](https://docs.rs/cosmian_crypto_core/latest/cosmian_crypto_core/).

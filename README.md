## CryptoCore

![Build status](https://github.com/Cosmian/crypto_core/actions/workflows/ci.yml/badge.svg)
![Build status](https://github.com/Cosmian/crypto_core/actions/workflows/audit.yml/badge.svg)
![latest version](https://img.shields.io/crates/v/cosmian_crypto_core.svg)

This crate implements the cryptographic primitives (modern encryption and signature schemes) used in many other Cosmian products, such as the Cloudproof libraries and the KMS.
It is primarily a thin layer over the [RustCrypto](https://github.com/RustCrypto) libraries, exposing as far as possible more straightforward and more consistent Traits, for example:

- it hides all GenericArray types and uses only [u8; N] arrays
- it provides a single struct for a Curve25519 private key, whether used for Diffie-Hellman or signatures.
- etc..

This crate may disappear in the future, depending on the evolution of the RustCrypto libraries.

## Using

To use Cosmian CryptoCore in another Rust software, add the dependency
using Cargo:

```bash
cargo add cosmian_crypto_core
```

## Building and Testing

### Build

To install and build Cosmian CryptoCore, clone the repo:

```bash
git clone https://github.com/Cosmian/crypto_core.git
```

Build it with Cargo:

```bash
cargo build --release
```

### Further improving performance

Running the nightly backend with the following flags (SIMD instructions) will improve performance by about 33% on the Ristretto backend, 25% for AES GCM, and 15% on the ED25519 backend

```sh
  RUSTFLAGS='--cfg curve25519_dalek_backend="simd" -C target_cpu=native'
```

### Running tests and benchmarks

Run tests using:

```bash
cargo test --release
```

Run benchmarks using:

```bash
cargo bench
```

## Symmetric key encryption

This crate offers standardized authenticated encryption schemes: AES-GCM - with 128 and 256 keys -, Chacha20-Poly1305, and XChachaPoly1305.

The AES version uses AES-NI instructions when available, which is the case on most modern processors.

In combined and detached modes, AES 256 GCM, Chacha20-Poly1305, and XChachaPoly1305 are compatible with their IETF equivalent in libsodium. Check this [documentation](https://doc.libsodium.org/secret-key_cryptography/aead) for details of the libsodium implementations.

### Symmetric encryption of a vector of bytes in combined mode

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

  println!("{dem:?} block combined SUCCESS");
```

### Symmetric encryption of a stream of bytes

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

// encrypt the first chunk
let mut ciphertext = encryptor
    .encrypt_next(Payload {
        msg: &message[..BLOCK_SIZE],
        aad,
    })
    .unwrap();

// encrypt the second and last chunk
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

// decrypt the first chunk which is BLOCK_SIZE + MAC_LENGTH bytes long
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

println!("Streaming DEM SUCCESS");
```

## Cryptographic Random Number Generator (RNG)

This crate exposes a cryptographically secure random number generator (RNG) that uses the implementation of the CHACHA algorithm with 12 rounds from the [`rand_chacha`](https://rust-random.github.io/rand/rand_chacha/index.html).
It is 128 bits secure.

```Rust
use cosmian_crypto_core::CsRng;
let mut rng = CsRng::from_entropy();
```

Performance: 1.7µs per instantiation

===============================

This crate implements the cryptographic primitives which are used in many other
Cosmian resources:

- a Data Encryption Method (DEM) based on AES256-GCM (128 bytes of security)
  offering a simple API (Nonce management and authentication checks are internals);
- a Diffie-Hellman key pair based on the curve25519 (128 bytes of security)
  allowing implementation of Diffie-Hellman based asymmetric cryptography;
- a Random Number Generator (RNG) implementing the ChaCha algorithm with 12
  rounds (128 bytes of security).
- a Key Derivation Function (KDF) based on SHAKE128 (128 bytes of security);

All these primitives are use pure rust implementations, are secure, and used
the fastest known algorithms. They offer a great basis on which to build more
complex software.

<!-- toc -->

- [Getting started](#getting-started)
- [Building and Testing](#building-and-testing)
  - [Build](#build)
  - [Use](#use)
  - [Run tests and benchmarks](#run-tests-and-benchmarks)
- [Features and Benchmarks](#features-and-benchmarks)
  - [Asymmetric Crypto](#asymmetric-crypto)
  - [Symmetric Crypto](#symmetric-crypto)
  - [Random Number Generator (RNG)](#random-number-generator-rng)
  - [Key Derivation Function (KDF)](#key-derivation-function-kdf)
- [Documentation](#documentation)

<!-- tocstop -->

## Getting started

The following example can be run using `cargo run --example demo`.

```rust
use cosmian_crypto_core::{
    asymmetric_crypto::{curve25519::X25519KeyPair, DhKeyPair},
    kdf,
    reexport::rand_core::SeedableRng,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem, SymKey},
    CsRng, KeyTrait,
};
use sha3::{
    digest::XofReader,
    digest::{ExtendableOutput, Update},
    Shake128,
};

// The random generator should be instantiated at the highest possible
// level since its creation is relatively costly.
let mut rng = CsRng::from_entropy();

// Secret message we want to transmit privately.
let plaintext = b"My secret message";

// Publicly known information. It can be used to enforce context separation.
let additional_data = Some(b"Some public tag".as_slice());

// Setting of the asymmetric keys
let bob_keypair = X25519KeyPair::new(&mut rng);
let alice_keypair = X25519KeyPair::new(&mut rng);

// In real world applications, DHKEX is often used to derive a symmetric key.
let shared_secret = bob_keypair.public_key() * alice_keypair.private_key();

// Derivation of a secret key from the DHKEX shared secret.
const KEY_DERIVATION_INFO: &[u8] = b"Curve25519 KDF derivation";
const KEY_LENGTH: usize = Aes256GcmCrypto::KEY_LENGTH;
let symmetric_key = SymKey::<KEY_LENGTH>::from_bytes(kdf!(
    KEY_LENGTH,
    &shared_secret.to_bytes(),
    KEY_DERIVATION_INFO
));

// DEM encapsulation using AES256-GCM. In order to prevent nonce reuse,
// the nonce is managed internally.
let c = Aes256GcmCrypto::encrypt(&mut rng, &symmetric_key, plaintext, additional_data).unwrap();

// DEM decryption using AES256-GCM. The additional data used should be the
// same as the one given for encryption.
let res = Aes256GcmCrypto::decrypt(&symmetric_key, &c, additional_data).unwrap();

assert_eq!(res, plaintext, "Decryption failed!");

println!("Message has been privately and successfully transmitted!");
```

## Features and Benchmarks

The benchmarks given below are run on a Intel(R) Core(TM) i7-10750H CPU @ 3.20GHz.

### Asymmetric Crypto

This crate implements a Diffie-Hellman asymmetric key pair based on the
Curve25519. This is one of the fastest elliptic curves known at this time and
it offers 128 bits of security.

It uses the [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
implementation, which offers an implementation of the Ristretto technique to
construct a prime order group on the curve. This group is used to implement
the public key.

```c
Bench the Group-Scalar multiplication on which is based the Diffie-Helman key exchange
                        time:   [59.932 µs 60.131 µs 60.364 µs]
```

### Symmetric Crypto

This crate implements a Data Encryption Method (DEM) based on the AES256-GCM
algorithm, as described in the [ISO 2004](https://www.shoup.net/iso/std6.pdf).
This implementation is 128-bits secure in both the classic and the post-quantum
models.

It uses the [`aes_gcm`](https://docs.rs/aes-gcm/latest/aes_gcm/index.html)
implementation of the AES GCM algorithm. This implementation makes use of the
AES instruction set when available, which allows for a high encryption speed.

```c
Bench the DEM encryption of a 2048-bytes message without additional data
                        time:   [2.7910 µs 2.7911 µs 2.7914 µs]

Bench the DEM decryption of a 2048-bytes message without additional data
                        time:   [2.7074 µs 2.7079 µs 2.7085 µs]
```

### Random Number Generator (RNG)

This crate uses the implementation of the CHACHA algorithm with 12 rounds from
the [`rand_chacha`](https://rust-random.github.io/rand/rand_chacha/index.html)
crate to construct our RNG. It is therefore 128-bits secure.

```c
Bench the generation of a cryptographic RNG
                        time:   [353.84 ns 353.96 ns 354.10 ns]
```

### Key Derivation Function (KDF)

This crate uses the pure rust implementation of the SHAKE128 algorithm from the
[sha3](https://docs.rs/sha3/latest/sha3) crate. This allows implementing a KDF
which 128-bits secure for input sizes of at least 256 bits (32 bytes).

```c
bench the KDF derivation of a 32-bytes IKM into a 64-bytes key
                        time:   [1.1065 µs 1.1067 µs 1.1070 µs]
```

## Documentation

The documentation can be generated using Cargo:

```bash
cargo docs
```

It is also available on
[doc.rs](https://docs.rs/cosmian_crypto_core/latest/cosmian_crypto_core/).

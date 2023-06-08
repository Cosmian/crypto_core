//! Defines the `SymmetricCrypto` and `DEM` traits and provides an
//! implementations of DEMs such as AES 128 GCM and AES 256 GCM

mod aes_128_gcm;
mod aes_256_gcm;
mod chacha20_poly1305;
mod dem;
mod key;
mod nonce;

pub use aes_128_gcm::Aes128Gcm;
pub use aes_256_gcm::Aes256Gcm;
pub use chacha20_poly1305::ChaCha20Poly1305;
pub use dem::{AeadExtra, Dem};
pub use key::SymmetricKey;
pub use nonce::Nonce;

//! Defines the `SymmetricCrypto` and `DEM` traits and provides an
//! implementations of DEMs such as AES 128 GCM and AES 256 GCM

#[cfg(feature = "aes")]
mod aes_128_gcm;
#[cfg(feature = "aes")]
mod aes_256_gcm;
#[cfg(feature = "chacha")]
mod chacha20_poly1305;
mod dem;
mod key;
mod nonce;
#[cfg(feature = "chacha")]
mod xchacha20_poly1305;

#[cfg(feature = "aes")]
pub use aes_128_gcm::Aes128Gcm;
#[cfg(feature = "aes")]
pub use aes_256_gcm::Aes256Gcm;
#[cfg(feature = "chacha")]
pub use chacha20_poly1305::ChaCha20Poly1305;
pub use dem::{Dem, DemInPlace, DemStream, Instantiable};
pub use key::SymmetricKey;
pub use nonce::Nonce;
#[cfg(feature = "chacha")]
pub use xchacha20_poly1305::XChaCha20Poly1305;

//! Defines the `SymmetricCrypto` and `DEM` traits and provides an
//! implementations of DEMs such as AES 128 GCM and AES 256 GCM

pub mod aes_128_gcm;
pub mod aes_256_gcm;
mod dem;
// pub mod chacha20_poly1305;
pub mod key;
pub mod nonce;

pub use dem::{AeadExtra, Dem};

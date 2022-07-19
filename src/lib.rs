mod error;

pub mod asymmetric;
pub mod entropy;
pub mod kdf;
pub mod symmetric_crypto;

pub use crate::error::CryptoBaseError;

pub trait KeyTrait: Sized + Clone {
    const LENGTH: usize;
    fn to_bytes(&self) -> Vec<u8>;
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoBaseError>;
}

use thiserror::Error;

/// Error type for this crate.
#[derive(Debug, Error, PartialEq)]
pub enum CryptoCoreError {
    #[error("Wrong size: {given} given should be {expected}")]
    SizeError { given: usize, expected: usize },
    #[error("Invalid size: {0}")]
    InvalidSize(String),
    #[error("Failed to parse")]
    HexParseError(#[from] hex::FromHexError),
    #[error("Failed to convert: {0}")]
    ConversionError(String),
    #[error("Cannot derive key of size {0}")]
    KdfError(usize),
    #[error("Key generation error")]
    KeyGenError,
    #[error("{0}")]
    EncryptionError(String),
    #[error("{0}")]
    DecryptionError(String),
    #[error("{0}")]
    HardwareCapability(String),
}

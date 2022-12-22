use thiserror::Error;

/// Error type for this crate.
#[derive(Debug, Error)]
pub enum CryptoCoreError {
    #[error("wrong size when parsing bytes: {given} given should be {expected}")]
    DeserialisationSizeError { given: usize, expected: usize },
    #[error("when reading LEB128 size, {0}")]
    ReadLeb128Error(leb128::read::Error),
    #[error("deserialisation error: {0}")]
    GenericDeserialisationError(String),

    #[error("when writing {value} as LEB128 size, IO error {error}")]
    WriteLeb128Error { value: u64, error: std::io::Error },

    #[error("when writing {bytes_len} bytes, IO error {error}")]
    SerialisationIoError {
        bytes_len: usize,
        error: std::io::Error,
    },

    #[error("when encrypting, plaintext of {plaintext_len} bytes is too big, max is {max} bytes")]
    PlaintextTooBigError { plaintext_len: usize, max: u64 },
    #[error(
        "when decrypting, ciphertext of {ciphertext_len} bytes is too small, min is {min} bytes"
    )]
    CiphertextTooSmallError { ciphertext_len: usize, min: u64 },
    #[error(
        "when decrypting, ciphertext of {ciphertext_len} bytes is too big, max is {max} bytes"
    )]
    CiphertextTooBigError { ciphertext_len: usize, max: u64 },

    #[error("failed to convert: {0}")]
    ConversionError(String),

    #[error("error during encryption")]
    EncryptionError,
    #[error("error during decryption")]
    DecryptionError,

    #[error("Failed to parse")]
    HexParseError(#[from] hex::FromHexError),
}

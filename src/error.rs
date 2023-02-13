use core::fmt::Display;

/// Error type for this crate.
#[derive(Debug)]
pub enum CryptoCoreError {
    DeserialisationEmptyError,
    DeserialisationSizeError {
        given: usize,
        expected: usize,
    },
    ReadLeb128Error(leb128::read::Error),
    GenericDeserialisationError(String),
    WriteLeb128Error {
        value: u64,
        error: std::io::Error,
    },
    SerialisationIoError {
        bytes_len: usize,
        error: std::io::Error,
    },
    PlaintextTooBigError {
        plaintext_len: usize,
        max: u64,
    },
    CiphertextTooSmallError {
        ciphertext_len: usize,
        min: u64,
    },
    CiphertextTooBigError {
        ciphertext_len: usize,
        max: u64,
    },
    ConversionError(String),
    EncryptionError,
    DecryptionError,
}

impl Display for CryptoCoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeserialisationEmptyError => write!(f, "empty input when parsing bytes"),
            Self::DeserialisationSizeError { given, expected } => write!(
                f,
                "wrong size when parsing bytes: {given} given should be {expected}"
            ),
            Self::ReadLeb128Error(err) => write!(f, "when reading LEB128, {err}"),
            Self::GenericDeserialisationError(err) => write!(f, "deserialisation error: {err}"),
            Self::WriteLeb128Error { value, error } => {
                write!(f, "when writing {value} as LEB128 size, IO error {error}")
            }
            Self::SerialisationIoError { bytes_len, error } => {
                write!(f, "when writing {bytes_len} bytes, {error}")
            }
            Self::PlaintextTooBigError { plaintext_len, max } => write!(
                f,
                "when encrypting, plaintext of {plaintext_len} bytes is too big, max is {max} \
                 bytes"
            ),
            Self::CiphertextTooSmallError {
                ciphertext_len,
                min,
            } => write!(
                f,
                "when decrypting, ciphertext of {ciphertext_len} bytes is too small, min is {min} \
                 bytes"
            ),
            Self::CiphertextTooBigError {
                ciphertext_len,
                max,
            } => write!(
                f,
                "when decrypting, ciphertext of {ciphertext_len} bytes is too big, max is {max} \
                 bytes"
            ),
            Self::ConversionError(err) => write!(f, "failed to convert: {err}"),
            Self::EncryptionError => write!(f, "error during encryption"),
            Self::DecryptionError => write!(f, "error during decryption"),
        }
    }
}

impl std::error::Error for CryptoCoreError {}

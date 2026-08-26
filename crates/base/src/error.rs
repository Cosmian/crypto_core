use core::fmt::Display;
use std::io;

/// Error type for this crate.
#[derive(Debug)]
pub enum Error {
    DecryptionError,
    DeserializationEmptyError,
    DeserializationIoError {
        bytes_len: usize,
        error: String,
    },
    DeserializationSizeError {
        given: usize,
        expected: usize,
    },
    GenericDeserializationError(String),
    GenericSerializationError(String),
    InversionError(String),
    ReadLeb128Error(leb128::read::Error),
    SerializationIoError {
        bytes_len: usize,
        error: std::io::Error,
    },
    WriteLeb128Error {
        value: u64,
        error: io::Error,
    },
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InversionError(e) => write!(f, "inversion error: {e}"),
            Self::DecryptionError => write!(f, "error during decryption"),
            Self::DeserializationEmptyError => {
                write!(f, "empty input when parsing bytes")
            }
            Self::DeserializationSizeError { given, expected } => write!(
                f,
                "wrong size when parsing bytes: {given} given should be {expected}"
            ),
            Self::GenericDeserializationError(err) => {
                write!(f, "deserialization error: {err}")
            }
            Self::GenericSerializationError(err) => {
                write!(f, "serialization error: {err}")
            }
            Self::ReadLeb128Error(err) => write!(f, "when reading LEB128, {err}"),
            Self::DeserializationIoError { bytes_len, error } => {
                write!(f, "when reading {bytes_len} bytes, {error}")
            }
            Self::SerializationIoError { bytes_len, error } => {
                write!(f, "when writing {bytes_len} bytes, {error}")
            }
            Self::WriteLeb128Error { value, error } => {
                write!(f, "when writing {value} as LEB128 size, IO error {error}")
            }
        }
    }
}

impl std::error::Error for Error {}

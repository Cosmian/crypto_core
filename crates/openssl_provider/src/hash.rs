use cosmian_crypto_core::traits::{HASH, XOF};
use openssl::{
    error::ErrorStack,
    hash::{Hasher, MessageDigest},
};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256;

impl HASH<32> for Sha256 {
    type State = Hasher;

    type Error = ErrorStack;

    fn initialize() -> Result<Self::State, Self::Error> {
        Hasher::new(MessageDigest::sha256())
    }

    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error> {
        state.update(bytes)
    }

    fn finalize(mut state: Self::State, buffer: &mut [u8; 32]) -> Result<(), Self::Error> {
        let mut bytes = state.finish()?;
        buffer.copy_from_slice(&bytes);
        // Zeroize the bytes in case they are used as a secret.
        bytes.zeroize();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha3_256;

impl HASH<32> for Sha3_256 {
    type State = Hasher;

    type Error = ErrorStack;

    fn initialize() -> Result<Self::State, Self::Error> {
        Hasher::new(MessageDigest::sha3_256())
    }

    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error> {
        state.update(bytes)
    }

    fn finalize(mut state: Self::State, buffer: &mut [u8; 32]) -> Result<(), Self::Error> {
        let mut bytes = state.finish()?;
        buffer.copy_from_slice(&bytes);
        // Zeroize the bytes in case they are used as a secret.
        bytes.zeroize();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shake256;

impl XOF for Shake256 {
    type State = Hasher;

    type Error = ErrorStack;

    fn initialize() -> Result<Self::State, Self::Error> {
        Hasher::new(MessageDigest::shake_256())
    }

    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error> {
        state.update(bytes)
    }

    fn finalize(mut state: Self::State, buffer: &mut [u8]) -> Result<(), Self::Error> {
        state.finish_xof(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_core::traits::tests::{test_hash, test_xof};

    #[test]
    fn test_hash_algorithms() {
        test_hash::<{ Sha256::LENGTH }, Sha256>();
        test_hash::<{ Sha3_256::LENGTH }, Sha3_256>();
        test_xof::<Shake256>();
    }
}

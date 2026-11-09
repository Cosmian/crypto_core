use cosmian_crypto_base::traits::{HASH, SHA256, SHA3_256, SHA3_512, SHA512};
use libcrux_sha2::Digest;
use libcrux_traits::digest::{
    arrayref::DigestIncremental, DigestIncrementalBase, InitializeDigestState,
};

use crate::error::Error;

pub struct Sha256;

impl HASH<32> for Sha256 {
    type State = libcrux_sha2::Sha256;

    type Error = Error;

    fn initialize() -> Result<Self::State, Self::Error> {
        Ok(libcrux_sha2::Sha256::new())
    }

    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error> {
        state.update(bytes);
        Ok(())
    }

    fn finalize(state: Self::State, bytes: &mut [u8; 32]) -> Result<(), Self::Error> {
        state.finish(bytes);
        Ok(())
    }
}

impl SHA256 for Sha256 {}

pub struct Sha512;

impl HASH<64> for Sha512 {
    type State = libcrux_sha2::Sha512;

    type Error = Error;

    fn initialize() -> Result<Self::State, Self::Error> {
        Ok(libcrux_sha2::Sha512::new())
    }

    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error> {
        state.update(bytes);
        Ok(())
    }

    fn finalize(state: Self::State, bytes: &mut [u8; 64]) -> Result<(), Self::Error> {
        state.finish(bytes);
        Ok(())
    }
}

impl SHA512 for Sha512 {}

pub struct Sha3_256;

impl HASH<32> for Sha3_256 {
    type State = libcrux_sha3::Sha3_256;

    type Error = Error;

    fn initialize() -> Result<Self::State, Self::Error> {
        Ok(libcrux_sha3::Sha3_256::new())
    }

    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error> {
        <libcrux_sha3::Sha3_256 as DigestIncrementalBase>::update(state, bytes)?;
        Ok(())
    }

    fn finalize(state: Self::State, bytes: &mut [u8; 32]) -> Result<(), Self::Error> {
        <libcrux_sha3::Sha3_256 as DigestIncremental<{ Self::LENGTH }>>::finish(state, bytes);
        Ok(())
    }
}

impl SHA3_256 for Sha3_256 {}

pub struct Sha3_512;

impl HASH<64> for Sha3_512 {
    type State = libcrux_sha3::Sha3_512;

    type Error = Error;

    fn initialize() -> Result<Self::State, Self::Error> {
        Ok(libcrux_sha3::Sha3_512::new())
    }

    fn update(state: &mut Self::State, bytes: &[u8]) -> Result<(), Self::Error> {
        <libcrux_sha3::Sha3_512 as DigestIncrementalBase>::update(state, bytes)?;
        Ok(())
    }

    fn finalize(state: Self::State, bytes: &mut [u8; 64]) -> Result<(), Self::Error> {
        <libcrux_sha3::Sha3_512 as DigestIncremental<{ Self::LENGTH }>>::finish(state, bytes);
        Ok(())
    }
}

impl SHA3_512 for Sha3_512 {}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_base::traits::test_sha256;

    #[test]
    fn test_libcrux_sha256() {
        test_sha256::<Sha256>();
    }
}

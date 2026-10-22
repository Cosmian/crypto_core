use cosmian_crypto_base::traits::HASH;
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

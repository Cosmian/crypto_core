//! Defines a symmetric key object of variable size.

use core::{hash::Hash, ops::Deref};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SecretKey;

/// Symmetric key of a given size.
///
/// It is internally built using an array of bytes of the given length.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct Key<const LENGTH: usize>([u8; LENGTH]);

// impl<const LENGTH: usize> KeyTrait<LENGTH> for Key<LENGTH> {
//     /// Generates a new symmetric random `Key`.
//     fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
//         let mut key = [0; LENGTH];
//         rng.fill_bytes(&mut key);
//         Self(key)
//     }

//     /// Converts the given key into bytes.
//     fn to_bytes(&self) -> [u8; LENGTH] {
//         self.0.to_owned()
//     }

//     /// Tries to convert the given bytes into a key.
//     fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
//         let bytes = <[u8; LENGTH]>::try_from(bytes)
//             .map_err(|e| CryptoCoreError::ConversionError(e.to_string()))?;
//         Ok(Self(bytes))
//     }
// }

impl<const LENGTH: usize> crate::Key for Key<LENGTH> {}

impl<const LENGTH: usize> crate::FixedSizeKey for Key<LENGTH> {
    const LENGTH: usize = LENGTH;

    fn to_bytes(&self) -> Vec<u8> {
        self.0.into()
    }

    fn try_from_slice(slice: &[u8]) -> Result<Self, crate::CryptoCoreError> {
        slice
            .try_into()
            .map(|bytes| Self(bytes))
            .map_err(|_| crate::CryptoCoreError::InvalidKeyLength)
    }
}

impl<const LENGTH: usize> SecretKey for Key<LENGTH> {
    fn new<R: rand_chacha::rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        let mut key = [0; LENGTH];
        rng.fill_bytes(&mut key);
        Self(key)
    }

    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl<const LENGTH: usize> Zeroize for Key<LENGTH> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Implements `Drop` trait to follow R23.
impl<const LENGTH: usize> Drop for Key<LENGTH> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for Key<LENGTH> {}

impl<const LENGTH: usize> Deref for Key<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {

    use crate::{reexport::rand_core::SeedableRng, symmetric_crypto::key::Key, CsRng, SecretKey};

    const KEY_LENGTH: usize = 32;

    #[test]
    fn test_key() {
        let mut cs_rng = CsRng::from_entropy();
        let key_1 = Key::<KEY_LENGTH>::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_1.len());
        let key_2 = Key::new(&mut cs_rng);
        assert_eq!(KEY_LENGTH, key_2.len());
        assert_ne!(key_1, key_2);
    }
}

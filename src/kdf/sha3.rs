use crate::{traits::KDF, SymmetricKey};
pub use tiny_keccak::{Hasher, Shake};

pub struct Kdf;

impl<const KEY_LENGTH: usize> KDF<KEY_LENGTH> for Kdf {
    fn derive(key: &[u8], info: &[u8]) -> SymmetricKey<KEY_LENGTH> {
        let mut bytes = SymmetricKey::default();
        let mut hasher = Shake::v256();
        hasher.update(key);
        hasher.update(info);
        hasher.finalize(&mut *bytes);
        bytes
    }
}

/// Key Derivation Function (KDF).
///
/// Derives the given inputs to the desired length using SHAKE128, which should
/// then be imported where this macro is used.
///
/// # Security
///
/// The input length needs to be at least 256 bits to give 128 bits of security.
///
/// [source](https://en.wikipedia.org/wiki/SHA-3#Instances)
///
/// For smaller inputs like passwords, the Argon2 algorithm should be used.
///
/// # Example
///
/// ```
/// #[macro_use]
/// use cosmian_crypto_core::kdf128;
///
/// const KEY_LENGTH: usize = 16;
///
/// const IKM: &str = "asdf34@!dsa@grq5e$2ASGy5";
///
/// // derive a 32-bytes key
/// let mut key = [0; KEY_LENGTH];
/// kdf128!(&mut key, IKM.as_bytes());
///
/// assert_eq!(KEY_LENGTH, key.len());
///
/// let mut key2 = [0; KEY_LENGTH];
/// kdf128!(&mut key2, IKM.as_bytes());
/// assert_eq!(key, key2);
/// ```
///
/// # Parameters
///
/// - `res`     : output to be updated in-place
/// - `bytes`   : KDF input
#[macro_export]
macro_rules! kdf128 {
    ($res: expr, $($bytes: expr),+) => {
        {
            let mut hasher = $crate::kdf::Shake::v128();
            $(
                <$crate::kdf::Shake as $crate::kdf::Hasher>::update(&mut hasher, $bytes);
            )*
            <$crate::kdf::Shake as $crate::kdf::Hasher>::finalize(hasher, $res);
        }
    };
}

/// Key Derivation Function (KDF).
///
/// Derives the given inputs to the desired length using SHAKE256, which should
/// then be imported where this macro is used.
///
/// # Security
///
/// The input length needs to be at least 512 bits to give 256 bits of security.
///
/// [source](https://en.wikipedia.org/wiki/SHA-3#Instances)
///
/// For smaller inputs like passwords, the Argon2 algorithm should be used.
///
/// # Example
///
/// ```
/// #[macro_use]
/// use cosmian_crypto_core::kdf256;
///
/// const KEY_LENGTH: usize = 32;
///
/// const ikm: &str = "asdf34@!dsa@grq5e$2ASGy5";
///
/// // derive a 32-bytes key
/// let mut key = [0; KEY_LENGTH];
/// kdf256!(&mut key, ikm.as_bytes());
///
/// assert_eq!(KEY_LENGTH, key.len());
///
/// let mut key2 = [0; KEY_LENGTH];
/// kdf256!(&mut key2, ikm.as_bytes());
/// assert_eq!(key, key2);
/// ```
///
/// # Parameters
///
/// - `res`     : output to be updated in-place
/// - `bytes`   : KDF input
#[macro_export]
macro_rules! kdf256 {
    ($res: expr, $($bytes: expr),+) => {
        {
            let mut hasher = $crate::kdf::Shake::v256();
            $(
                <$crate::kdf::Shake as $crate::kdf::Hasher>::update(&mut hasher, $bytes);
            )*
            <$crate::kdf::Shake as $crate::kdf::Hasher>::finalize(hasher, $res);
        }
    };
}

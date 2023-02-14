pub use tiny_keccak::{Hasher, Shake};

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
/// use cosmian_crypto_core::kdf;
///
/// const KEY_LENGTH: usize = 32;
///
/// const ikm: &str = "asdf34@!dsa@grq5e$2ASGy5";
///
/// // derive a 32-bytes key
/// let key = kdf!(KEY_LENGTH, ikm.as_bytes());
///
/// assert_eq!(KEY_LENGTH, key.len());
/// assert_eq!(key, kdf!(KEY_LENGTH, ikm.as_bytes()));
/// ```
///
/// # Parameters
///
/// - `length`  : desired length (needs to be constant)
/// - `bytes`   : KDF input
#[macro_export]
macro_rules! kdf {
    ($length: ident, $($bytes: expr),+) => {
        {
            let mut res = [0; $length];
            let mut hasher = $crate::kdf::Shake::v256();
            $(
                <$crate::kdf::Shake as $crate::kdf::Hasher>::update(&mut hasher, $bytes);
            )*
            <$crate::kdf::Shake as $crate::kdf::Hasher>::finalize(hasher, &mut res);
            res
        }
    };
}

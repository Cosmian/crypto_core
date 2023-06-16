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
/// const ikm: &str = "asdf34@!dsa@grq5e$2ASGy5";
///
/// // derive a 32-bytes key
/// let key = kdf128!(KEY_LENGTH, ikm.as_bytes());
///
/// assert_eq!(KEY_LENGTH, key.len());
/// assert_eq!(key, kdf128!(KEY_LENGTH, ikm.as_bytes()));
/// ```
///
/// # Parameters
///
/// - `length`  : desired length (needs to be constant)
/// - `bytes`   : KDF input
#[macro_export]
macro_rules! kdf128 {
    ($length: expr, $($bytes: expr),+) => {
        {
            let mut res = [0; $length];
            let mut hasher = tiny_keccak::Shake::v128();
            $(
                <tiny_keccak::Shake as tiny_keccak::Hasher>::update(&mut hasher, $bytes);
            )*
            <tiny_keccak::Shake as tiny_keccak::Hasher>::finalize(hasher, &mut res);
            res
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
/// let key = kdf256!(KEY_LENGTH, ikm.as_bytes());
///
/// assert_eq!(KEY_LENGTH, key.len());
/// assert_eq!(key, kdf256!(KEY_LENGTH, ikm.as_bytes()));
/// ```
///
/// # Parameters
///
/// - `length`  : desired length (needs to be constant)
/// - `bytes`   : KDF input
#[macro_export]
macro_rules! kdf256 {
    ($length: expr, $($bytes: expr),+) => {
        {
            let mut res = [0; $length];
            let mut hasher = tiny_keccak::Shake::v256();
            $(
                <tiny_keccak::Shake as tiny_keccak::Hasher>::update(&mut hasher, $bytes);
            )*
            <tiny_keccak::Shake as tiny_keccak::Hasher>::finalize(hasher, &mut res);
            res
        }
    };
}

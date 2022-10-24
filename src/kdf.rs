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
/// use sha3::{
///     digest::{ExtendableOutput, Update, XofReader},
///     Shake128,
/// };
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
            let mut hasher = Shake128::default();
            $(
                hasher.update($bytes);
            )*
            let mut reader = hasher.finalize_xof();
            let mut res = [0; $length];
            reader.read(&mut res);
            res
        }
    };
}

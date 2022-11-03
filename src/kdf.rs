use crate::CryptoCoreError;
pub use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Keccak256, Shake128,
};

/// Security level of 128-bits (in bytes)
pub const SECURITY_LEVEL: usize = 32;

/// Key Derivation Function (KDF).
///
/// Derives the given inputs to the desired length using SHAKE128, which should
/// then be imported where this macro is used.
///
/// # Security
///
/// In order to guarantee 128 bits of pre-quantum security, the input length
/// needs to be at least 128 bits and the output length needs to be at least
/// 256 bits.
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
    ($output_length: ident, $($bytes: expr),+) => {
        {
            let mut input_length = 0;
            $(
                input_length += $bytes.len();
            )+
            if input_length < $crate::kdf::SECURITY_LEVEL {
                Err($crate::CryptoCoreError::InvalidSize(format!(
                            "Input bytes length is too small to guarantee security: {}, should be at least {}",
                            input_length,
                            $crate::kdf::SECURITY_LEVEL
                )))
            } else if $output_length < 2 * $crate::kdf::SECURITY_LEVEL {
                Err($crate::CryptoCoreError::InvalidSize(format!(
                            "Output bytes length too small to guarantee security: {}, should be at least {}",
                            $output_length,
                            2 * $crate::kdf::SECURITY_LEVEL
                )))
            } else {
                let mut hasher = $crate::kdf::Shake128::default();
                // macro is useful to allow passing several `bytes` arguments
                $(
                    <$crate::kdf::Shake128 as $crate::kdf::Update>::update(&mut hasher, $bytes);
                )*
                    let mut reader = <$crate::kdf::Shake128 as $crate::kdf::ExtendableOutput>::finalize_xof(hasher);
                let mut res = [0; $output_length];
                <<$crate::kdf::Shake128 as $crate::kdf::ExtendableOutput>::Reader as $crate::kdf::XofReader>::read(&mut reader, &mut res);
                Ok(res)
            }
        }
    };
}

/// Pads the given bytes to the given padding value.
///
/// - `w`   : padding value
/// - `X`   : bytes to pad
macro_rules! byte_pad {
    ($w: expr, $($X: expr),+) => {
        {let mut length = 0;
            $(
                length += $X.len();
            )+
                let mut res = Vec::with_capacity(length + length % $w);
            // macro is useful to allow passing seceral `bytes` arguments
            $(
                res.extend($X);
            )+
                res.extend((res.len()..res.capacity()).map(|_| 0));
            res
        }
    };
}

/// Implementation of the KMAC algorithm as specified in the NIST standard.
/// <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf>
///
/// The length of the output is `OUTPUT_LENGTH`.
///
/// # Security
///
/// The security is 128 pre-quantum bits.
///
/// # Parameters
///
/// - `key`     : KMAC key
/// - `message` : KMAC message
/// - `seed`    : KMAC seed
pub fn kmac<const OUTPUT_LENGTH: usize>(
    key: &[u8],
    message: &[u8],
    seed: &[u8],
) -> Result<[u8; OUTPUT_LENGTH], CryptoCoreError> {
    // NIST standard specifies the padding value should be 168 bits = 21 bytes
    const PADDING_VALUE: usize = 21;
    const INFO: &[u8] = b"KMAC";
    // check the key length is greater than 128 bits
    if key.len() < SECURITY_LEVEL {
        return Err(CryptoCoreError::InvalidSize(format!(
            "Key too smal to guarantee security: {}, should be at least {SECURITY_LEVEL}",
            key.len(),
        )));
    }
    // check the output length is greater than 128 bits
    if OUTPUT_LENGTH < 2 * SECURITY_LEVEL {
        return Err(CryptoCoreError::InvalidSize(format!(
            "Key too smal to guarantee security: {OUTPUT_LENGTH}, should be at least {}",
            2 * SECURITY_LEVEL
        )));
    }
    let mut hasher = Shake128::default();
    hasher.update(&byte_pad!(PADDING_VALUE, INFO, seed));
    hasher.update(&byte_pad!(PADDING_VALUE, key));
    hasher.update(message);
    hasher.update(&OUTPUT_LENGTH.to_be_bytes());
    let mut reader = hasher.finalize_xof();
    let mut res = [0; OUTPUT_LENGTH];
    reader.read(&mut res);
    Ok(res)
}

pub use blake2::{Blake2b512, Blake2s256, Digest};

/// Blake2b 512 Variable Output Hash Function.
///
/// Blake2b is a cryptographic hash function defined in RFC 7693.
/// `<https://www.rfc-editor.org/rfc/rfc7693.txt>`
///
/// Collision Security: 2^256 (in the classic setting)
///
/// # Example
///
/// ```
/// #[macro_use]
/// use cosmian_crypto_core::{blake2b, CryptoCoreError};
///
/// const LENGTH: usize = 12;
///
/// fn hash_with_blake2b() -> Result<[u8; LENGTH], CryptoCoreError> {
///     let msg1 = b"asdf34@!dsa@grq5e$2ASGy5";
///     let msg2 = b"oiu54%6uhg1@34";
///     let mut out = [0; LENGTH];
///     blake2b!(out, msg1, msg2)?;
///     Ok(out)
/// }
///
/// let res = hash_with_blake2b().unwrap();
///
/// assert_eq!(LENGTH, res.len());
/// ```
///
/// # Parameters
///
/// - `res`     : output to be updated in-place
/// - `bytes`   : Hash input
#[macro_export]
macro_rules! blake2b {
    ($res: expr, $($bytes: expr),+) => {
        {
            let length = $res.len();
            if length <= 64 {
                let mut hasher = <$crate::blake2::Blake2b512 as $crate::blake2::Digest>::new();
                $(
                    <$crate::blake2::Blake2b512 as $crate::blake2::Digest>::update(&mut hasher, $bytes);
                )*
                let h = <$crate::blake2::Blake2b512 as $crate::blake2::Digest>::finalize(hasher);
                $res.copy_from_slice(&h[..length]);
                Ok(())
            } else {
                Err($crate::CryptoCoreError::InvalidBytesLength("blake2b".to_string(), length, None))
            }
        }
    };
}

/// Blake2s 256 Hash Function with Variable Output.
///
/// Blake2s is a cryptographic hash function defined in RFC 7693.
/// `<https://www.rfc-editor.org/rfc/rfc7693.txt>`
///
/// Collision Security: 2^128 (in the classic setting)
///
/// # Example
///
/// ```
/// #[macro_use]
/// use cosmian_crypto_core::{blake2s, CryptoCoreError};
///
/// const LENGTH: usize = 12;
///
/// fn hash_with_blake2s() -> Result<[u8; LENGTH], CryptoCoreError> {
///     let msg1 = b"asdf34@!dsa@grq5e$2ASGy5";
///     let msg2 = b"oiu54%6uhg1@34";
///     let mut out = [0; LENGTH];
///     blake2s!(out, msg1, msg2)?;
///     Ok(out)
/// }
///
/// let res = hash_with_blake2s().unwrap();
///
/// assert_eq!(LENGTH, res.len());
/// ```
///
/// # Parameters
///
/// - `res`     : output to be updated in-place
/// - `bytes`   : Hash input
#[macro_export]
macro_rules! blake2s {
    ($res: expr, $($bytes: expr),+) => {
        {
            let length = $res.len();
            if length <= 32 {
                let mut hasher = <$crate::blake2::Blake2s256 as $crate::blake2::Digest>::new();
                $(
                    <$crate::blake2::Blake2s256 as $crate::blake2::Digest>::update(&mut hasher, $bytes);
                )*
                let h = <$crate::blake2::Blake2s256 as $crate::blake2::Digest>::finalize(hasher);
                $res.copy_from_slice(&h[..length]);
                Ok(())
            } else {
                Err($crate::CryptoCoreError::InvalidBytesLength("blake2b".to_string(), length, None))
            }
        }
    };
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::CryptoCoreError;

    #[test]
    fn test_blake_2b() -> Result<(), CryptoCoreError> {
        const LENGTH: usize = 12;

        let msg1 = b"asdf34@!dsa@grq5e$2ASGy5";
        let msg2 = b"oiu54%6uhg1@34";

        let mut res1 = [0; LENGTH];

        {
            let mut hasher = Blake2b512::new();
            hasher.update(msg1);
            hasher.update(msg2);
            let h = hasher.finalize();
            res1.copy_from_slice(&h[..LENGTH]);
        }

        let mut res2 = [0; LENGTH];
        blake2b!(res2, msg1, msg2)?;

        assert_eq!(res1, res2);
        Ok(())
    }

    #[test]
    fn test_blake_2s() -> Result<(), CryptoCoreError> {
        const LENGTH: usize = 12;

        let msg1 = b"asdf34@!dsa@grq5e$2ASGy5";
        let msg2 = b"oiu54%6uhg1@34";

        let mut res1 = [0; LENGTH];

        {
            let mut hasher = Blake2s256::new();
            hasher.update(msg1);
            hasher.update(msg2);
            let h = hasher.finalize();
            res1.copy_from_slice(&h[..LENGTH]);
        }

        let mut res2 = [0; LENGTH];
        blake2s!(res2, msg1, msg2)?;

        assert_eq!(res1, res2);
        Ok(())
    }
}

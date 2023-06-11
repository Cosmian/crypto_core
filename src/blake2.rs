pub use tiny_keccak::{Hasher, Shake};

/// Blake2b 512 Variable Output Hash Function.
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
///     blake2b!(LENGTH, msg1, msg2)
/// }
///
/// let res = hash_with_blake2b().unwrap();
///
/// assert_eq!(LENGTH, res.len());
/// ```
///
/// # Parameters
///
/// - `length`  : desired length (needs to be constant)
/// - `bytes`   : Hash input
#[macro_export]
macro_rules! blake2b {
    ($length: expr, $($bytes: expr),+) => {
        {
            use $crate::digest::VariableOutput;
            let mut res = [0; $length];
            let mut hasher = match blake2::Blake2bVar::new($length) {
                Ok(hasher) => hasher,
                Err(_) => return Err(CryptoCoreError::InvalidBytesLength),
            };
            $(
                <blake2::Blake2bVar as blake2::digest::Update>::update(&mut hasher, $bytes);
            )*
            if let Err(_) =
                <blake2::Blake2bVar as blake2::digest::VariableOutput>::finalize_variable(
                    hasher, &mut res,
                )
            {
                return Err(CryptoCoreError::InvalidBytesLength);
            }
            Result::<_, CryptoCoreError>::Ok(res)
        }
    };
}

/// Blake2s 256 Hash Function.
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
///     blake2s!(LENGTH, msg1, msg2)
/// }
///
/// let res = hash_with_blake2s().unwrap();
///
/// assert_eq!(LENGTH, res.len());
/// ```
///
/// # Parameters
///
/// - `length`  : desired length (needs to be constant)
/// - `bytes`   : KDF input
#[macro_export]
macro_rules! blake2s {
    ($length: expr, $($bytes: expr),+) => {
        {
            use $crate::digest::VariableOutput;
            let mut res = [0; $length];
            let mut hasher = match blake2::Blake2sVar::new($length) {
                Ok(hasher) => hasher,
                Err(_) => return Err(CryptoCoreError::InvalidBytesLength),
            };
            $(
                <blake2::Blake2sVar as blake2::digest::Update>::update(&mut hasher, $bytes);
            )*
            if let Err(_) =
                <blake2::Blake2sVar as blake2::digest::VariableOutput>::finalize_variable(
                    hasher, &mut res,
                )
            {
                return Err(CryptoCoreError::InvalidBytesLength);
            }
            Result::<_, CryptoCoreError>::Ok(res)
        }
    };
}

#[cfg(test)]
mod tests {
    use blake2;
    use blake2::digest::VariableOutput;

    use crate::CryptoCoreError;

    #[test]
    fn test_blake_2b() -> Result<(), CryptoCoreError> {
        const LENGTH: usize = 12;

        let msg1 = b"asdf34@!dsa@grq5e$2ASGy5";
        let msg2 = b"oiu54%6uhg1@34";

        let res1 = {
            let mut res = [0_u8; LENGTH];

            let mut hasher = match blake2::Blake2bVar::new(LENGTH) {
                Ok(hasher) => hasher,
                Err(_) => return Err(CryptoCoreError::InvalidBytesLength),
            };
            <blake2::Blake2bVar as blake2::digest::Update>::update(&mut hasher, msg1);
            <blake2::Blake2bVar as blake2::digest::Update>::update(&mut hasher, msg2);
            if let Err(_) =
                <blake2::Blake2bVar as blake2::digest::VariableOutput>::finalize_variable(
                    hasher, &mut res,
                )
            {
                return Err(CryptoCoreError::InvalidBytesLength);
            }
            Result::<_, CryptoCoreError>::Ok(res)
        }?;
        // use the macro
        let res2 = blake2b!(LENGTH, msg1, msg2)?;
        assert_eq!(res1, res2);

        Ok(())
    }

    #[test]
    fn test_blake_2s() -> Result<(), CryptoCoreError> {
        const LENGTH: usize = 12;

        let msg1 = b"asdf34@!dsa@grq5e$2ASGy5";
        let msg2 = b"oiu54%6uhg1@34";

        let res1 = {
            let mut res = [0_u8; LENGTH];

            let mut hasher =
                blake2::Blake2sVar::new(LENGTH).map_err(|_| CryptoCoreError::InvalidBytesLength)?;
            <blake2::Blake2sVar as blake2::digest::Update>::update(&mut hasher, msg1);
            <blake2::Blake2sVar as blake2::digest::Update>::update(&mut hasher, msg2);
            <blake2::Blake2sVar as blake2::digest::VariableOutput>::finalize_variable(
                hasher, &mut res,
            )
            .map_err(|_| CryptoCoreError::InvalidBytesLength)?;
            Result::<_, CryptoCoreError>::Ok(res)
        }?;
        // use the macro
        let res2 = blake2s!(LENGTH, msg1, msg2)?;
        assert_eq!(res1, res2);

        Ok(())
    }
}

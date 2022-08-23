use crate::CryptoCoreError;
use generic_array::{ArrayLength, GenericArray};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a key of `KEY_LENGTH` bytes using a HMAC-based Extract-and-Expand
/// Key Derivation Function (HKDF) supplying a `bytes` and some `info` context
/// `String`. The hash function used is Sha256.
///
/// - `bytes`   : input bytes to hash, should be at least 32-bytes long
/// - `info`    : some optional additional information to use in the hash
pub fn hkdf_256<KeyLength: ArrayLength<u8>>(
    bytes: &[u8],
    info: &[u8],
) -> Result<GenericArray<u8, KeyLength>, CryptoCoreError> {
    if bytes.len() < 32 {
        return Err(CryptoCoreError::InvalidSize(
            "Input `bytes` size should be at least 32".to_string(),
        ));
    }
    let h = Hkdf::<Sha256>::new(None, bytes);
    let mut out = GenericArray::<u8, KeyLength>::default();
    h.expand(info, &mut out)
        .map_err(|_| CryptoCoreError::KdfError(KeyLength::to_usize()))?;
    Ok(out)
}

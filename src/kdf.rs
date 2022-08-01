use crate::CryptoCoreError;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a key of `KEY_LENGTH` bytes using a HMAC-based Extract-and-Expand
/// Key Derivation Function (HKDF) supplying a `bytes` and some `info` context
/// `String`. The hash function used is Sha256.
///
/// - `bytes`   : input bytes to hash, should be at least 32-bytes long
/// - `info`    : some optional additional information to use in the hash
pub fn hkdf_256<const KEY_LENGTH: usize>(
    bytes: &[u8],
    info: &[u8],
) -> Result<[u8; KEY_LENGTH], CryptoCoreError> {
    if bytes.len() < 32 {
        return Err(CryptoCoreError::InvalidSize(
            "Input `bytes` should be of length at least 32".to_string(),
        ));
    }
    let h = Hkdf::<Sha256>::new(None, bytes);
    let mut out = [0_u8; KEY_LENGTH];
    h.expand(info, &mut out)
        .map_err(|_| CryptoCoreError::KdfError(KEY_LENGTH))?;
    Ok(out)
}

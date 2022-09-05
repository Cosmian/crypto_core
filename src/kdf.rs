use crate::CryptoCoreError;
use hkdf::Hkdf;
use sha2::{digest::OutputSizeUser, Sha256};

/// Derive a key of `KEY_LENGTH` bytes using a HMAC-based Extract-and-Expand
/// Key Derivation Function (HKDF) supplying a `bytes` and some `info` context
/// `String`. The hash function used is Sha256.
///
/// - `ikm`     : input key material, should be at least 32-bytes long
/// - `info`    : some optional additional information to use in the hash
pub fn hkdf_256<const LENGTH: usize>(
    ikm: &[u8],
    info: &[u8],
) -> Result<[u8; LENGTH], CryptoCoreError> {
    if ikm.len() < <Sha256 as OutputSizeUser>::output_size() {
        return Err(CryptoCoreError::InvalidSize(format!(
            "Input `bytes` size should be at least {} bytes",
            <Sha256 as OutputSizeUser>::output_size()
        )));
    }
    let h = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0; LENGTH];
    h.expand(info, &mut out)
        .map_err(|_| CryptoCoreError::KdfError(LENGTH))?;
    Ok(out)
}

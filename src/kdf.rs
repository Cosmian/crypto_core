use hkdf::Hkdf;
use sha2::Sha256;

use crate::CryptoBaseError;

/// Derive a key of `key_len` bytes using a HMAC-based Extract-and-Expand Key
/// Derivation Function (HKDF) supplying a `master` key and some `info`
/// context String. The hash function used is sha256.
///
/// TODO: implement traits for KDF and implement other versions ?
///
/// - `master`  : input bytes to hash
/// - `key_len` : length of the key to generate
/// - `info`    : some optional additional information to use in the hash
pub fn hkdf_256(master: &[u8], key_len: usize, info: &[u8]) -> Result<Vec<u8>, CryptoBaseError> {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = vec![0_u8; key_len];
    h.expand(info, &mut out)
        .map_err(CryptoBaseError::KdfError)?;
    Ok(out)
}

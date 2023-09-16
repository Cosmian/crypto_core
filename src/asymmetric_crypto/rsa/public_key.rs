use crate::{key_wrap, Aes128Gcm, Aes256Gcm, CryptoCoreError, RandomFixedSizeCBytes, SymmetricKey};
use crate::{KeyWrappingAlgorithm, PublicKey};
use rand_chacha::rand_core::CryptoRngCore;
use zeroize::Zeroizing;

pub struct RsaPublicKey(pub(super) rsa::RsaPublicKey);

impl RsaPublicKey {
    /// Wrap a key using PKCS #1 v1.5 RS (also denoted CKM_RSA_PKCS)
    pub fn wrap_key<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        wrapping_algorithm: KeyWrappingAlgorithm,
        key_material: &Zeroizing<Vec<u8>>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        Ok(match wrapping_algorithm {
            KeyWrappingAlgorithm::Pkcs1v1_5 => self
                .0
                .encrypt(&mut *rng, rsa::Pkcs1v15Encrypt, key_material)?
                .to_vec(),
            KeyWrappingAlgorithm::Oaep => {
                let padding = rsa::Oaep::new::<sha2::Sha256>();
                self.0.encrypt(&mut *rng, padding, key_material)?.to_vec()
            }
            KeyWrappingAlgorithm::Aes128KeyWrap => {
                ckm_rsa_aes_key_wrap::<{ Aes128Gcm::KEY_LENGTH }, R>(rng, self, key_material)?
            }
            KeyWrappingAlgorithm::Aes256KeyWrap => {
                ckm_rsa_aes_key_wrap::<{ Aes256Gcm::KEY_LENGTH }, R>(rng, self, key_material)?
            }
        })
    }
}

impl PublicKey for RsaPublicKey {}

impl From<rsa::RsaPublicKey> for RsaPublicKey {
    fn from(key: rsa::RsaPublicKey) -> Self {
        Self(key)
    }
}

/// Implementation of PKCS#11 RSA AES KEY WRAP (CKM_RSA_AES_KEY_WRAP)
/// [https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061152]
fn ckm_rsa_aes_key_wrap<const AES_KEY_LENGTH: usize, R: CryptoRngCore>(
    rng: &mut R,
    rsa_public_key: &RsaPublicKey,
    key_material: &Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, CryptoCoreError> {
    // Generates a temporary random AES key of ulAESKeyBits length.  This key is not accessible to the user - no handle is returned.
    let key_encryption_key = SymmetricKey::<AES_KEY_LENGTH>::new(rng);
    // Wraps the target key with the temporary AES key using CKM_AES_KEY_WRAP_KWP ([AES KEYWRAP] section 6.3).
    // PKCS#11 CKM_AES_KEY_WRAP_KWP is identical to tRFC 5649
    let mut ciphertext = key_wrap(key_material, &key_encryption_key)?;
    //Wraps the AES key with the wrapping RSA key using CKM_RSA_PKCS_OAEP with parameters of OAEPParams.
    // Zeroizes the temporary AES key (automatically done by the conversion into())
    let mut wrapped_kwk = rsa_public_key.wrap_key(
        rng,
        KeyWrappingAlgorithm::Oaep,
        &(key_encryption_key.into()),
    )?;
    // Concatenates two wrapped keys and outputs the concatenated blob.
    // The first is the wrapped AES key, and the second is the wrapped target key.
    wrapped_kwk.append(&mut ciphertext);
    Ok(wrapped_kwk)
}

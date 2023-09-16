use crate::{key_wrap, CryptoCoreError, RandomFixedSizeCBytes, SymmetricKey};
use crate::{PublicKey, RsaKeyWrappingAlgorithm};
use digest::{Digest, DynDigest};
use rand_chacha::rand_core::CryptoRngCore;
use zeroize::Zeroizing;

pub struct RsaPublicKey(pub(super) rsa::RsaPublicKey);

impl RsaPublicKey {
    /// Wrap a key using PKCS #1 v1.5 RS (also denoted CKM_RSA_PKCS)
    pub fn wrap_key<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        wrapping_algorithm: RsaKeyWrappingAlgorithm,
        key_material: &Zeroizing<Vec<u8>>,
    ) -> Result<Vec<u8>, CryptoCoreError> {
        Ok(match wrapping_algorithm {
            RsaKeyWrappingAlgorithm::Pkcs1v1_5 => {
                self.0
                    .encrypt(&mut *rng, rsa::Pkcs1v15Encrypt, key_material)?
            }
            RsaKeyWrappingAlgorithm::OaepSha256 => {
                ckm_rsa_pkcs_oaep::<sha2::Sha256, R>(rng, self, key_material)?
            }
            RsaKeyWrappingAlgorithm::OaepSha1 => {
                ckm_rsa_pkcs_oaep::<sha1::Sha1, R>(rng, self, key_material)?
            }
            RsaKeyWrappingAlgorithm::OaepSha3 => {
                ckm_rsa_pkcs_oaep::<sha3::Sha3_256, R>(rng, self, key_material)?
            }
            RsaKeyWrappingAlgorithm::Aes256Sha256 => {
                ckm_rsa_aes_key_wrap::<sha2::Sha256, 128, R>(rng, self, key_material)?
            }
            RsaKeyWrappingAlgorithm::Aes256Sha1 => {
                ckm_rsa_aes_key_wrap::<sha1::Sha1, 256, R>(rng, self, key_material)?
            }
            RsaKeyWrappingAlgorithm::Aes256Sha3 => {
                ckm_rsa_aes_key_wrap::<sha3::Sha3_256, 256, R>(rng, self, key_material)?
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

/// Implementation of PKCS#1 RSA OAEP (CKM_RSA_PKCS_OAEP)
/// [https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061137]
fn ckm_rsa_pkcs_oaep<H: 'static + Digest + DynDigest + Send + Sync, R: CryptoRngCore>(
    rng: &mut R,
    rsa_public_key: &RsaPublicKey,
    key_material: &Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, CryptoCoreError> {
    let padding = rsa::Oaep::new::<H>();
    Ok(rsa_public_key.0.encrypt(&mut *rng, padding, key_material)?)
}

/// Implementation of PKCS#11 RSA AES KEY WRAP (CKM_RSA_AES_KEY_WRAP)
/// [https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061152]
fn ckm_rsa_aes_key_wrap<
    H: 'static + Digest + DynDigest + Send + Sync,
    const AES_KEY_LENGTH: usize,
    R: CryptoRngCore,
>(
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
    let mut wrapped_kwk =
        ckm_rsa_pkcs_oaep::<H, R>(rng, rsa_public_key, &key_encryption_key.into())?;
    // Concatenates two wrapped keys and outputs the concatenated blob.
    // The first is the wrapped AES key, and the second is the wrapped target key.
    wrapped_kwk.append(&mut ciphertext);
    Ok(wrapped_kwk)
}

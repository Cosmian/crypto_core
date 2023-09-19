use digest::{Digest, DynDigest};
use rand_chacha::rand_core::CryptoRngCore;
use rsa::traits::PublicKeyParts;
use zeroize::Zeroizing;

use crate::{
    key_wrap, CryptoCoreError, PublicKey, RandomFixedSizeCBytes, RsaKeyLength,
    RsaKeyWrappingAlgorithm, SymmetricKey,
};

#[derive(Debug, PartialEq)]
pub struct RsaPublicKey(pub(super) rsa::RsaPublicKey);

impl RsaPublicKey {
    /// Get the key length which is the modulus size in bits
    pub fn key_length(&self) -> RsaKeyLength {
        match self.0.n().bits() {
            2048 => RsaKeyLength::Modulus2048,
            3072 => RsaKeyLength::Modulus3072,
            4096 => RsaKeyLength::Modulus4096,
            _ => panic!("Invalid RSA key length; this should never happen"),
        }
    }

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
                ckm_rsa_aes_key_wrap::<sha2::Sha256, { 128 / 8 }, R>(rng, self, key_material)?
            }
            RsaKeyWrappingAlgorithm::Aes256Sha1 => {
                ckm_rsa_aes_key_wrap::<sha1::Sha1, { 256 / 8 }, R>(rng, self, key_material)?
            }
            RsaKeyWrappingAlgorithm::Aes256Sha3 => {
                ckm_rsa_aes_key_wrap::<sha3::Sha3_256, { 256 / 8 }, R>(rng, self, key_material)?
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
///
/// The AES_KEY_LENGTH is the length of the AES key in bytes.
fn ckm_rsa_aes_key_wrap<
    H: 'static + Digest + DynDigest + Send + Sync,
    const AES_KEY_LENGTH: usize,
    R: CryptoRngCore,
>(
    rng: &mut R,
    rsa_public_key: &RsaPublicKey,
    key_material: &Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, CryptoCoreError> {
    // Generates a temporary random AES key of ulAESKeyBits length.  This key is not
    // accessible to the user - no handle is returned.
    let key_encryption_key = SymmetricKey::<AES_KEY_LENGTH>::new(rng);
    // Wraps the target key with the temporary AES key using CKM_AES_KEY_WRAP_KWP
    // ([AES KEYWRAP] section 6.3). PKCS#11 CKM_AES_KEY_WRAP_KWP is identical to
    // tRFC 5649
    let mut ciphertext = key_wrap(key_material, &key_encryption_key)?;
    //Wraps the AES key with the wrapping RSA key using CKM_RSA_PKCS_OAEP with
    // parameters of OAEPParams. Zeroizes the temporary AES key (automatically
    // done by the conversion into())
    let mut wrapped_kwk =
        ckm_rsa_pkcs_oaep::<H, R>(rng, rsa_public_key, &key_encryption_key.into())?;
    // Concatenates two wrapped keys and outputs the concatenated blob.
    // The first is the wrapped AES key, and the second is the wrapped target key.
    wrapped_kwk.append(&mut ciphertext);
    Ok(wrapped_kwk)
}

impl pkcs8::EncodePublicKey for RsaPublicKey {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<pkcs8::Document> {
        self.0.to_public_key_der()
    }
}

impl pkcs8::DecodePublicKey for RsaPublicKey {
    fn from_public_key_der(bytes: &[u8]) -> pkcs8::spki::Result<Self> {
        Ok(Self(rsa::RsaPublicKey::from_public_key_der(bytes)?))
    }
}

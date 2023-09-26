use digest::{Digest, DynDigest};
use pkcs8::SecretDocument;
use rand_chacha::rand_core::CryptoRngCore;
use rand_core::RngCore;
use rsa::traits::PublicKeyParts;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    asymmetric_crypto::{PrivateKey, RsaKeyLength, RsaKeyWrappingAlgorithm, RsaPublicKey},
    key_unwrap, pkcs8_fix, CryptoCoreError,
};

#[derive(Hash, Clone, Debug, PartialEq, Eq)]
pub struct RsaPrivateKey(rsa::RsaPrivateKey);

impl RsaPrivateKey {
    /// Generate a random private key
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        key_length: RsaKeyLength,
    ) -> Result<Self, CryptoCoreError> {
        Ok(Self(rsa::RsaPrivateKey::new(
            rng,
            (key_length as i32) as usize,
        )?))
    }

    /// Get the key length which is the modulus size in bits
    #[must_use]
    pub fn key_length(&self) -> RsaKeyLength {
        match self.0.n().bits() {
            2048 => RsaKeyLength::Modulus2048,
            3072 => RsaKeyLength::Modulus3072,
            4096 => RsaKeyLength::Modulus4096,
            _ => panic!("Invalid RSA key length; this should never happen"),
        }
    }
}

/// Key wrapping support
impl RsaPrivateKey {
    /// Unwrap a key
    pub fn unwrap_key(
        &self,
        wrapping_algorithm: RsaKeyWrappingAlgorithm,
        encrypted_key_material: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoCoreError> {
        Ok(match wrapping_algorithm {
            RsaKeyWrappingAlgorithm::Pkcs1v1_5 => Zeroizing::from(
                self.0
                    .decrypt(rsa::Pkcs1v15Encrypt, encrypted_key_material)?,
            ),
            RsaKeyWrappingAlgorithm::OaepSha256 => {
                ckm_rsa_pkcs_oaep::<sha2::Sha256>(self, encrypted_key_material)?
            }
            RsaKeyWrappingAlgorithm::OaepSha1 => {
                ckm_rsa_pkcs_oaep::<sha1::Sha1>(self, encrypted_key_material)?
            }
            RsaKeyWrappingAlgorithm::OaepSha3 => {
                ckm_rsa_pkcs_oaep::<sha3::Sha3_256>(self, encrypted_key_material)?
            }
            RsaKeyWrappingAlgorithm::Aes256Sha256 => {
                ckm_rsa_aes_key_unwrap::<sha2::Sha256>(self, encrypted_key_material)?
            }
            RsaKeyWrappingAlgorithm::Aes256Sha1 => {
                ckm_rsa_aes_key_unwrap::<sha1::Sha1>(self, encrypted_key_material)?
            }
            RsaKeyWrappingAlgorithm::Aes256Sha3 => {
                ckm_rsa_aes_key_unwrap::<sha3::Sha3_256>(self, encrypted_key_material)?
            }
        })
    }
}

impl PrivateKey for RsaPrivateKey {
    type PublicKey = RsaPublicKey;

    fn public_key(&self) -> Self::PublicKey {
        self.0.to_public_key().into()
    }
}

/// Facades
impl RsaPrivateKey {
    /// Get the public key
    ///
    /// This is a facade for [`PrivateKey::public_key`]
    #[must_use]
    pub fn public_key(&self) -> <RsaPrivateKey as crate::asymmetric_crypto::PrivateKey>::PublicKey {
        PrivateKey::public_key(self)
    }
}

impl ZeroizeOnDrop for RsaPrivateKey {}

/// Implementation of PKCS#1 RSA OAEP (`CKM_RSA_PKCS_OAEP`)
/// [https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061137]
fn ckm_rsa_pkcs_oaep<H: 'static + Digest + DynDigest + Send + Sync>(
    rsa_private_key: &RsaPrivateKey,
    encrypted_key_material: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoCoreError> {
    let padding = rsa::Oaep::new::<H>();
    Ok(Zeroizing::from(
        rsa_private_key.0.decrypt(padding, encrypted_key_material)?,
    ))
}

/// Implementation of PKCS#11 RSA AES KEY WRAP (`CKM_RSA_AES_KEY_WRAP`)
/// [https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061152]
///
/// Also check [https://cloud.google.com/kms/docs/key-wrapping?hl=fr]
fn ckm_rsa_aes_key_unwrap<H: 'static + Digest + DynDigest + Send + Sync>(
    rsa_private_key: &RsaPrivateKey,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoCoreError> {
    // Splits the input into two parts. The first is the wrapped AES key, and the
    // second is the wrapped target key. The length of the first part is equal to
    // the length of the unwrapping RSA key.
    let encapsulation_bytes_len = ((rsa_private_key.key_length() as i32) / 8) as usize;
    // Un-wraps the temporary AES key from the first part with the private RSA key
    // using CKM_RSA_PKCS_OAEP with parameters of OAEPParams.
    let aes_key = ckm_rsa_pkcs_oaep::<H>(
        rsa_private_key,
        ciphertext[0..encapsulation_bytes_len].as_ref(),
    )?;
    // Un-wraps the target key from the second part with the temporary AES key using
    // CKM_AES_KEY_WRAP_KWP ([AES KEYWRAP] section 6.3). Zeroizes the temporary
    // AES key. Returns the handle to the newly unwrapped target key.
    Ok(Zeroizing::from(key_unwrap(
        &ciphertext[encapsulation_bytes_len..],
        &aes_key,
    )?))
}

impl pkcs8::EncodePrivateKey for RsaPrivateKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        self.0.to_pkcs8_der()
    }

    fn to_pkcs8_encrypted_der(
        &self,
        rng: impl rand_core::CryptoRng + RngCore,
        password: impl AsRef<[u8]>,
    ) -> pkcs8::Result<SecretDocument> {
        pkcs8_fix::to_pkcs8_encrypted_der(&self.to_pkcs8_der()?, rng, password)
    }
}

impl pkcs8::DecodePrivateKey for RsaPrivateKey {
    fn from_pkcs8_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        Ok(Self(rsa::RsaPrivateKey::from_pkcs8_der(bytes)?))
    }
}

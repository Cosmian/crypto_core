use crate::{
    Aes128Gcm, Aes256Gcm, CryptoCoreError, KeyLength, KeyWrappingAlgorithm, PrivateKey,
    RsaPublicKey, SymmetricKey,
};
use rand_chacha::rand_core::CryptoRngCore;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Hash, Clone, Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct RsaPrivateKey(rsa::RsaPrivateKey);

impl RsaPrivateKey {
    /// Generate a random private key
    pub fn new<R: CryptoRngCore>(
        rng: &mut R,
        key_length: KeyLength,
    ) -> Result<Self, CryptoCoreError> {
        Ok(Self(rsa::RsaPrivateKey::new(
            rng,
            (key_length as i32) as usize,
        )?))
    }

    /// Unwrap a key
    pub fn unwrap_key(
        &self,
        wrapping_algorithm: KeyWrappingAlgorithm,
        encrypted_key_material: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoCoreError> {
        Ok(match wrapping_algorithm {
            KeyWrappingAlgorithm::Pkcs1v1_5 => Zeroizing::from(
                self.0
                    .decrypt(rsa::Pkcs1v15Encrypt, encrypted_key_material)?,
            ),
            KeyWrappingAlgorithm::Oaep => {
                let padding = rsa::Oaep::new::<sha2::Sha256>();
                Zeroizing::from(self.0.decrypt(padding, encrypted_key_material)?)
            }
            KeyWrappingAlgorithm::Aes128KeyWrap => {
                ckm_rsa_aes_key_unwrap::<128>(self, encrypted_key_material)?
            }
            KeyWrappingAlgorithm::Aes256KeyWrap => {
                ckm_rsa_aes_key_unwrap::<256>(self, encrypted_key_material)?
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

impl From<rsa::RsaPrivateKey> for RsaPrivateKey {
    fn from(key: rsa::RsaPrivateKey) -> Self {
        Self(key)
    }
}

/// Implementation of PKCS#11 RSA AES KEY WRAP (CKM_RSA_AES_KEY_WRAP)
/// [https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061152]
fn ckm_rsa_aes_key_unwrap<const AES_KEY_LENGTH: usize>(
    rsa_private_key: &RsaPrivateKey,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoCoreError> {
    // Splits the input into two parts. The first is the wrapped AES key, and the second is the wrapped target key. The length of the first part is equal to the length of the unwrapping RSA key.
    // Un-wraps the temporary AES key from the first part with the private RSA key using CKM_RSA_PKCS_OAEP with parameters of OAEPParams.
    // Un-wraps the target key from the second part with the temporary AES key using CKM_AES_KEY_WRAP_KWP ([AES KEYWRAP] section 6.3).
    // Zeroizes the temporary AES key.
    // Returns the handle to the newly unwrapped target key.

    todo!()
    // // Generates a temporary random AES key of ulAESKeyBits length.  This key is not accessible to the user - no handle is returned.
    // let key_encryption_key = SymmetricKey::<AES_KEY_LENGTH>::new(rng);
    // // Wraps the target key with the temporary AES key using CKM_AES_KEY_WRAP_KWP ([AES KEYWRAP] section 6.3).
    // // PKCS#11 CKM_AES_KEY_WRAP_KWP is identical to tRFC 5649
    // let mut ciphertext = key_wrap(key_material, &key_encryption_key)?;
    // //Wraps the AES key with the wrapping RSA key using CKM_RSA_PKCS_OAEP with parameters of OAEPParams.
    // // Zeroizes the temporary AES key (automatically done by the conversion into())
    // let mut wrapped_kwk = rsa_public_key.wrap_key(
    //     rng,
    //     KeyWrappingAlgorithm::Oaep,
    //     &(key_encryption_key.into()),
    // )?;
    // // Concatenates two wrapped keys and outputs the concatenated blob.
    // // The first is the wrapped AES key, and the second is the wrapped target key.
    // wrapped_kwk.append(&mut ciphertext);
    // Ok(wrapped_kwk)
}

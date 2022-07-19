use super::{AsymmetricCrypto, KeyPair};
use crate::{
    entropy::CsRng,
    kdf::hkdf_256,
    symmetric_crypto::{
        aes_256_gcm_pure::{self, Aes256GcmCrypto},
        nonce::NonceTrait,
        SymmetricCrypto,
    },
    CryptoBaseError, KeyTrait,
};
use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    ops::{Add, DerefMut, Mul, Sub},
    sync::Mutex,
};
use zeroize::Zeroize;

const HKDF_INFO: &[u8; 21] = b"ecies-ristretto-25519";

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "Vec<u8>")]
pub struct X25519PrivateKey(Scalar);

impl X25519PrivateKey {
    #[must_use]
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }

    #[must_use]
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }
}

impl KeyTrait for X25519PrivateKey {
    const LENGTH: usize = 32;

    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoBaseError> {
        Self::try_from(bytes)
    }
}

impl TryFrom<Vec<u8>> for X25519PrivateKey {
    type Error = CryptoBaseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519PrivateKey {
    type Error = CryptoBaseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let len = bytes.len();
        let bytes: [u8; <Self>::LENGTH] = bytes.try_into().map_err(|_| Self::Error::SizeError {
            given: len,
            expected: <Self>::LENGTH,
        })?;
        let scalar = Scalar::from_canonical_bytes(bytes).ok_or_else(|| {
            Self::Error::ConversionError(
                "Given bytes do not represent a cannonical Scalar!".to_string(),
            )
        })?;
        Ok(Self(scalar))
    }
}

impl From<X25519PrivateKey> for Vec<u8> {
    fn from(key: X25519PrivateKey) -> Self {
        key.to_bytes()
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PrivateKey {
    type Error = CryptoBaseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Self::try_from(bytes)
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn mul(self, rhs: &'a X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 * rhs.0)
    }
}

impl<'a, 'b> Mul<&'b X25519PrivateKey> for &'a X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn mul(self, rhs: &'b X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 * rhs.0)
    }
}

impl Add for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PrivateKey> for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: &'a X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<X25519PrivateKey> for &'a X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl<'a, 'b> Add<&'b X25519PrivateKey> for &'a X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn add(self, rhs: &'b X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 + rhs.0)
    }
}

impl Sub for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Sub<&'a X25519PrivateKey> for X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: &'a X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Sub<X25519PrivateKey> for &'a X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl<'a, 'b> Sub<&'b X25519PrivateKey> for &'a X25519PrivateKey {
    type Output = X25519PrivateKey;

    fn sub(self, rhs: &'b X25519PrivateKey) -> Self::Output {
        X25519PrivateKey(self.0 - rhs.0)
    }
}

impl Zeroize for X25519PrivateKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(try_from = "&[u8]", into = "Vec<u8>")]
pub struct X25519PublicKey(RistrettoPoint);

impl X25519PublicKey {
    //compressed
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self::from(&X25519PrivateKey::new(rng))
    }
}

impl KeyTrait for X25519PublicKey {
    const LENGTH: usize = 32;

    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        self.0.compress().as_bytes().to_vec()
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoBaseError> {
        Self::try_from(bytes)
    }
}

impl From<&X25519PrivateKey> for X25519PublicKey {
    fn from(private_key: &X25519PrivateKey) -> Self {
        Self(&private_key.0 * &constants::RISTRETTO_BASEPOINT_TABLE)
    }
}

impl TryFrom<Vec<u8>> for X25519PublicKey {
    type Error = CryptoBaseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519PublicKey {
    type Error = CryptoBaseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let len = value.len();
        if len != <Self>::LENGTH {
            return Err(Self::Error::SizeError {
                given: len,
                expected: <Self>::LENGTH,
            });
        };
        let compressed = CompressedRistretto::from_slice(value);
        let point = compressed.decompress().ok_or_else(|| {
            Self::Error::ConversionError(
                "Cannot decompress given bytes into a valid curve point!".to_string(),
            )
        })?;
        Ok(Self(point))
    }
}

impl From<X25519PublicKey> for Vec<u8> {
    fn from(key: X25519PublicKey) -> Self {
        key.to_bytes()
    }
}

/// Parse from an hex encoded String
impl TryFrom<&str> for X25519PublicKey {
    type Error = CryptoBaseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Self::try_from(bytes.as_slice())
    }
}

/// Display the hex encoded value of the key
impl Display for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.compress().to_bytes()))
    }
}

impl Add for X25519PublicKey {
    type Output = Self;

    fn add(self, rhs: X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a X25519PublicKey> for X25519PublicKey {
    type Output = X25519PublicKey;

    fn add(self, rhs: &'a X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a, 'b> Add<&'a X25519PublicKey> for &'b X25519PublicKey {
    type Output = X25519PublicKey;

    fn add(self, rhs: &'a X25519PublicKey) -> Self::Output {
        X25519PublicKey(self.0 + rhs.0)
    }
}

impl<'a, 'b> Mul<&'a X25519PrivateKey> for &'b X25519PublicKey {
    type Output = X25519PublicKey;

    fn mul(self, rhs: &'a X25519PrivateKey) -> Self::Output {
        X25519PublicKey(self.0 * rhs.0)
    }
}

impl<'a> Mul<&'a X25519PrivateKey> for X25519PublicKey {
    type Output = Self;

    fn mul(self, rhs: &'a X25519PrivateKey) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct X25519KeyPair {
    private_key: X25519PrivateKey,
    public_key: X25519PublicKey,
}

impl X25519KeyPair {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let private_key = X25519PrivateKey::new(rng);
        let public_key = X25519PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

impl KeyPair for X25519KeyPair {
    type PrivateKey = X25519PrivateKey;
    type PublicKey = X25519PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn private_key(&self) -> &Self::PrivateKey {
        &self.private_key
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for X25519KeyPair {
    fn into(self) -> Vec<u8> {
        let mut bytes = self.private_key().to_bytes();
        bytes.append(&mut self.public_key().to_bytes());
        bytes
    }
}

impl TryFrom<Vec<u8>> for X25519KeyPair {
    type Error = CryptoBaseError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for X25519KeyPair {
    type Error = CryptoBaseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let len = <Self as KeyPair>::PrivateKey::LENGTH + <Self as KeyPair>::PublicKey::LENGTH;
        if len != bytes.len() {
            return Err(Self::Error::SizeError {
                given: bytes.len(),
                expected: len,
            });
        }
        let private_key = <Self as KeyPair>::PrivateKey::try_from(
            &bytes[..<Self as KeyPair>::PrivateKey::LENGTH],
        )?;
        let public_key = <Self as KeyPair>::PublicKey::try_from(
            &bytes[<Self as KeyPair>::PrivateKey::LENGTH..],
        )?;
        Ok(Self {
            private_key,
            public_key,
        })
    }
}

impl Display for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.private_key(), self.public_key())
    }
}

pub struct X25519Crypto {
    pub(crate) rng: Mutex<CsRng>,
}

impl Default for X25519Crypto {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for X25519Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.description())
    }
}

impl PartialEq for X25519Crypto {
    fn eq(&self, other: &Self) -> bool {
        self.description() == other.description()
    }
}

impl X25519Crypto {
    /// For ECIES, cipher text needs to store:
    //
    // - the public key of the ephemeral keypair
    // - the AES nonce/iv
    // - the AES MAC
    pub const ENCRYPTION_OVERHEAD: usize =
        <X25519PublicKey>::LENGTH + aes_256_gcm_pure::NONCE_LENGTH + aes_256_gcm_pure::MAC_LENGTH;

    /// Generate a 256 bit symmetric key used with ECIES encryption
    pub fn sym_key_from_public_key(
        ephemeral_keypair: &X25519KeyPair, // (y, gʸ)
        public_key: &X25519PublicKey,      // gˣ
    ) -> Result<[u8; 32], CryptoBaseError> {
        //calculate the shared point: (gˣ)ʸ
        let point = public_key.0 * ephemeral_keypair.private_key.0;
        // create a 64 bytes master key using gʸ and the shared point
        let mut master = [0_u8; 2 * <X25519PublicKey>::LENGTH];
        master[..<X25519PublicKey>::LENGTH]
            .clone_from_slice(&ephemeral_keypair.public_key.to_bytes());
        master[<X25519PublicKey>::LENGTH..].clone_from_slice(&point.compress().to_bytes());
        //Derive a 256 bit key using HKDF
        Ok(hkdf_256(&master, 32, HKDF_INFO)?
            .try_into()
            .expect("Size should be okay"))
    }

    /// Generate a 256 bit symmetric key used with ECIES decryption
    pub fn sym_key_from_private_key(
        ephemeral_public_key: &X25519PublicKey, // gʸ
        private_key: &X25519PrivateKey,         // x
    ) -> Result<[u8; 32], CryptoBaseError> {
        //calculate the shared point: (gʸ)ˣ
        let point = private_key.0 * ephemeral_public_key.0;
        // create a 64 bytes master key using gʸ and the shared point
        let mut master = [0_u8; 2 * <X25519PublicKey>::LENGTH];
        master[..<X25519PublicKey>::LENGTH].clone_from_slice(&ephemeral_public_key.to_bytes());
        master[<X25519PublicKey>::LENGTH..].clone_from_slice(point.compress().as_bytes());
        //Derive a 256 bit key using HKDF
        Ok(hkdf_256(&master, 32, HKDF_INFO)?
            .try_into()
            .expect("Size should be okay"))
    }
}

impl AsymmetricCrypto for X25519Crypto {
    type EncryptionParameters = ();
    type KeyPair = X25519KeyPair;
    type KeyPairGenerationParameters = ();
    type PrivateKeyGenerationParameters = ();

    /// Instantiate the Ristretto X25519 Curve
    #[must_use]
    fn new() -> Self {
        Self {
            rng: Mutex::new(CsRng::new()),
        }
    }

    /// The plain English description of the scheme
    fn description(&self) -> String {
        "Ristretto X25519".to_string()
    }

    /// Generate a private key
    fn generate_private_key(
        &self,
        _: Option<&Self::PrivateKeyGenerationParameters>,
    ) -> Result<<Self::KeyPair as KeyPair>::PrivateKey, CryptoBaseError> {
        Ok(X25519PrivateKey::new(
            &mut self.rng.lock().expect("a lock failed").deref_mut(),
        ))
    }

    /// Generate a key pair, private key and public key
    fn generate_key_pair(
        &self,
        _: Option<&Self::KeyPairGenerationParameters>,
    ) -> Result<Self::KeyPair, CryptoBaseError> {
        Ok(X25519KeyPair::new(
            &mut self.rng.lock().expect("a lock failed").deref_mut(),
        ))
    }

    /// Generate a symmetric key, and its encryption,to be used in an hybrid
    /// encryption scheme
    fn generate_symmetric_key<S: SymmetricCrypto>(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        _: Option<&Self::EncryptionParameters>,
    ) -> Result<(S::Key, Vec<u8>), CryptoBaseError> {
        let bytes = self.generate_random_bytes(S::Key::LENGTH);
        let symmetric_key = S::Key::try_from_bytes(&bytes)?;
        let encrypted_key = self.encrypt(public_key, None, &symmetric_key.to_bytes())?;
        Ok((symmetric_key, encrypted_key))
    }

    /// Decrypt a symmetric key used in an hybrid encryption scheme
    fn decrypt_symmetric_key<S: SymmetricCrypto>(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> Result<S::Key, CryptoBaseError> {
        let decrypted = self
            .decrypt(private_key, data)
            .map_err(|err| CryptoBaseError::DecryptionError(err.to_string()))?;
        S::Key::try_from_bytes(&decrypted)
    }

    /// A utility function to generate random bytes from an uniform distribution
    /// using a cryptographically secure RNG
    fn generate_random_bytes(&self, len: usize) -> Vec<u8> {
        let rng = &mut *self.rng.lock().expect("a mutex lock failed");
        let mut bytes = vec![0_u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// The encrypted message length
    fn encrypted_message_length(&self, clear_text_message_length: usize) -> usize {
        clear_text_message_length + <Self>::ENCRYPTION_OVERHEAD
    }

    /// Encrypt a message using ECIES
    /// `<https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme>`
    fn encrypt(
        &self,
        public_key: &<Self::KeyPair as KeyPair>::PublicKey,
        _: Option<&Self::EncryptionParameters>,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        let ephemeral_keypair =
            X25519KeyPair::new(&mut self.rng.lock().expect("a lock failed").deref_mut());
        let sym_key_bytes = Self::sym_key_from_public_key(&ephemeral_keypair, public_key)?;
        // use the pure rust aes implementation
        let sym_key = aes_256_gcm_pure::Key::from(sym_key_bytes);
        let nonce =
            aes_256_gcm_pure::Nonce::new(&mut self.rng.lock().expect("a lock failed").deref_mut());
        //prepare the result
        let mut result: Vec<u8> = Vec::with_capacity(data.len() + <Self>::ENCRYPTION_OVERHEAD);
        result.extend(ephemeral_keypair.public_key.to_bytes());
        result.extend_from_slice(&nonce.0);
        result.extend(Aes256GcmCrypto::encrypt(&sym_key, data, &nonce, None)?);
        Ok(result)
    }

    /// The decrypted message length
    fn clear_text_message_length(encrypted_message_length: usize) -> usize {
        if encrypted_message_length <= <Self>::ENCRYPTION_OVERHEAD {
            0
        } else {
            encrypted_message_length - <Self>::ENCRYPTION_OVERHEAD
        }
    }

    /// Decrypt a message using ECIES
    /// `<https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme>`
    fn decrypt(
        &self,
        private_key: &<Self::KeyPair as KeyPair>::PrivateKey,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoBaseError> {
        if data.len() < <Self>::ENCRYPTION_OVERHEAD {
            return Err(CryptoBaseError::InvalidSize(
                "decryption failed: message is too short".to_string(),
            ));
        }
        if data.len() == <Self>::ENCRYPTION_OVERHEAD {
            return Ok(vec![]);
        }
        // gʸ
        let ephemeral_public_key_bytes = &data[0..<X25519PublicKey>::LENGTH];
        let ephemeral_public_key = X25519PublicKey::try_from(ephemeral_public_key_bytes)?;
        let sym_key_bytes = Self::sym_key_from_private_key(&ephemeral_public_key, private_key)?;
        // use the pure rust aes implementation
        let sym_key = aes_256_gcm_pure::Key::from(sym_key_bytes);
        let nonce_bytes = &data
            [<X25519PublicKey>::LENGTH..<X25519PublicKey>::LENGTH + aes_256_gcm_pure::NONCE_LENGTH];
        let nonce = aes_256_gcm_pure::Nonce::try_from_bytes(nonce_bytes)?;
        Aes256GcmCrypto::decrypt(
            &sym_key,
            &data[<X25519PublicKey>::LENGTH + aes_256_gcm_pure::NONCE_LENGTH..],
            &nonce,
            None,
        )
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use super::{AsymmetricCrypto, KeyPair, X25519Crypto, X25519PrivateKey, X25519PublicKey};
    use crate::{symmetric_crypto::aes_256_gcm_pure, KeyTrait};

    #[test]
    fn test_generate_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair_1 = crypto.generate_key_pair(None).unwrap();
        assert_ne!(
            &[0_u8; X25519PrivateKey::LENGTH],
            key_pair_1.private_key.0.as_bytes()
        );
        assert_ne!(
            vec![0_u8; X25519PublicKey::LENGTH],
            key_pair_1.public_key.to_bytes()
        );
        assert_eq!(
            X25519PrivateKey::LENGTH,
            key_pair_1.private_key.0.as_bytes().len()
        );
        assert_eq!(
            X25519PublicKey::LENGTH,
            key_pair_1.public_key.to_bytes().len()
        );
        let key_pair_2 = crypto.generate_key_pair(None).unwrap();
        assert_ne!(key_pair_2.private_key, key_pair_1.private_key);
        assert_ne!(key_pair_2.public_key, key_pair_1.public_key);
    }

    #[test]
    fn test_parse_key_pair() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.generate_key_pair(None).unwrap();
        let hex = format!("{}", key_pair);
        let recovered =
            super::X25519KeyPair::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(key_pair, recovered);
    }

    #[test]
    fn test_parse_public_key() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.generate_key_pair(None).unwrap();
        let hex = format!("{}", key_pair.public_key());
        let recovered =
            super::X25519PublicKey::try_from(hex::decode(hex).unwrap().as_slice()).unwrap();
        assert_eq!(key_pair.public_key(), &recovered);
    }

    #[test]
    fn test_encryption_decryption() {
        let crypto = super::X25519Crypto::new();
        let random_msg = crypto.generate_random_bytes(4096);
        assert_ne!(vec![0_u8; 4096], random_msg);
        let key_pair: super::X25519KeyPair = crypto.generate_key_pair(None).unwrap();
        let enc_bytes = crypto
            .encrypt(&key_pair.public_key, None, &random_msg)
            .unwrap();
        assert_eq!(
            4096_usize + <X25519Crypto>::ENCRYPTION_OVERHEAD,
            crypto.encrypted_message_length(random_msg.len())
        );
        assert_eq!(
            4096_usize,
            super::X25519Crypto::clear_text_message_length(enc_bytes.len())
        );
        let clear_text = crypto.decrypt(&key_pair.private_key, &enc_bytes).unwrap();
        assert_eq!(random_msg, clear_text);
    }

    #[test]
    fn test_encryption_decryption_symmetric_key() {
        let crypto = super::X25519Crypto::new();
        let key_pair = crypto.generate_key_pair(None).unwrap();

        let (sym_key, enc_sym_key) = crypto
            .generate_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(
                key_pair.public_key(),
                None,
            )
            .unwrap();
        let decrypted_key = crypto.decrypt_symmetric_key::<aes_256_gcm_pure::Aes256GcmCrypto>(
            &key_pair.private_key,
            &enc_sym_key,
        );
        assert_eq!(sym_key, decrypted_key.unwrap());
    }
}

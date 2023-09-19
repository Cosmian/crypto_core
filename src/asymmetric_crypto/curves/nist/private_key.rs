use std::hash::Hash;

#[cfg(feature = "aes")]
use aead::generic_array::GenericArray;
use elliptic_curve::{
    sec1::{self},
    Curve, CurveArithmetic, SecretKey,
};
use pkcs8::{
    pkcs5::{pbes2, scrypt},
    EncodePrivateKey, EncryptedPrivateKeyInfo, SecretDocument,
};
use rand_core::{RngCore, SeedableRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "ser")]
use crate::bytes_ser_de::{Deserializer, Serializable, Serializer};
use crate::{
    pkcs8_fix, reexport::rand_core::CryptoRngCore, CBytes, CryptoCoreError, CsRng, FixedSizeCBytes,
    NistPublicKey, RandomFixedSizeCBytes, SecretCBytes,
};

/// Nist Curve private key
///
/// The `LENGTH` const generic parameter is the length of the serialized private
/// key in bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NistPrivateKey<C: Curve, const LENGTH: usize> {
    // the secret bytes of the key
    bytes: [u8; LENGTH],
    // this is just a cache of the instantiated secret key
    // to speed up curve arithmetic
    pub(super) secret_key: SecretKey<C>,
}

impl<C: Curve, const LENGTH: usize> Drop for NistPrivateKey<C, LENGTH> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<C: Curve, const LENGTH: usize> Zeroize for NistPrivateKey<C, LENGTH> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        // the SecretKey is already zeroized when dropped
    }
}

impl<C: Curve, const LENGTH: usize> ZeroizeOnDrop for NistPrivateKey<C, LENGTH> {}

impl<C: Curve, const LENGTH: usize> Hash for NistPrivateKey<C, LENGTH> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // the key is completely defined by its bytes
        self.bytes.hash(state);
    }
}

impl<C: Curve, const LENGTH: usize> CBytes for NistPrivateKey<C, LENGTH> {}

#[cfg(feature = "aes")]
impl<C: Curve, const LENGTH: usize> FixedSizeCBytes<LENGTH> for NistPrivateKey<C, LENGTH> {
    /// Serialize the `PrivateKey` as a non zero scalar
    fn to_bytes(&self) -> [u8; LENGTH] {
        self.bytes
    }

    /// Deserialize the `PrivateKey` from a non zero scalar
    fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, CryptoCoreError> {
        let ga = GenericArray::from_slice(bytes.as_slice());
        let secret_key = SecretKey::<C>::from_bytes(ga).map_err(|_| {
            CryptoCoreError::InvalidBytesLength(
                "EC Private Key".to_owned(),
                bytes.len(),
                Some(LENGTH),
            )
        })?;
        Ok(Self { bytes, secret_key })
    }
}

#[cfg(feature = "aes")]
impl<C: Curve + CurveArithmetic, const LENGTH: usize> RandomFixedSizeCBytes<LENGTH>
    for NistPrivateKey<C, LENGTH>
{
    /// Generate a random private key
    fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let key = SecretKey::<C>::random(rng);
        let mut bytes = [0_u8; LENGTH];
        bytes.copy_from_slice(&key.to_bytes());
        Self {
            bytes,
            secret_key: key,
        }
    }

    /// Get the underlying bytes slice of the private key
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "aes")]
impl<C: Curve + CurveArithmetic, const LENGTH: usize> SecretCBytes<LENGTH>
    for NistPrivateKey<C, LENGTH>
{
}

/// Facade for the `RandomFixedSizeCBytes` and `FixedSizeCBytes` traits
#[cfg(feature = "aes")]
impl<C: Curve + CurveArithmetic, const LENGTH: usize> NistPrivateKey<C, LENGTH> {
    /// Generate a random private key
    ///
    /// This is a facade to `RandomFixedSizeCBytes::new`
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        <Self as RandomFixedSizeCBytes<LENGTH>>::new(rng)
    }

    /// Get the underlying bytes slice of the private key
    ///
    /// This is a facade to `RandomFixedSizeCBytes::as_bytes`
    pub fn as_bytes(&self) -> &[u8] {
        <Self as RandomFixedSizeCBytes<LENGTH>>::as_bytes(self)
    }

    /// Serialize the `PrivateKey` as a non zero scalar
    ///
    /// This is a facade to `<Self as FixedSizeCBytes>::to_bytes`
    pub fn to_bytes(&self) -> [u8; LENGTH] {
        <Self as FixedSizeCBytes<LENGTH>>::to_bytes(self)
    }

    /// Deserialize the `PrivateKey` from a non zero scalar
    ///
    /// This is a facade to `<Self as FixedSizeCBytes<LENGTH>>::try_from_bytes`
    pub fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, CryptoCoreError> {
        <Self as FixedSizeCBytes<LENGTH>>::try_from_bytes(bytes)
    }
}

impl<C: Curve + CurveArithmetic, const LENGTH: usize> crate::PrivateKey
    for NistPrivateKey<C, LENGTH>
{
    type PublicKey = NistPublicKey<C, LENGTH>;

    fn public_key(&self) -> Self::PublicKey {
        Self::PublicKey::from(self)
    }
}

/// Key Serialization framework
#[cfg(all(feature = "ser", feature = "aes"))]
impl<C: Curve + CurveArithmetic, const LENGTH: usize> Serializable for NistPrivateKey<C, LENGTH> {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        LENGTH
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_array(self.as_bytes())
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let bytes = de.read_array::<LENGTH>()?;
        Self::try_from_bytes(bytes)
    }
}

impl<C, const LENGTH: usize> pkcs8::EncodePrivateKey for NistPrivateKey<C, LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        self.secret_key.to_pkcs8_der()
    }

    fn to_pkcs8_encrypted_der(
        &self,
        rng: impl rand_core::CryptoRng + RngCore,
        password: impl AsRef<[u8]>,
    ) -> pkcs8::Result<SecretDocument> {
        pkcs8_fix::to_pkcs8_encrypted_der(&self.to_pkcs8_der()?, rng, password)
    }
}

impl<C, const LENGTH: usize> pkcs8::DecodePrivateKey for NistPrivateKey<C, LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    fn from_pkcs8_der(bytes: &[u8]) -> pkcs8::Result<Self> {
        let key = SecretKey::<C>::from_pkcs8_der(bytes)?;
        let mut bytes = [0_u8; LENGTH];
        bytes.copy_from_slice(&key.to_bytes());
        Ok(Self {
            bytes,
            secret_key: key,
        })
    }
}

/// PKCS#8 support (deprecated)
#[deprecated = "use the methods on the `pkcs8::EncodePrivateKey` and `pkcs8::DecodePrivateKey` traits instead"]
impl<C, const LENGTH: usize> NistPrivateKey<C, LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    pub const LENGTH: usize = LENGTH;

    /// Encode the private key as a `PKCS#8 PrivateKeyInfo` ASN.1 DER
    #[deprecated = "use the methods on the `pkcs8::EncodePrivateKey` and `pkcs8::DecodePrivateKey` traits instead"]
    pub fn try_to_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>, CryptoCoreError> {
        let bytes =
            pkcs8::EncodePrivateKey::to_pkcs8_der(&self.secret_key).map(|d| d.to_bytes())?;
        Ok(bytes)
    }

    /// Encode the private key as a `PKCS#8 EncryptedPrivateKeyInfo` ASN.1 DER
    /// The encryption algorithm used is Scrypt AES-256 CBC
    #[deprecated = "use the methods on the `pkcs8::EncodePrivateKey` and `pkcs8::DecodePrivateKey` traits instead"]
    pub fn try_to_encrypted_pkcs8(
        &self,
        password: impl AsRef<[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoCoreError> {
        let mut rng = CsRng::from_entropy();

        // Due to in compatibility issues with the openssl library, we use the
        // modified parameters for Scrypt and cannot use the default implemented with

        // ```Rust
        // let bytes =
        //     pkcs8::EncodePrivateKey::to_pkcs8_encrypted_der(&self.secret_key, &mut rng, password)
        //         .map(|d| d.to_bytes())?;
        // ```

        // see this issue for more details and the PR progress that will fix it:
        // https://github.com/RustCrypto/formats/issues/1205

        let doc: SecretDocument = {
            let bytes = self.secret_key.to_pkcs8_der()?;
            let mut salt = [0u8; 16];
            rng.fill_bytes(&mut salt);

            let mut iv = [0u8; 16];
            rng.fill_bytes(&mut iv);

            // 14 = log_2(16384), 32 bytes = 256 bits
            let scrypt_params = scrypt::Params::new(14, 8, 1, 32).unwrap();
            let pbes2_params =
                pbes2::Parameters::scrypt_aes256cbc(scrypt_params, &salt, &iv).unwrap();

            let encrypted_data = pbes2_params.encrypt(password, bytes.as_bytes())?;

            EncryptedPrivateKeyInfo {
                encryption_algorithm: pbes2_params.into(),
                encrypted_data: &encrypted_data,
            }
            .try_into()?
        };

        Ok(doc.to_bytes())
    }

    /// Decode the private key from a `PKCS#8 PrivateKeyInfo` ASN.1 DER
    #[deprecated = "use the methods on the `pkcs8::EncodePrivateKey` and `pkcs8::DecodePrivateKey` traits instead"]
    pub fn try_from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        let secret_key: SecretKey<C> = pkcs8::DecodePrivateKey::from_pkcs8_der(bytes)?;
        let mut bytes = [0_u8; LENGTH];
        bytes.copy_from_slice(&secret_key.to_bytes());
        Ok(Self { bytes, secret_key })
    }

    /// Decode the private key as a `PKCS#8 EncryptedPrivateKeyInfo` ASN.1 DER
    #[deprecated = "use the methods on the `pkcs8::EncodePrivateKey` and `pkcs8::DecodePrivateKey` traits instead"]
    pub fn try_from_encrypted_pkcs8(
        bytes: &[u8],
        password: impl AsRef<[u8]>,
    ) -> Result<Self, CryptoCoreError> {
        let secret_key: SecretKey<C> =
            pkcs8::DecodePrivateKey::from_pkcs8_encrypted_der(bytes, password)?;
        let mut bytes = [0_u8; LENGTH];
        bytes.copy_from_slice(&secret_key.to_bytes());
        Ok(Self { bytes, secret_key })
    }
}

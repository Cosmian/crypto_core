use elliptic_curve::{
    group::Curve as Curve_,
    sec1::{self, ToEncodedPoint},
    Curve, CurveArithmetic, ProjectivePoint, PublicKey,
};

use super::private_key::NistPrivateKey;
#[cfg(feature = "ser")]
use crate::bytes_ser_de::{Deserializer, Serializable, Serializer};
use crate::{CBytes, CryptoCoreError, FixedSizeCBytes, NistCurvePoint};

/// Nist Curve public key
///
/// The `LENGTH` const generic parameter is the length of the serialized public
/// key in bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NistPublicKey<C: Curve + CurveArithmetic, const LENGTH: usize>(PublicKey<C>);

impl<C: Curve + CurveArithmetic, const LENGTH: usize> CBytes for NistPublicKey<C, LENGTH> {}

impl<C, const LENGTH: usize> FixedSizeCBytes<LENGTH> for NistPublicKey<C, LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    /// Serialize the underlying SEC1 Encoded Point as an array of bytes
    fn to_bytes(&self) -> [u8; LENGTH] {
        self.0.to_encoded_point(true).as_bytes().try_into().expect(
            "FATAL Error: the parameterized size of the length of serialized public keys is \
             incorrect for the given curve",
        )
    }

    /// Deserialize the array of bytes as a SEC1 Encoded Point and build a
    /// `NistPublicKey` from it
    fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, crate::CryptoCoreError> {
        let pk = PublicKey::from_sec1_bytes(&bytes)?;
        Ok(Self(pk))
    }
}

impl<C, const LENGTH: usize> NistPublicKey<C, LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    pub const LENGTH: usize = LENGTH;

    #[must_use]
    pub fn dh<const PRIVATE_KEY_LENGTH: usize>(
        &self,
        rhs: &NistPrivateKey<C, PRIVATE_KEY_LENGTH>,
    ) -> NistCurvePoint<C> {
        let public_point = ProjectivePoint::<C>::from(*self.0.as_affine());
        let shared_point = public_point * rhs.secret_key.to_nonzero_scalar().as_ref();
        NistCurvePoint(shared_point.to_affine())
    }

    /// Encode the public key as a `X.509 SubjectPublicKeyInfo` (SPKI) ASN.1 DER
    /// byte array.
    #[deprecated = "use the methods on the `Pkcs8PublicKey` trait instead"]
    pub fn try_to_pkcs8(&self) -> Result<Vec<u8>, CryptoCoreError> {
        let bytes =
            pkcs8::EncodePublicKey::to_public_key_der(&self.0).map(pkcs8::Document::into_vec)?;
        Ok(bytes)
    }

    /// Decode the public key from a `X.509 SubjectPublicKeyInfo` (SPKI) ASN.1
    /// DER byte array.
    #[deprecated = "use the methods on the `Pkcs8PublicKey` trait instead"]
    pub fn try_from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        let key = pkcs8::DecodePublicKey::from_public_key_der(bytes)?;
        Ok(Self(key))
    }
}

/// Facades
///
/// Facades are used to hide the underlying types and provide a more
/// user friendly interface to the user.
impl<C, const LENGTH: usize> NistPublicKey<C, LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    /// Serialize the underlying SEC1 Encoded Point as an array of bytes
    ///
    /// This is a facade to `<Self as FixedSizeCBytes>::to_bytes`
    #[must_use]
    pub fn to_bytes(&self) -> [u8; LENGTH] {
        <Self as FixedSizeCBytes<LENGTH>>::to_bytes(self)
    }

    /// Deserialize the array of bytes as ua SEC1 Encoded Point and build a
    /// `NistPublicKey` from it
    ///
    /// This is a facade to `<Self as FixedSizeCBytes>::try_from_bytes`
    pub fn try_from_bytes(bytes: [u8; LENGTH]) -> Result<Self, crate::CryptoCoreError> {
        <Self as FixedSizeCBytes<LENGTH>>::try_from_bytes(bytes)
    }
}

impl<C: Curve + CurveArithmetic, const LENGTH: usize> crate::PublicKey
    for NistPublicKey<C, LENGTH>
{
}

impl<
        C: Curve + CurveArithmetic,
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
    > From<&NistPrivateKey<C, PRIVATE_KEY_LENGTH>> for NistPublicKey<C, PUBLIC_KEY_LENGTH>
{
    fn from(sk: &NistPrivateKey<C, PRIVATE_KEY_LENGTH>) -> Self {
        Self(PublicKey::from_secret_scalar(
            &sk.secret_key.to_nonzero_scalar(),
        ))
    }
}

impl<C, const PUBLIC_KEY_LENGTH: usize> From<&NistCurvePoint<C>>
    for NistPublicKey<C, PUBLIC_KEY_LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    fn from(point: &NistCurvePoint<C>) -> Self {
        Self(
            PublicKey::from_affine(point.0)
                .expect("FATAL ERROR: The NIST curve point should always be on the curve"),
        )
    }
}

/// Key Serialization framework
#[cfg(feature = "ser")]
impl<C, const LENGTH: usize> Serializable for NistPublicKey<C, LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    fn length(&self) -> usize {
        LENGTH
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        self.to_bytes().write(ser)
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let bytes = <[u8; LENGTH]>::read(de)?;
        Self::try_from_bytes(bytes).map_err(D::Error::from)
    }
}

impl<C, const LENGTH: usize> pkcs8::EncodePublicKey for NistPublicKey<C, LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    fn to_public_key_der(&self) -> pkcs8::spki::Result<pkcs8::Document> {
        self.0.to_public_key_der()
    }
}

impl<C, const LENGTH: usize> pkcs8::DecodePublicKey for NistPublicKey<C, LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    fn from_public_key_der(bytes: &[u8]) -> pkcs8::spki::Result<Self> {
        Ok(Self(PublicKey::from_public_key_der(bytes)?))
    }
}

#[cfg(all(test, feature = "aes"))]
mod tests {
    use elliptic_curve::{sec1, Curve, CurveArithmetic};
    use p192::NistP192;
    use p224::NistP224;
    use p256::NistP256;
    use p384::NistP384;
    use rand_core::SeedableRng;

    use crate::{
        CsRng, NistPrivateKey, NistPublicKey, P192_PRIVATE_KEY_LENGTH, P192_PUBLIC_KEY_LENGTH,
        P224_PRIVATE_KEY_LENGTH, P224_PUBLIC_KEY_LENGTH, P256_PRIVATE_KEY_LENGTH,
        P256_PUBLIC_KEY_LENGTH, P384_PRIVATE_KEY_LENGTH, P384_PUBLIC_KEY_LENGTH,
    };

    fn serialization_deserialization_test<
        C,
        const PRIVATE_KEY_LENGTH: usize,
        const PUBLIC_KEY_LENGTH: usize,
    >()
    where
        C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
        <C as Curve>::FieldBytesSize: sec1::ModulusSize,
        <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
        <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
    {
        let mut rng = CsRng::from_entropy();

        let mut i = 0;
        loop {
            let sk = NistPrivateKey::<C, PRIVATE_KEY_LENGTH>::new(&mut rng);
            assert_eq!(sk.to_bytes().len(), PRIVATE_KEY_LENGTH);

            let pk = NistPublicKey::from(&sk);

            let bytes = pk.to_bytes();
            let pk2 = NistPublicKey::<C, PUBLIC_KEY_LENGTH>::try_from_bytes(bytes).unwrap();

            assert_eq!(pk, pk2);

            let length = pk.to_bytes().len();
            assert_eq!(length, PUBLIC_KEY_LENGTH);

            i += 1;
            if i > 100 {
                break;
            }
        }
    }

    #[test]
    fn test_serialization_deserialization() {
        serialization_deserialization_test::<
            NistP384,
            P384_PRIVATE_KEY_LENGTH,
            P384_PUBLIC_KEY_LENGTH,
        >();
        serialization_deserialization_test::<
            NistP256,
            P256_PRIVATE_KEY_LENGTH,
            P256_PUBLIC_KEY_LENGTH,
        >();
        serialization_deserialization_test::<
            NistP224,
            P224_PRIVATE_KEY_LENGTH,
            P224_PUBLIC_KEY_LENGTH,
        >();
        serialization_deserialization_test::<
            NistP192,
            P192_PRIVATE_KEY_LENGTH,
            P192_PUBLIC_KEY_LENGTH,
        >();
    }
}

use elliptic_curve::{sec1, Curve, CurveArithmetic};

use crate::{
    EciesEcPrivateKey, EciesEcPublicKey, EciesEcSharedPoint, FixedSizeCBytes, NistCurvePoint,
    NistPrivateKey, NistPublicKey, RandomFixedSizeCBytes,
};

impl<C: Curve + CurveArithmetic, const LENGTH: usize> EciesEcPrivateKey<LENGTH>
    for NistPrivateKey<C, LENGTH>
{
    fn new<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
        <Self as RandomFixedSizeCBytes<LENGTH>>::new(rng)
    }
}

impl<C> EciesEcSharedPoint for NistCurvePoint<C>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    fn to_vec(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl<C, const PRIVATE_KEY_LENGTH: usize, const PUBLIC_KEY_LENGTH: usize>
    EciesEcPublicKey<PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH> for NistPublicKey<C, PUBLIC_KEY_LENGTH>
where
    C: Curve + CurveArithmetic + pkcs8::AssociatedOid,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
    <C as CurveArithmetic>::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: sec1::FromEncodedPoint<C>,
{
    type PrivateKey = NistPrivateKey<C, PRIVATE_KEY_LENGTH>;
    type SharedPoint = NistCurvePoint<C>;

    fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        <Self as FixedSizeCBytes<PUBLIC_KEY_LENGTH>>::to_bytes(self)
    }

    fn try_from_bytes(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Result<Self, crate::CryptoCoreError> {
        <Self as FixedSizeCBytes<PUBLIC_KEY_LENGTH>>::try_from_bytes(bytes)
    }

    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        Self::from(private_key)
    }

    fn dh(&self, private_key: &Self::PrivateKey) -> Self::SharedPoint {
        self.dh(private_key)
    }
}

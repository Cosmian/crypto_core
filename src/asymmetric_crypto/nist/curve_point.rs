use elliptic_curve::{
    sec1::{self, ToEncodedPoint},
    Curve, CurveArithmetic,
};

pub struct NistCurvePoint<C>(pub(crate) C::AffinePoint)
where
    C: Curve + CurveArithmetic,
    C::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize;

impl<C> NistCurvePoint<C>
where
    C: Curve + CurveArithmetic,
    C::AffinePoint: sec1::ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: sec1::ModulusSize,
{
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }
}

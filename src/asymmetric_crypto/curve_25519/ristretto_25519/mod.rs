mod curve_point;
mod private_key;

pub use curve_point::{R25519CurvePoint, R25519_CURVE_POINT_LENGTH};
pub use private_key::{R25519PrivateKey, R25519_PRIVATE_KEY_LENGTH};

// The public key is a Curve Point
pub type R25519PublicKey = R25519CurvePoint;
/// Length of a Ristretto public key in bytes.
pub const R25519_PUBLIC_KEY_LENGTH: usize = R25519_CURVE_POINT_LENGTH;

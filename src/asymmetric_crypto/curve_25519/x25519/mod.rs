mod curve_point;
#[cfg(feature = "certificate")]
mod encoding;
mod key_pair;
mod private_key;

pub use curve_point::{X25519CurvePoint, X25519_CURVE_POINT_LENGTH};
pub use key_pair::X25519Keypair;
pub use private_key::X25519PrivateKey;

// Use a curve point representation as a Public key
pub type X25519PublicKey = X25519CurvePoint;
/// Length of a serialized X25519 public key in bytes.
pub const X25519_PUBLIC_KEY_LENGTH: usize = X25519_CURVE_POINT_LENGTH;

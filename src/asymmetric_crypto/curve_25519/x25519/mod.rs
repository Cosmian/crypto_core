mod public_key;

pub use public_key::X25519PublicKey;
pub use public_key::X25519_PUBLIC_KEY_LENGTH;

use super::private_key::Curve25519PrivateKey;

pub type X25519PrivateKey = Curve25519PrivateKey;

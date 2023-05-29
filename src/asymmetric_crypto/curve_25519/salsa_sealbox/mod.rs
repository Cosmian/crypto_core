mod ecies;
mod public_key;

pub use ecies::EciesSalsaSealBox;
pub use public_key::X25519PublicKey;

use super::private_key::Curve25519PrivateKey;

pub type X25519PrivateKey = Curve25519PrivateKey;

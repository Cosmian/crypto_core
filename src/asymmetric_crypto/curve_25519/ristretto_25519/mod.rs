mod public_key;

use super::private_key::Curve25519PrivateKey;

pub type R25519PrivateKey = Curve25519PrivateKey;
pub use public_key::R25519PublicKey;

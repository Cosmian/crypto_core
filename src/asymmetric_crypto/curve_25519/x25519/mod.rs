#[cfg(feature = "certificate")]
mod encoding;
mod key_pair;
mod private_key;
mod public_key;

pub use private_key::X25519PrivateKey;
pub use public_key::{X25519PublicKey, X25519_PUBLIC_KEY_LENGTH};

use super::private_key::Curve25519PrivateKey;

pub type X25519PrivateKey = Curve25519PrivateKey;
pub use key_pair::X25519Keypair;

pub use ed25519_dalek::{SecretKey as EdSecretKey, VerifyingKey as EdPublicKey};

use crate::Curve25519Secret;

pub type Ed25519PrivateKey = Curve25519Secret;

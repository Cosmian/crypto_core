//! Thin wrapper over the Dalek ed25519 Edward points and ed25519 signature

mod ed25519;
mod private_key;
mod public_key;

pub use private_key::Ed25519PrivateKey;
pub use public_key::Ed25519PublicKey;

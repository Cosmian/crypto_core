//! Thin wrapper over the Dalek ed25519 Edward points and ed25519 signature

#[cfg(feature = "certificate")]
mod certificate;
mod ed_dsa;
mod private_key;
mod public_key;

#[cfg(feature = "certificate")]
pub use certificate::{build_certificate, build_certificate_profile};
pub use ed_dsa::{Cached25519Signer, Ed25519Keypair, Ed25519Signature};
pub use private_key::{Ed25519PrivateKey, ED25519_PRIVATE_KEY_LENGTH};
pub use public_key::{Ed25519PublicKey, ED25519_PUBLIC_KEY_LENGTH};

#[cfg(all(feature = "chacha", feature = "blake",))]
mod ecies_salsa_sealed_box;
#[cfg(all(feature = "chacha", feature = "blake",))]
pub use ecies_salsa_sealed_box::EciesSalsaSealBox;

#[cfg(all(feature = "chacha", feature = "blake", feature = "curve25519"))]
mod ecies_x25519_xchacha20;
#[cfg(all(feature = "chacha", feature = "blake", feature = "curve25519"))]
pub use ecies_x25519_xchacha20::EciesX25519XChaCha20;

mod r25519;
mod x25519;

#[cfg(all(feature = "aes", feature = "sha3",))]
use crate::{
    EciesAes128, R25519PublicKey, X25519PublicKey, CURVE_25519_SECRET_LENGTH,
    R25519_PRIVATE_KEY_LENGTH, R25519_PUBLIC_KEY_LENGTH, X25519_PUBLIC_KEY_LENGTH,
};

#[cfg(all(feature = "aes", feature = "sha3",))]
pub type EciesR25519Aes128 =
    EciesAes128<R25519_PRIVATE_KEY_LENGTH, R25519_PUBLIC_KEY_LENGTH, R25519PublicKey>;
#[cfg(all(feature = "aes", feature = "sha3",))]
pub type EciesX25519Aes128 =
    EciesAes128<CURVE_25519_SECRET_LENGTH, X25519_PUBLIC_KEY_LENGTH, X25519PublicKey>;

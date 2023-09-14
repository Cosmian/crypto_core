mod keys;
pub use keys::*;

use crate::{
    EciesAes128, P192PublicKey, P224PublicKey, P256PublicKey, P384PublicKey,
    P192_PRIVATE_KEY_LENGTH, P192_PUBLIC_KEY_LENGTH, P224_PRIVATE_KEY_LENGTH,
    P224_PUBLIC_KEY_LENGTH, P256_PRIVATE_KEY_LENGTH, P256_PUBLIC_KEY_LENGTH,
    P384_PRIVATE_KEY_LENGTH, P384_PUBLIC_KEY_LENGTH,
};

pub type EciesP384Aes128 =
    EciesAes128<P384_PRIVATE_KEY_LENGTH, P384_PUBLIC_KEY_LENGTH, P384PublicKey>;
pub type EciesP256Aes128 =
    EciesAes128<P256_PRIVATE_KEY_LENGTH, P256_PUBLIC_KEY_LENGTH, P256PublicKey>;
pub type EciesP224Aes128 =
    EciesAes128<P224_PRIVATE_KEY_LENGTH, P224_PUBLIC_KEY_LENGTH, P224PublicKey>;
pub type EciesP192Aes128 =
    EciesAes128<P192_PRIVATE_KEY_LENGTH, P192_PUBLIC_KEY_LENGTH, P192PublicKey>;
//! NIST curves
//! This module exposes 4 common NIST curves: P192, P224, P256, P384

use p192::NistP192;
use p224::NistP224;
use p256::NistP256;
use p384::NistP384;

mod curve_point;
mod private_key;
mod public_key;

pub const P384_PRIVATE_KEY_LENGTH: usize = 48;
pub type P384PrivateKey = private_key::NistPrivateKey<NistP384, P384_PRIVATE_KEY_LENGTH>;
pub const P384_PUBLIC_KEY_LENGTH: usize = 49;
pub type P384PublicKey = public_key::NistPublicKey<NistP384, P384_PUBLIC_KEY_LENGTH>;

pub const P256_PRIVATE_KEY_LENGTH: usize = 32;
pub type P256PrivateKey = private_key::NistPrivateKey<NistP256, P256_PRIVATE_KEY_LENGTH>;
pub const P256_PUBLIC_KEY_LENGTH: usize = 33;
pub type P256PublicKey = public_key::NistPublicKey<NistP256, P256_PUBLIC_KEY_LENGTH>;

pub const P224_PRIVATE_KEY_LENGTH: usize = 28;
pub type P224PrivateKey = private_key::NistPrivateKey<NistP224, P224_PRIVATE_KEY_LENGTH>;
pub const P224_PUBLIC_KEY_LENGTH: usize = 29;
pub type P224PublicKey = public_key::NistPublicKey<NistP224, P224_PUBLIC_KEY_LENGTH>;

pub const P192_PRIVATE_KEY_LENGTH: usize = 24;
pub type P192PrivateKey = private_key::NistPrivateKey<NistP192, P192_PRIVATE_KEY_LENGTH>;
pub const P192_PUBLIC_KEY_LENGTH: usize = 25;
pub type P192PublicKey = public_key::NistPublicKey<NistP192, P192_PUBLIC_KEY_LENGTH>;

pub(crate) use curve_point::NistCurvePoint;
#[cfg(feature = "ecies")]
pub(crate) use private_key::NistPrivateKey;
#[cfg(feature = "ecies")]
pub(crate) use public_key::NistPublicKey;

#[cfg(test)]
mod test_pkcs8_openssl_compat;

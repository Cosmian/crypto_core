mod point;
mod scalar;

pub use point::P256Point;
pub use scalar::P256Scalar;

use cosmian_crypto_core::traits::CyclicGroup;
use openssl::nid::Nid;

const NID: Nid = Nid::X9_62_PRIME256V1;

#[derive(Debug, Clone, Copy, Default)]
pub struct P256;

impl CyclicGroup for P256 {
    type Element = P256Point;

    type Multiplicity = P256Scalar;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash::Sha256, kem::MonadicKEM};
    use cosmian_crypto_core::{
        traits::{
            kem_to_pke::GenericPKE,
            tests::{test_cyclic_group, test_kem, test_nike, test_pke},
        },
        Aes256Gcm,
    };

    #[test]
    fn test_p256() {
        test_cyclic_group::<P256>();
        test_nike::<P256>();
        test_kem::<32, MonadicKEM<32, P256, Sha256>>();
        test_pke::<GenericPKE<32, 12, 16, MonadicKEM<32, P256, Sha256>, Aes256Gcm>>();
    }
}

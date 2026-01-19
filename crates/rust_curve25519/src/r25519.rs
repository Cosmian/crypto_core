mod point;
mod scalar;

pub use point::R25519Point;
pub use scalar::R25519Scalar;

use cosmian_crypto_core::traits::{providers::R25519GroupProvider, CyclicGroup};

pub struct R25519;

impl CyclicGroup for R25519 {
    type Element = R25519Point;

    type Multiplicity = R25519Scalar;
}

impl R25519GroupProvider for R25519 {}

#[cfg(test)]
mod tests {
    use crate::R25519;
    use cosmian_crypto_core::{
        kdf::Kdf256,
        traits::tests::{test_cyclic_group, test_nike},
    };

    #[test]
    fn test_r25519_arithmetic() {
        test_cyclic_group::<R25519>();
    }

    #[test]
    fn test_r25519_nike() {
        test_nike::<R25519>();
    }

    #[test]
    fn test_r25519_kem() {
        use cosmian_crypto_core::traits::{cyclic_group_to_kem::GenericKem, tests::test_kem};

        const R25519_KEY_LENGTH: usize = 32;
        type R25519Kem = GenericKem<R25519_KEY_LENGTH, R25519, Kdf256>;
        test_kem::<R25519_KEY_LENGTH, R25519Kem>();
    }
}

mod curve_point;
mod private_key;

pub use curve_point::{R25519Point, R25519_POINT_LENGTH};
pub use private_key::{R25519Scalar, R25519_SCALAR_LENGTH};

use crate::traits::CyclicGroup;

pub struct R25519;

impl CyclicGroup for R25519 {
    type Element = R25519Point;

    type Multiplicity = R25519Scalar;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::tests::{test_cyclic_group, test_nike};

    #[test]
    fn test_r25519_arithmetic() {
        test_cyclic_group::<R25519>();
    }

    #[test]
    fn test_r25519_nike() {
        test_nike::<R25519>();
    }
}

#[cfg(feature = "sha3")]
pub use kem::*;

#[cfg(feature = "sha3")]
mod kem {
    use crate::{kdf::Kdf, traits::cyclic_group_to_kem::GenericKem, R25519};

    pub const R25519_KEY_LENGTH: usize = 32;
    pub type R25519Kem = GenericKem<R25519_KEY_LENGTH, R25519, Kdf>;

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::traits::tests::test_kem;

        #[test]
        fn test_r25519_kem() {
            test_kem::<R25519_KEY_LENGTH, R25519Kem>();
        }
    }
}

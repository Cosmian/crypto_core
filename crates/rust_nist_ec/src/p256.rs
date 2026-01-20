use cosmian_crypto_core::traits::CyclicGroup;

mod point;
mod scalar;

pub use point::P256Point;
pub use scalar::P256Scalar;

#[derive(Debug, Clone, Copy, Default)]
pub struct P256;

impl CyclicGroup for P256 {
    type Element = P256Point;

    type Multiplicity = P256Scalar;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256() {
        use cosmian_crypto_core::traits::tests::{test_cyclic_group, test_nike};

        test_cyclic_group::<P256>();
        test_nike::<P256>();
    }
}

use rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_hc::Hc128Rng;

/// An implementation of a cryptographically secure
/// pseudo random generator using HC128
#[derive(Debug)]
pub struct CsRng {
    rng: Hc128Rng,
}

impl CsRng {
    /// Generates a new random number generator.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: Hc128Rng::from_entropy(),
        }
    }

    /// Generates a vector of random bytes with the given length.
    #[inline]
    #[must_use]
    pub fn generate_random_bytes<const LENGTH: usize>(&mut self) -> [u8; LENGTH] {
        let mut bytes = [0; LENGTH];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }
}

impl Default for CsRng {
    #[must_use]
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for CsRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest).map_err(rand_core::Error::new)
    }
}

impl CryptoRng for CsRng {}

#[cfg(test)]
mod test {

    use crate::entropy::CsRng;

    #[test]
    fn test_random_bytes() {
        let mut cs_rng = CsRng::default();
        const N: usize = 1024;
        let random_bytes_1 = cs_rng.generate_random_bytes::<N>();
        assert_eq!(N, random_bytes_1.len());
        let random_bytes_2 = cs_rng.generate_random_bytes();
        assert_eq!(N, random_bytes_1.len());
        assert_ne!(random_bytes_1, random_bytes_2);
    }
}

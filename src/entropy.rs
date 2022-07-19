use rand::{RngCore as _, SeedableRng};
use rand_core::{CryptoRng, RngCore};
use rand_hc::Hc128Rng;

/// An implementation of a cryptographically secure
/// pseudo random generator using HC128
#[derive(Debug)]
pub struct CsRng {
    rng: Hc128Rng,
}

impl CsRng {
    /// Generate a new random number generator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rng: Hc128Rng::from_entropy(),
        }
    }

    /// Generate a vector of random bytes with the given length.
    ///
    /// - `len` : number of random bytes to generate
    pub fn generate_random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; len];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }
}

impl Default for CsRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for CsRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest).map_err(rand_core::Error::new)
    }
}

impl CryptoRng for CsRng {}

use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore, SeedableRng};
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
    pub fn generate_random_bytes<N: ArrayLength<u8>>(&mut self) -> GenericArray<u8, N> {
        let mut bytes = GenericArray::<u8, N>::default();
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

#[cfg(test)]
mod test {

    use crate::entropy::CsRng;
    use generic_array::typenum::{Unsigned, U1024};

    #[test]
    fn test_random_bytes() {
        let mut cs_rng = CsRng::default();
        type N = U1024;
        let random_bytes_1 = cs_rng.generate_random_bytes::<N>();
        assert_eq!(<N as Unsigned>::to_usize(), random_bytes_1.len());
        let random_bytes_2 = cs_rng.generate_random_bytes();
        assert_eq!(<N as Unsigned>::to_usize(), random_bytes_1.len());
        assert_ne!(random_bytes_1, random_bytes_2);
    }
}

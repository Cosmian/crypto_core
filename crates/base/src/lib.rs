//! This crate implements crypto primitives which are used in many other Cosmian
//! cryptographic crates.

mod error;
mod key;
mod secret;

pub mod bytes_ser_de;

#[macro_use]
pub mod traits;

#[cfg(feature = "macro")]
#[macro_use]
pub mod bytes;

pub mod reexport {
    pub use rand_core;
    pub use zeroize;
}

pub use error::Error;
pub use key::SymmetricKey;
pub use secret::Secret;

use rand_core::CryptoRngCore;

/// Use `ChaCha` with 12 rounds as cryptographic RNG.
pub type CsRng = rand_chacha::ChaCha12Rng;

/// Shuffles the given slice in a destructive way.
pub fn shuffle_in_place<X>(xs: &mut [X], rng: &mut impl CryptoRngCore) {
    for i in 0..xs.len() {
        let j = rng.next_u32() as usize % xs.len();
        xs.swap(i, j);
    }
}

/// Returns a vector containing a shuffled copy of the given elements.
pub fn shuffle<X: Clone>(xs: &[X], rng: &mut impl CryptoRngCore) -> Vec<X> {
    let mut res = xs.to_vec();
    shuffle_in_place(&mut res, rng);
    res
}

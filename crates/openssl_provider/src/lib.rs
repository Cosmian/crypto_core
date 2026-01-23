//! This crate implements a cryptographic provider on top of the OpenSSL
//! bindings. Those bindings do not fit well with the arithmetic traits defined
//! in CryptoCore: since all operations are performed through FFI, the all --
//! even those as simple as returning the 0 -- are fallible.
//!
//! Instead of modifying all arithmetic traits, which would imply the need to
//! unwrap upon every single arithmetic operation, this provider has been design
//! in a monadic style: elements are FFI monads that can either be a valid
//! object or in an error state (the `openssl::ErrorStack` error type) and
//! comply with arithmetic traits. The only quirk is that the caller is then
//! required to check the monad state at some point, which leaks an internal
//! detail.
//!
//! To ease its usage, a dedicated KEM is implemented which performs the check
//! of the monad state when necessary (using the `GenericKEM` from CryptoCore
//! would return a monad instead of the proper keys or encapsulation).

pub mod hash;
pub mod kem;
pub mod p256;

/// An FFI monad is either in an OK or error state.
pub trait FFIMonad: Sized {
    /// Type of the error state.
    type Error: std::error::Error;

    /// Return true if this monad is in its OK state.
    fn is_ok(&self) -> bool;

    /// Returns true if this monad is in its error state.
    fn is_err(&self) -> bool {
        !self.is_ok()
    }

    /// Return this monad unchanged if it is in its OK state, or apply the given
    /// function on its error state.
    fn manage_error<E: std::error::Error>(self, f: fn(Self::Error) -> E) -> Result<Self, E>;
}

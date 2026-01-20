#[cfg(feature = "curve25519")]
mod curve_25519;
#[cfg(feature = "curve25519")]
pub use curve_25519::*;

#[cfg(feature = "nist_curves")]
mod nist;
#[cfg(feature = "nist_curves")]
pub use nist::*;

#[cfg(test)]
mod tests {
    use openssl::error::ErrorStack;

    impl From<std::io::Error> for crate::CryptoCoreError {
        fn from(_: std::io::Error) -> Self {
            Self::EncryptionError
        }
    }

    impl From<ErrorStack> for crate::CryptoCoreError {
        fn from(_: ErrorStack) -> Self {
            Self::EncryptionError
        }
    }
}

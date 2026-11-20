use core::fmt::Display;

use openssl::error::ErrorStack;

#[derive(Debug)]
pub struct Error(ErrorStack);

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenSSL: {}", self.0)
    }
}

impl std::error::Error for Error {}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Self(e)
    }
}

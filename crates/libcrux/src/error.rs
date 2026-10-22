use core::fmt::Display;
use libcrux_traits::digest::UpdateError;

#[derive(Debug)]
pub enum Error {
    Sha3(UpdateError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha3(e) => write!(f, "SHA3 error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<UpdateError> for Error {
    fn from(e: UpdateError) -> Self {
        Self::Sha3(e)
    }
}

mod curves;
pub use curves::*;

#[cfg(feature = "rsa")]
mod rsa;
#[cfg(feature = "rsa")]
pub use rsa::*;

pub trait PublicKey {}

pub trait PrivateKey {
    type PublicKey: PublicKey;

    fn public_key(&self) -> Self::PublicKey;
}

impl<T: PrivateKey> From<&T> for Box<dyn PublicKey>
where
    T::PublicKey: 'static,
{
    fn from(private_key: &T) -> Self {
        Box::new(private_key.public_key())
    }
}

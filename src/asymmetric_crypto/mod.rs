mod curves;
pub use curves::*;

#[cfg(feature = "enable-rsa")]
mod rsa;
#[cfg(feature = "enable-rsa")]
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

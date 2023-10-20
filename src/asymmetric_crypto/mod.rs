mod curves;
pub use curves::*;

#[cfg(feature = "rsa")]
mod rsa;

#[cfg(feature = "rsa")]
pub use self::rsa::*;

#[cfg(any(feature = "rsa", feature = "nist_curves"))]
mod subject_public_key_info;

pub trait PublicKey {
    #[cfg(feature = "signature")]
    fn verify(
        &self,
        msg: &[u8],
        signature: &[u8],
        signature_algorithm: Option<const_oid::ObjectIdentifier>,
    ) -> Result<(), crate::CryptoCoreError>;
}

pub trait PrivateKey {
    type PublicKey: PublicKey;

    fn public_key(&self) -> Self::PublicKey;

    #[cfg(feature = "signature")]
    fn try_sign(
        &self,
        msg: &[u8],
        signature_algorithm: Option<const_oid::ObjectIdentifier>,
    ) -> Result<Vec<u8>, crate::CryptoCoreError>;
}

impl<T> From<&T> for Box<dyn PublicKey>
where
    T: PrivateKey,
    T::PublicKey: 'static,
{
    fn from(private_key: &T) -> Self {
        Box::new(private_key.public_key())
    }
}

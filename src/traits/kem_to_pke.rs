use super::*;
use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
};

pub use error::Error;

#[derive(Clone, Copy, Default)]
pub struct GenericPKE<const KEY_LENGTH: usize, Kem: KEM, E: AE<KEY_LENGTH>>(PhantomData<(Kem, E)>);

impl<
        const KEY_LENGTH: usize,
        Kem: KEM<SessionKey = SymmetricKey<KEY_LENGTH>>,
        E: AE<KEY_LENGTH>,
    > PKE for GenericPKE<KEY_LENGTH, Kem, E>
{
    type Plaintext = E::Plaintext;
    type Ciphertext = (Kem::Encapsulation, E::Ciphertext);
    type PublicKey = Kem::EncapsulationKey;
    type SecretKey = Kem::DecapsulationKey;
    type Error = Error<KEY_LENGTH, Kem, E>;

    fn encrypt(
        pk: &Self::PublicKey,
        ptx: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Ciphertext, Self::Error> {
        let (key, enc) = Kem::enc(pk, rng).map_err(Self::Error::Kem)?;
        let ctx = E::encrypt(&key, ptx, rng).map_err(Self::Error::Ae)?;
        Ok((enc, ctx))
    }

    fn decrypt(
        sk: &Self::SecretKey,
        ctx: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Self::Error> {
        let key = Kem::dec(sk, &ctx.0).map_err(Self::Error::Kem)?;
        let ptx = E::decrypt(&key, &ctx.1).map_err(Self::Error::Ae)?;
        Ok(ptx)
    }
}

mod error {
    use super::*;

    #[derive(Clone, Debug)]
    pub enum Error<const KEY_LENGTH: usize, Kem: KEM, Ae: AE<KEY_LENGTH>> {
        Kem(Kem::Error),
        Ae(Ae::Error),
    }

    impl<const KEY_LENGTH: usize, Kem: KEM, E: AE<KEY_LENGTH>> Display for Error<KEY_LENGTH, Kem, E> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Error::Kem(e) => write!(f, "KEM error in PKE: {e}"),
                Error::Ae(e) => write!(f, "AE error in PKE: {e}"),
            }
        }
    }

    impl<const KEY_LENGTH: usize, Kem: Debug + KEM, E: Debug + AE<KEY_LENGTH>> std::error::Error
        for Error<KEY_LENGTH, Kem, E>
    {
    }
}

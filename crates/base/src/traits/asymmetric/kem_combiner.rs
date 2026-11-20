use crate::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    traits::{KDF, KEM},
    Error, SymmetricKey,
};
use error::KemError;
use std::{fmt::Debug, marker::PhantomData};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct Pair<T1, T2>(T1, T2);

impl<Dk1, Dk2, Ek1: for<'z> From<&'z Dk1>, Ek2: for<'z> From<&'z Dk2>> From<&Pair<Dk1, Dk2>>
    for Pair<Ek1, Ek2>
{
    fn from(value: &Pair<Dk1, Dk2>) -> Self {
        Pair(Ek1::from(&value.0), Ek2::from(&value.1))
    }
}

impl<T1: ZeroizeOnDrop, T2: ZeroizeOnDrop> ZeroizeOnDrop for Pair<T1, T2> {}

impl<T1: Serializable, T2: Serializable> Serializable for Pair<T1, T2> {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length() + self.1.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        Ok(ser
            .write(&self.0)
            .map_err(|e| Error::GenericSerializationError(e.to_string()))?
            + ser
                .write(&self.1)
                .map_err(|e| Error::GenericSerializationError(e.to_string()))?)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok(Self(
            de.read()
                .map_err(|e: T1::Error| Error::GenericDeserializationError(e.to_string()))?,
            de.read()
                .map_err(|e: T2::Error| Error::GenericDeserializationError(e.to_string()))?,
        ))
    }
}

/// A KEM combining two other KEM schemes and providing best-of-both CCA
/// security.
#[derive(Debug, Clone, Copy)]
pub struct KemCombiner<
    const KEY_LENGTH: usize,
    const KEY_LENGTH_1: usize,
    const KEY_LENGTH_2: usize,
    Kem1: KEM<KEY_LENGTH_1>,
    Kem2: KEM<KEY_LENGTH_2>,
    Kdf: KDF<KEY_LENGTH>,
>(PhantomData<(Kem1, Kem2, Kdf)>);

// Derive a KEM implementation of the KEM combiner with best-of-both CCA
// security.
impl<
        const KEY_LENGTH: usize,
        const KEY_LENGTH_1: usize,
        const KEY_LENGTH_2: usize,
        Kem1: Debug + KEM<KEY_LENGTH_1>,
        Kem2: Debug + KEM<KEY_LENGTH_2>,
        Kdf: Debug + KDF<KEY_LENGTH>,
    > KEM<KEY_LENGTH> for KemCombiner<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>
where
    Kem1::EncapsulationKey: Debug + for<'a> From<&'a Kem1::DecapsulationKey>,
    Kem2::EncapsulationKey: Debug + for<'a> From<&'a Kem2::DecapsulationKey>,
{
    // Since we can use a tuple (`Serializable` is automatically derived for
    // tuples), let's just do it.
    type Encapsulation = Pair<Kem1::Encapsulation, Kem2::Encapsulation>;

    type EncapsulationKey = Pair<Kem1::EncapsulationKey, Kem2::EncapsulationKey>;

    type DecapsulationKey = Pair<Kem1::DecapsulationKey, Kem2::DecapsulationKey>;

    type Error = KemError<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>;

    fn keygen(
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        let (dk_1, ek_1) = Kem1::keygen(rng).map_err(Self::Error::Kem1)?;
        let (dk_2, ek_2) = Kem2::keygen(rng).map_err(Self::Error::Kem2)?;
        Ok((Pair(dk_1, dk_2), Pair(ek_1, ek_2)))
    }

    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(SymmetricKey<KEY_LENGTH>, Self::Encapsulation), Self::Error> {
        let (ss_1, enc_1) = Kem1::enc(&ek.0, rng).map_err(Self::Error::Kem1)?;
        let (ss_2, enc_2) = Kem2::enc(&ek.1, rng).map_err(Self::Error::Kem2)?;
        let key = Kdf::derive(
            &ek.serialize()?,
            vec![
                &*ss_1,
                &*ss_2,
                &enc_1
                    .serialize()
                    .map_err(Self::Error::to_serialization_error)?,
                &enc_2
                    .serialize()
                    .map_err(Self::Error::to_serialization_error)?,
            ],
        )
        .map_err(Self::Error::Kdf)?;
        Ok((key, Pair(enc_1, enc_2)))
    }

    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error> {
        let ss_1 = Kem1::dec(&dk.0, &enc.0).map_err(Self::Error::Kem1)?;
        let ss_2 = Kem2::dec(&dk.1, &enc.1).map_err(Self::Error::Kem2)?;
        let ek = (
            Kem1::EncapsulationKey::from(&dk.0),
            Kem2::EncapsulationKey::from(&dk.1),
        );
        let key = Kdf::derive(
            &ek.serialize()?,
            vec![
                &*ss_1,
                &*ss_2,
                &enc.0
                    .serialize()
                    .map_err(Self::Error::to_serialization_error)?,
                &enc.1
                    .serialize()
                    .map_err(Self::Error::to_serialization_error)?,
            ],
        )
        .map_err(Self::Error::Kdf)?;
        Ok(key)
    }
}

mod error {
    use super::*;
    use crate::Error;
    use std::fmt::Display;

    #[derive(Debug)]
    pub enum KemError<
        const KEY_LENGTH: usize,
        const KEY_LENGTH_1: usize,
        const KEY_LENGTH_2: usize,
        Kem1: KEM<KEY_LENGTH_1>,
        Kem2: KEM<KEY_LENGTH_2>,
        Kdf: KDF<KEY_LENGTH>,
    > {
        Kem1(Kem1::Error),
        Kem2(Kem2::Error),
        Kdf(Kdf::Error),
        Serialization(String),
    }

    impl<
            const KEY_LENGTH: usize,
            const KEY_LENGTH_1: usize,
            const KEY_LENGTH_2: usize,
            Kem1: KEM<KEY_LENGTH_1>,
            Kem2: KEM<KEY_LENGTH_2>,
            Kdf: KDF<KEY_LENGTH>,
        > Display for KemError<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                KemError::Kem1(e) => write!(f, "KEM1 error in KEM combiner: {e}"),
                KemError::Kem2(e) => write!(f, "KEM2 error in KEM combiner: {e}"),
                KemError::Kdf(e) => write!(f, "KDF error in KEM combiner: {e}"),
                KemError::Serialization(e) => write!(f, "serialization error in KEM combiner: {e}"),
            }
        }
    }

    impl<
            const KEY_LENGTH: usize,
            const KEY_LENGTH_1: usize,
            const KEY_LENGTH_2: usize,
            Kem1: Debug + KEM<KEY_LENGTH_1>,
            Kem2: Debug + KEM<KEY_LENGTH_2>,
            Kdf: Debug + KDF<KEY_LENGTH>,
        > std::error::Error for KemError<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>
    {
    }

    impl<
            const KEY_LENGTH: usize,
            const KEY_LENGTH_1: usize,
            const KEY_LENGTH_2: usize,
            Kem1: KEM<KEY_LENGTH_1>,
            Kem2: KEM<KEY_LENGTH_2>,
            Kdf: KDF<KEY_LENGTH>,
        > From<Error> for KemError<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>
    {
        fn from(e: Error) -> Self {
            Self::to_serialization_error(e)
        }
    }

    impl<
            const KEY_LENGTH: usize,
            const KEY_LENGTH_1: usize,
            const KEY_LENGTH_2: usize,
            Kem1: KEM<KEY_LENGTH_1>,
            Kem2: KEM<KEY_LENGTH_2>,
            Kdf: KDF<KEY_LENGTH>,
        > KemError<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>
    {
        pub fn to_serialization_error<E: std::error::Error>(e: E) -> Self {
            Self::Serialization(e.to_string())
        }
    }
}

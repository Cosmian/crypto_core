use crate::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    traits::{KDF, KEM},
    SymmetricKey,
};
use error::KemError;
use std::{fmt::Debug, marker::PhantomData};
use zeroize::ZeroizeOnDrop;

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

// NOTE: since a KEM requires its encapsulation key to be derivable (via From)
// from its decapsulation key and Rust prevents us to derive an implementation
// for tuples, we need to use wrapper types.

/// Decapsulation key of a KEM combiner.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct KemCombinerDK<
    const KEY_LENGTH: usize,
    const KEY_LENGTH_1: usize,
    const KEY_LENGTH_2: usize,
    Kem1: KEM<KEY_LENGTH_1>,
    Kem2: KEM<KEY_LENGTH_2>,
    Kdf: KDF<KEY_LENGTH>,
>(
    // Use an explicit pair as serialization is derived for pairs.
    (Kem1::DecapsulationKey, Kem2::DecapsulationKey),
    PhantomData<Kdf>,
);

/// Encapsulation key of a KEM combiner.
#[derive(Debug, Clone)]
pub struct KemCombinerEK<
    const KEY_LENGTH: usize,
    const KEY_LENGTH_1: usize,
    const KEY_LENGTH_2: usize,
    Kem1: KEM<KEY_LENGTH_1>,
    Kem2: KEM<KEY_LENGTH_2>,
    Kdf: KDF<KEY_LENGTH>,
>(
    // Use an explicit pair as serialization is derived for pairs.
    (Kem1::EncapsulationKey, Kem2::EncapsulationKey),
    PhantomData<Kdf>,
);

// Though not required by the KEM trait, it is nice to be able to serialize the
// combined decapsulation key when underlying both KEM decapsulation keys are
// serializable.

impl<
        const KEY_LENGTH: usize,
        const KEY_LENGTH_1: usize,
        const KEY_LENGTH_2: usize,
        Kem1: Debug + KEM<KEY_LENGTH_1>,
        Kem2: Debug + KEM<KEY_LENGTH_2>,
        Kdf: Debug + KDF<KEY_LENGTH>,
    > Serializable for KemCombinerDK<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>
where
    Kem1::DecapsulationKey: Serializable,
    Kem2::DecapsulationKey: Serializable,
{
    type Error = KemError<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write(&self.0)
            .map_err(Self::Error::to_serialization_error)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok(Self(de.read()?, PhantomData))
    }
}

// NOTE: the above-mentioned `From` implementation.

impl<
        const KEY_LENGTH: usize,
        const KEY_LENGTH_1: usize,
        const KEY_LENGTH_2: usize,
        Kem1: KEM<KEY_LENGTH_1>,
        Kem2: KEM<KEY_LENGTH_2>,
        Kdf: KDF<KEY_LENGTH>,
    > From<&KemCombinerDK<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>>
    for KemCombinerEK<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>
{
    fn from(dk: &KemCombinerDK<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>) -> Self {
        KemCombinerEK(
            (
                Kem1::EncapsulationKey::from(&dk.0 .0),
                Kem2::EncapsulationKey::from(&dk.0 .1),
            ),
            PhantomData,
        )
    }
}

// KEM encapsulation keys are required to be serializable.

impl<
        const KEY_LENGTH: usize,
        const KEY_LENGTH_1: usize,
        const KEY_LENGTH_2: usize,
        Kem1: Debug + KEM<KEY_LENGTH_1>,
        Kem2: Debug + KEM<KEY_LENGTH_2>,
        Kdf: Debug + KDF<KEY_LENGTH>,
    > Serializable for KemCombinerEK<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>
{
    type Error = KemError<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        ser.write(&self.0)
            .map_err(Self::Error::to_serialization_error)
    }

    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Ok(Self(de.read()?, PhantomData))
    }
}

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
    Kem1::EncapsulationKey: Debug,
    Kem2::EncapsulationKey: Debug,
{
    // Since we can use a tuple (`Serializable` is automatically derived for
    // tuples), let's just do it.
    type Encapsulation = (Kem1::Encapsulation, Kem2::Encapsulation);

    type EncapsulationKey = KemCombinerEK<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>;

    type DecapsulationKey = KemCombinerDK<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>;

    type Error = KemError<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>;

    fn keygen(
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
        let (dk_1, ek_1) = Kem1::keygen(rng).map_err(Self::Error::Kem1)?;
        let (dk_2, ek_2) = Kem2::keygen(rng).map_err(Self::Error::Kem2)?;
        Ok((
            KemCombinerDK((dk_1, dk_2), PhantomData),
            KemCombinerEK((ek_1, ek_2), PhantomData),
        ))
    }

    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(SymmetricKey<KEY_LENGTH>, Self::Encapsulation), Self::Error> {
        let (ss_1, enc_1) = Kem1::enc(&ek.0 .0, rng).map_err(Self::Error::Kem1)?;
        let (ss_2, enc_2) = Kem2::enc(&ek.0 .1, rng).map_err(Self::Error::Kem2)?;
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
        Ok((key, (enc_1, enc_2)))
    }

    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<SymmetricKey<KEY_LENGTH>, Self::Error> {
        let ss_1 = Kem1::dec(&dk.0 .0, &enc.0).map_err(Self::Error::Kem1)?;
        let ss_2 = Kem2::dec(&dk.0 .1, &enc.1).map_err(Self::Error::Kem2)?;
        let ek = KemCombinerEK::from(dk);
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
    use crate::CryptoCoreError;
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
        > From<CryptoCoreError>
        for KemError<KEY_LENGTH, KEY_LENGTH_1, KEY_LENGTH_2, Kem1, Kem2, Kdf>
    {
        fn from(e: CryptoCoreError) -> Self {
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

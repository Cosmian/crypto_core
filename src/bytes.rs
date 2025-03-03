#[macro_export]
macro_rules! define_byte_type {
    ($name: ident) => {
        gensym::gensym! { _define_byte_type! { $name } }
    };
}

macro_rules! _define_byte_type {
    ($module: ident, $name: ident) => {
        pub use $module::$name;

        mod $module {
            #[derive(Debug, Clone, Hash, PartialEq, Eq)]
            pub struct $name<const LENGTH: usize>([u8; LENGTH]);

            use std::ops::{Deref, DerefMut};

            use rand_core::RngCore;

            use crate::{bytes_ser_de::Serializable, CryptoCoreError, Sampling};

            impl<const LENGTH: usize> Deref for $name<LENGTH> {
                type Target = [u8; LENGTH];

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl<const LENGTH: usize> DerefMut for $name<LENGTH> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut self.0
                }
            }

            impl<const LENGTH: usize> From<[u8; LENGTH]> for $name<LENGTH> {
                fn from(bytes: [u8; LENGTH]) -> Self {
                    Self(bytes)
                }
            }

            impl<const LENGTH: usize> Sampling for $name<LENGTH> {
                fn random(rng: &mut impl RngCore) -> Self {
                    let mut bytes = [0; LENGTH];
                    rng.fill_bytes(&mut bytes);
                    Self(bytes)
                }
            }

            impl<const LENGTH: usize> Serializable for $name<LENGTH> {
                type Error = CryptoCoreError;

                fn length(&self) -> usize {
                    LENGTH
                }

                fn write(
                    &self,
                    ser: &mut crate::bytes_ser_de::Serializer,
                ) -> Result<usize, Self::Error> {
                    ser.write_array(&self.0)
                }

                fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
                    de.read_array::<LENGTH>().map(Self)
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use crate::{
        bytes_ser_de::test_serialization, CBytes, CryptoCoreError, CsRng, FixedSizeCBytes,
        RandomFixedSizeCBytes, Sampling,
    };
    use rand_core::SeedableRng;

    /// Defines two new byte types (thus asserting definitions are hygienic),
    /// test their serializations and implement some more stuff for one of them
    /// to prove enough is implemented by default for the defined byte types to
    /// be actually usable.
    #[test]
    fn test_bytes() {
        define_byte_type!(B1);
        define_byte_type!(B2);

        impl CBytes for B2<32> {}

        impl FixedSizeCBytes<32> for B2<32> {
            const LENGTH: usize = 32;

            fn to_bytes(&self) -> [u8; 32] {
                *self.deref()
            }

            fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoCoreError> {
                Ok(Self::from(bytes))
            }
        }

        impl RandomFixedSizeCBytes<32> for B2<32> {
            fn new<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
                Self::random(rng)
            }

            fn as_bytes(&self) -> &[u8] {
                &**self
            }
        }

        let mut rng = CsRng::from_entropy();
        let b1 = B1::<32>::random(&mut rng);
        let b2 = B2::<32>::new(&mut rng);

        test_serialization(&b1).unwrap();
        test_serialization(&b2).unwrap();
    }
}

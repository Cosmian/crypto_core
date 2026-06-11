macro_rules! make_mlkem {
    ($module:tt, $mlkem:ident,
     ($enc:ident, $ctx:ident, $enc_size:tt, $enc_name:tt),
     ($ek:ident, $pk:ident, $ek_size:tt, $ek_name:tt),
     ($dk:ident, $sk:ident, $dk_size:tt, $dk_name:tt)) => {
        pub mod $module {

            use core::ops::IndexMut;
            use std::pin::Pin;

            use cosmian_crypto_core::{
                bytes_ser_de::{Deserializer, Serializable, Serializer},
                traits::KEM,
                CryptoCoreError, Secret, SymmetricKey,
            };
            use libcrux_ml_kem::$module;
            use zeroize::{Zeroize, ZeroizeOnDrop};

            #[derive(Clone)]
            pub struct $enc($module::$ctx);

            impl std::fmt::Debug for $enc {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, $enc_name)
                }
            }

            impl PartialEq for $enc {
                fn eq(&self, other: &Self) -> bool {
                    self.0.as_slice() == other.0.as_slice()
                }
            }

            impl Eq for $enc {}

            impl $enc {
                pub const LENGTH: usize = $enc_size;
            }

            impl Serializable for $enc {
                type Error = CryptoCoreError;

                fn length(&self) -> usize {
                    Self::LENGTH
                }

                fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                    ser.write_array(self.0.as_slice())
                }

                fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
                    Ok(Self(
                        $module::$ctx::try_from(de.read_array::<{ Self::LENGTH }>()?).map_err(
                            |e| CryptoCoreError::GenericDeserializationError(e.to_string()),
                        )?,
                    ))
                }
            }

            #[derive(Clone)]
            pub struct $ek($module::$pk);

            impl std::fmt::Debug for $ek {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, $ek_name)
                }
            }

            impl PartialEq for $ek {
                fn eq(&self, other: &Self) -> bool {
                    self.0.as_slice() == other.0.as_slice()
                }
            }

            impl Eq for $ek {}

            impl $ek {
                pub const LENGTH: usize = $ek_size;
            }

            impl Serializable for $ek {
                type Error = CryptoCoreError;

                fn length(&self) -> usize {
                    Self::LENGTH
                }

                fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                    ser.write_array(self.0.as_slice())
                }

                fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
                    Ok(Self(
                        $module::$pk::try_from(de.read_array::<{ Self::LENGTH }>()?).map_err(
                            |e| CryptoCoreError::GenericDeserializationError(e.to_string()),
                        )?,
                    ))
                }
            }

            #[derive(Clone)]
            pub struct $dk(Pin<Box<$module::$sk>>);

            impl std::fmt::Debug for $dk {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, $dk_name)
                }
            }

            impl $dk {
                pub const LENGTH: usize = $dk_size;
            }

            impl Drop for $dk {
                fn drop(&mut self) {
                    self.0.index_mut(..Self::LENGTH).zeroize();
                }
            }

            impl ZeroizeOnDrop for $dk {}

            impl Serializable for $dk {
                type Error = CryptoCoreError;

                fn length(&self) -> usize {
                    Self::LENGTH
                }

                fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                    ser.write_array(self.0.as_slice())
                }

                fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
                    let mut bytes = de.read_array::<{ Self::LENGTH }>()?;
                    let dk = Self(Box::pin($module::$sk::try_from(&bytes).map_err(|e| {
                        CryptoCoreError::GenericDeserializationError(e.to_string())
                    })?));
                    bytes.zeroize();
                    Ok(dk)
                }
            }

            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct $mlkem;

            impl KEM<32> for $mlkem {
                type Encapsulation = $enc;

                type EncapsulationKey = $ek;

                type DecapsulationKey = $dk;

                type Error = CryptoCoreError;

                fn keygen(
                    rng: &mut impl cosmian_crypto_core::reexport::rand_core::CryptoRngCore,
                ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error> {
                    let mut randomness = [0; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
                    rng.fill_bytes(&mut randomness);
                    let (dk, ek) = $module::generate_key_pair(randomness).into_parts();
                    Ok(($dk(Box::pin(dk)), $ek(ek)))
                }

                fn enc(
                    ek: &Self::EncapsulationKey,
                    rng: &mut impl cosmian_crypto_core::reexport::rand_core::CryptoRngCore,
                ) -> Result<(SymmetricKey<32>, Self::Encapsulation), Self::Error> {
                    let mut randomness = [0; libcrux_ml_kem::SHARED_SECRET_SIZE];
                    rng.fill_bytes(&mut randomness);
                    let (enc, mut ss) = $module::encapsulate(&ek.0, randomness);
                    Ok((Secret::from_unprotected_bytes(&mut ss).into(), $enc(enc)))
                }

                fn dec(
                    dk: &Self::DecapsulationKey,
                    enc: &Self::Encapsulation,
                ) -> Result<cosmian_crypto_core::SymmetricKey<32>, Self::Error> {
                    let mut ss = $module::decapsulate(&dk.0, &enc.0);
                    Ok(Secret::from_unprotected_bytes(&mut ss).into())
                }
            }
        }
    };
}

make_mlkem!(
    mlkem512,
    MlKem512,
    (
        MlKem512Encapsulation,
        MlKem512Ciphertext,
        768,
        "ML-KEM 512 encapsulation"
    ),
    (
        MlKem512EncapsulationKey,
        MlKem512PublicKey,
        800,
        "ML-KEM 512 encapsulation key"
    ),
    (
        MlKem512DecapsulationKey,
        MlKem512PrivateKey,
        1632,
        "ML-KEM 512 decapsulation key"
    )
);

make_mlkem!(
    mlkem768,
    MlKem768,
    (
        MlKem768Encapsulation,
        MlKem768Ciphertext,
        1088,
        "ML-KEM 768 encapsulation"
    ),
    (
        MlKem768EncapsulationKey,
        MlKem768PublicKey,
        1184,
        "ML-KEM 768 encapsulation key"
    ),
    (
        MlKem768DecapsulationKey,
        MlKem768PrivateKey,
        2400,
        "ML-KEM 768 decapsulation key"
    )
);

make_mlkem!(
    mlkem1024,
    MlKem1024,
    (
        MlKem1024Encapsulation,
        MlKem1024Ciphertext,
        1568,
        "ML-KEM 1024 encapsulation"
    ),
    (
        MlKem1024EncapsulationKey,
        MlKem1024PublicKey,
        1568,
        "ML-KEM 1024 encapsulation key"
    ),
    (
        MlKem1024DecapsulationKey,
        MlKem1024PrivateKey,
        3168,
        "ML-KEM 1024 decapsulation key"
    )
);

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_core::traits::tests::test_kem;

    #[test]
    fn test_mlkem() {
        test_kem::<32, mlkem512::MlKem512>();
        test_kem::<32, mlkem768::MlKem768>();
        test_kem::<32, mlkem1024::MlKem1024>();
    }
}

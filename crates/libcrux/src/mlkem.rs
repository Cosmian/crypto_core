macro_rules! make_mlkem {
    ($module:tt, $mlkem:ident,
     ($enc:ident, $ctx:ident, $enc_size:tt),
     ($ek:ident, $pk:ident, $ek_size:tt),
     ($dk:ident, $sk:ident, $dk_size:tt)) => {
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

            pub struct $enc($module::$ctx);

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

            pub struct $ek($module::$pk);

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

            pub struct $dk(Pin<Box<$module::$sk>>);

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
    (MlKem512Encapsulation, MlKem512Ciphertext, 768),
    (MlKem512EncapsulationKey, MlKem512PublicKey, 800),
    (MlKem512DecapsulationKey, MlKem512PrivateKey, 1632)
);

make_mlkem!(
    mlkem768,
    MlKem768,
    (MlKem768Encapsulation, MlKem768Ciphertext, 1088),
    (MlKem768EncapsulationKey, MlKem768PublicKey, 1184),
    (MlKem768DecapsulationKey, MlKem768PrivateKey, 2400)
);

make_mlkem!(
    mlkem1024,
    MlKem1024,
    (MlKem1024Encapsulation, MlKem1024Ciphertext, 1568),
    (MlKem1024EncapsulationKey, MlKem1024PublicKey, 1568),
    (MlKem1024DecapsulationKey, MlKem1024PrivateKey, 3168)
);

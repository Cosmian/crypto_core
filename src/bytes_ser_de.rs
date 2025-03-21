//! Implements the `Serializer` and `Deserializer` objects using LEB128.

use std::{
    fmt::Debug,
    io::{Read, Write},
};

use leb128;
use zeroize::Zeroizing;

use crate::CryptoCoreError;

/// A `Serializable` object can easily be serialized and deserialized into an
/// array of bytes.
pub trait Serializable: Sized {
    /// Error type returned by the serialization.
    type Error: std::error::Error + From<CryptoCoreError>;

    /// Retrieves the length of the serialized object if it can be known.
    ///
    /// This length will be used to initialize the `Serializer` with the
    /// correct capacity in `try_to_bytes()`.
    fn length(&self) -> usize;

    /// Writes to the given `Serializer`.
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error>;

    /// Reads from the given `Deserializer`.
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error>;

    /// Serializes the object. Allocates the correct capacity if it is known.
    fn serialize(&self) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        let mut ser = Serializer::with_capacity(self.length());
        ser.write(self)?;
        Ok(ser.finalize())
    }

    /// Deserializes the object.
    fn deserialize(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err(CryptoCoreError::DeserializationEmptyError.into());
        }

        let mut de = Deserializer::new(bytes);
        match de.read::<Self>() {
            Ok(result) => {
                if de.finalize().is_empty() {
                    Ok(result)
                } else {
                    Err(CryptoCoreError::DeserializationSizeError {
                        given: bytes.len(),
                        expected: result.length(),
                    }
                    .into())
                }
            }
            Err(err) => Err(CryptoCoreError::GenericDeserializationError(format!(
                "failed deserializing with error '{err}' on bytes '{bytes:?}'",
            ))
            .into()),
        }
    }
}

pub struct Deserializer<'a> {
    readable: &'a [u8],
}

impl<'a> Deserializer<'a> {
    /// Generates a new `Deserializer` from the given bytes.
    ///
    /// - `bytes`   : bytes to deserialize
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Deserializer<'a> {
        Deserializer { readable: bytes }
    }

    /// Reads a `u64` from the `Deserializer`.
    pub fn read_leb128_u64(&mut self) -> Result<u64, CryptoCoreError> {
        leb128::read::unsigned(&mut self.readable).map_err(CryptoCoreError::ReadLeb128Error)
    }

    /// Reads an array of bytes of length `LENGTH` from the `Deserializer`.
    pub fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], CryptoCoreError> {
        let mut buf = [0; LENGTH];
        self.readable.read_exact(&mut buf).map_err(|e| {
            CryptoCoreError::DeserializationIoError {
                bytes_len: LENGTH,
                error: e.to_string(),
            }
        })?;
        Ok(buf)
    }

    /// Reads a vector of bytes from the `Deserializer`.
    ///
    /// Vectors serialization overhead is `size_of(LEB128(vector_size))`, where
    /// `LEB128()` is the LEB128 serialization function.
    pub fn read_vec(&mut self) -> Result<Vec<u8>, CryptoCoreError> {
        // The size of the vector is prefixed to the serialization.
        let original_length = self.readable.len();
        let len_u64 = self.read_leb128_u64()?;
        if len_u64 == 0 {
            return Ok(vec![]);
        };
        let len = usize::try_from(len_u64).map_err(|_| {
            CryptoCoreError::GenericDeserializationError(format!(
                "size of vector is too big for architecture: {len_u64} bytes",
            ))
        })?;
        let mut buf = vec![0_u8; len];
        self.readable.read_exact(&mut buf).map_err(|_| {
            CryptoCoreError::DeserializationSizeError {
                expected: len + to_leb128_len(len),
                given: original_length,
            }
        })?;
        Ok(buf)
    }

    /// Reads a slice of bytes from the `Deserializer`.
    ///
    /// Returns a reference to the read subslice
    pub fn read_vec_as_ref(&mut self) -> Result<&'a [u8], CryptoCoreError> {
        let len_u64 = self.read_leb128_u64()?;
        let len = usize::try_from(len_u64).map_err(|_| {
            CryptoCoreError::GenericDeserializationError(format!(
                "size of vector is too big for architecture: {len_u64} bytes",
            ))
        })?;
        let (front, back) = self.readable.split_at(len);
        self.readable = back;
        Ok(front)
    }

    /// Reads the value of a type which implements `Serializable`.
    pub fn read<T: Serializable>(&mut self) -> Result<T, <T as Serializable>::Error> {
        T::read(self)
    }

    /// Returns a pointer to the underlying value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        self.readable
    }

    /// Consumes the `Deserializer` and returns the remaining bytes.
    #[must_use]
    pub fn finalize(self) -> Vec<u8> {
        self.readable.to_vec()
    }
}

// Implement `ZeroizeOnDrop` not to leak serialized sercrets.
pub struct Serializer(Zeroizing<Vec<u8>>);

impl Serializer {
    /// Generates a new `Serializer`.
    #[must_use]
    pub fn new() -> Self {
        Self(Zeroizing::new(vec![]))
    }

    /// Generates a new `Serializer` with the given capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// Writes a `u64` to the `Serializer`.
    ///
    /// - `n`   : `u64` to write
    pub fn write_leb128_u64(&mut self, n: u64) -> Result<usize, CryptoCoreError> {
        leb128::write::unsigned(&mut *self.0, n)
            .map_err(|error| CryptoCoreError::WriteLeb128Error { value: n, error })
    }

    /// Writes an array of bytes to the `Serializer`.
    ///
    /// - `array`   : array of bytes to write
    pub fn write_array(&mut self, array: &[u8]) -> Result<usize, CryptoCoreError> {
        self.0
            .write(array)
            .map_err(|error| CryptoCoreError::SerializationIoError {
                bytes_len: array.len(),
                error,
            })
    }

    /// Writes a vector of bytes to the `Serializer`.
    ///
    /// Vectors serialization overhead is `size_of(LEB128(vector_size))`, where
    /// `LEB128()` is the LEB128 serialization function.
    ///
    /// - `vector`  : vector of bytes to write
    pub fn write_vec(&mut self, vector: &[u8]) -> Result<usize, CryptoCoreError> {
        // Use the size as prefix. This allows initializing the vector with the
        // correct capacity on deserialization.
        let mut len = self.write_leb128_u64(vector.len() as u64)?;
        len += self.write_array(vector)?;
        Ok(len)
    }

    /// Writes an value which type implements `Serializable`.
    ///
    /// - `value`   : value to write
    pub fn write<T: Serializable>(
        &mut self,
        value: &T,
    ) -> Result<usize, <T as Serializable>::Error> {
        value.write(self)
    }

    /// Consumes the `Serializer` and returns the serialized bytes.
    #[must_use]
    pub fn finalize(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl Default for Serializer {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the length of the LEB128 serialization of the given `usize`.
///
/// # Unsigned LEB128
///
/// MSB ------------------ LSB
///       10011000011101100101  In raw binary
///      010011000011101100101  Padded to a multiple of 7 bits
///  0100110  0001110  1100101  Split into 7-bit groups
/// 00100110 10001110 11100101  Add high 1 bits on all but last (most
/// significant) group to form bytes     0x26     0x8E     0xE5  In hexadecimal
///
/// → 0xE5 0x8E 0x26            Output stream (LSB to MSB)
///
/// Source: [Wikipedia](https://en.wikipedia.org/wiki/LEB128#Encoding_format)
///
/// # Parameters
///
/// - `n`   : `usize` for which to compute the length of the serialization
#[must_use]
pub fn to_leb128_len(n: usize) -> usize {
    let mut n = n >> 7;
    let mut size = 1;
    while n != 0 {
        size += 1;
        n >>= 7;
    }
    size
}

/// Test that for the given value, the following holds:
///
/// - `(len ∘ serialize) = length`
/// - `serialize` is deterministic
/// - `(deserialize ∘ serialize) = Id`
///
/// # Panics
///
/// Panics on failure.
pub fn test_serialization<T: PartialEq + Debug + Serializable>(v: &T) -> Result<(), String> {
    let bytes = v
        .serialize()
        .map_err(|e| format!("serialization failure: {e}"))?;
    let w = T::deserialize(&bytes).map_err(|e| format!("deserialization failure: {e}"))?;
    if bytes.len() != v.length() {
        return Err(format!(
            "incorrect serialized length (1): {} != {}",
            bytes.len(),
            v.length()
        ));
    }
    if v != &w {
        return Err(format!("incorrect deserialization: {:?} != {:?}", v, w));
    }
    if bytes.len() != w.length() {
        return Err(format!(
            "incorrect serialized length (2): {} != {}",
            bytes.len(),
            w.length()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{to_leb128_len, Deserializer, Serializable, Serializer};
    use crate::{
        reexport::rand_core::{RngCore, SeedableRng},
        CryptoCoreError, CsRng,
    };

    /// We don't have a non-fixed size implementation of Serializable inside
    /// `crypto_core` so just have a dummy implementation here.
    #[derive(Debug, PartialEq)]
    struct DummyLeb128Serializable {
        bytes: Vec<u8>,
    }

    impl Serializable for DummyLeb128Serializable {
        type Error = CryptoCoreError;

        fn length(&self) -> usize {
            to_leb128_len(self.bytes.len()) + self.bytes.len()
        }

        fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
            ser.write_vec(&self.bytes)
        }

        fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
            Ok(Self {
                bytes: de.read_vec()?,
            })
        }
    }

    #[test]
    fn test_to_leb128_len() {
        let mut rng = CsRng::from_entropy();
        let mut ser = Serializer::new();
        for i in 1..1000 {
            let n = rng.next_u32();
            let length = ser.write_leb128_u64(u64::from(n)).unwrap();
            assert_eq!(
                length,
                to_leb128_len(n as usize),
                "Wrong serialization length for {i}th integer: `{n}u64`"
            );
        }
    }

    #[test]
    fn test_ser_de() -> Result<(), CryptoCoreError> {
        let a1 = b"azerty".to_vec();
        let a2 = b"".to_vec();
        let a3 = "nbvcxwmlkjhgfdsqpoiuytreza)àç_è-('é&".as_bytes().to_vec();

        let mut ser = Serializer::new();
        assert_eq!(7, ser.write_vec(&a1)?);
        assert_eq!(1, ser.write_vec(&a2)?);
        assert_eq!(41, ser.write_vec(&a3)?);
        assert_eq!(49, ser.0.len());

        let mut de = Deserializer::new(&ser.0);
        let a1_ = de.read_vec()?;
        assert_eq!(a1, a1_);
        let a2_ = de.read_vec()?;
        assert_eq!(a2, a2_);
        let a3_ = de.read_vec()?;
        assert_eq!(a3, a3_);
        Ok(())
    }

    #[cfg(feature = "curve25519")]
    #[test]
    fn test_r25519_serialization() -> Result<(), CryptoCoreError> {
        use crate::{asymmetric_crypto::R25519PrivateKey, bytes_ser_de::test_serialization};

        let key = R25519PrivateKey::new(&mut CsRng::from_entropy());
        test_serialization(&key).unwrap();

        let dummy = DummyLeb128Serializable {
            bytes: vec![1; 512],
        };
        test_serialization(&dummy).unwrap();

        Ok(())
    }
}

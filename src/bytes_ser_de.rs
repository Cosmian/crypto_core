//! Implements the `Serializer` and `Deserializer` objects using LEB128.

use std::{
    collections::{HashMap, HashSet, LinkedList},
    fmt::Debug,
    hash::Hash,
    io::{Read, Write},
    num::NonZeroUsize,
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

    /// Reads a packed vector of Boolean values.
    pub fn read_packed_booleans(&'a mut self) -> Result<Vec<bool>, CryptoCoreError> {
        let byte_iter = ByteIterator::<'a>::new(self);
        unpack(byte_iter)
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

    /// Writes a vector of Boolean values in a packed manner.
    ///
    /// Each boolean value is converted into a bit to form a big number. Then,
    /// each byte of this number is written in a LEB128-fashion except for the
    /// last byte. Indeed, where LEB128 does not care about leading zeros since
    /// they are not significant, interpreting leading zeros as leading false
    /// values would change the returned value. Therefore, the highest bit of
    /// each non-terminating byte is 0 while the leading bits of the terminating
    /// bytes are a sequence of ones followed by a single 0. Only the remaining
    /// bits are interpreted as boolean values.
    pub fn write_packed_booleans(&mut self, booleans: &[bool]) -> Result<usize, CryptoCoreError> {
        self.write_array(&pack(booleans))
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

impl Serializable for bool {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        1
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_leb128_u64(*self as u64)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let b = de.read_leb128_u64()?;
        match b {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CryptoCoreError::GenericDeserializationError(format!(
                "not a valid boolean value serialization {b}"
            ))),
        }
    }
}

impl Serializable for u64 {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        if *self == 0 {
            1
        } else {
            (64 - self.leading_zeros()).div_ceil(7) as usize
        }
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_leb128_u64(*self)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read_leb128_u64()
    }
}

impl Serializable for usize {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        to_leb128_len(*self)
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_leb128_u64(*self as u64)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read_leb128_u64().and_then(|n| {
            usize::try_from(n).map_err(|_| {
                CryptoCoreError::GenericDeserializationError("not an usize number".to_string())
            })
        })
    }
}

impl Serializable for NonZeroUsize {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        self.get().length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.get().write(ser)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Self::new(de.read()?).ok_or_else(|| {
            Self::Error::GenericDeserializationError(
                "null value read while a non-zero value was expected".to_string(),
            )
        })
    }
}

impl Serializable for String {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        self.len().length() + self.len()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_vec(self.as_bytes())
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read_vec().and_then(|bytes| {
            String::from_utf8(bytes)
                .map_err(|e| CryptoCoreError::GenericDeserializationError(e.to_string()))
        })
    }
}

impl<T: Serializable> Serializable for Option<T>
where
    T::Error: From<CryptoCoreError>,
{
    type Error = T::Error;

    fn length(&self) -> usize {
        1 + self.as_ref().map(|t| t.length()).unwrap_or_default()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        if let Some(t) = self {
            let mut n = ser.write(&true)?;
            n += ser.write(t)?;
            Ok(n)
        } else {
            ser.write(&false).map_err(Self::Error::from)
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let is_some = de.read::<bool>()?;
        if is_some {
            de.read().map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<T1: Serializable, T2: Serializable> Serializable for (T1, T2)
where
    T1::Error: From<CryptoCoreError>,
    T2::Error: From<CryptoCoreError>,
{
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        self.0.length() + self.1.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = self
            .0
            .write(ser)
            .map_err(|e| Self::Error::GenericSerializationError(e.to_string()))?;
        n += self
            .1
            .write(ser)
            .map_err(|e| Self::Error::GenericSerializationError(e.to_string()))?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        Ok((
            de.read()
                .map_err(|e: T1::Error| Self::Error::GenericDeserializationError(e.to_string()))?,
            de.read()
                .map_err(|e: T2::Error| Self::Error::GenericDeserializationError(e.to_string()))?,
        ))
    }
}

impl<const LENGTH: usize> Serializable for [u8; LENGTH] {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        LENGTH
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write_array(self)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read_array::<LENGTH>()
    }
}

impl<const LENGTH: usize, T: Default + Serializable> Serializable for [T; LENGTH]
where
    T::Error: From<CryptoCoreError>,
{
    type Error = T::Error;

    fn length(&self) -> usize {
        self.iter().map(Serializable::length).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.iter().try_fold(0, |n, t| Ok(n + ser.write(t)?))
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let mut res = std::array::from_fn(|_| T::default());
        for res_i in &mut res {
            *res_i = de.read::<T>()?;
        }
        Ok(res)
    }
}

impl<T: Serializable> Serializable for Vec<T>
where
    T::Error: From<CryptoCoreError>,
{
    type Error = T::Error;

    fn length(&self) -> usize {
        self.len().length() + self.iter().map(Serializable::length).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.iter()
            .try_fold(ser.write(&self.len())?, |n, t| Ok(n + ser.write(t)?))
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = de.read::<usize>()?;
        let mut res = Vec::with_capacity(length);
        for _ in 0..length {
            res.push(de.read::<T>()?);
        }
        Ok(res)
    }
}

impl<T: Serializable> Serializable for LinkedList<T>
where
    T::Error: From<CryptoCoreError>,
{
    type Error = T::Error;

    fn length(&self) -> usize {
        self.len().length() + self.iter().map(Serializable::length).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.iter()
            .try_fold(ser.write(&self.len())?, |n, t| Ok(n + ser.write(t)?))
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = de.read::<usize>()?;
        (0..length).map(|_| de.read::<T>()).collect()
    }
}

impl<T: Hash + Eq + Serializable> Serializable for HashSet<T>
where
    T::Error: From<CryptoCoreError>,
{
    type Error = T::Error;

    fn length(&self) -> usize {
        self.len().length() + self.iter().map(Serializable::length).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.iter()
            .try_fold(ser.write(&self.len())?, |n, t| Ok(n + ser.write(t)?))
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = de.read::<usize>()?;
        let mut res = HashSet::with_capacity(length);
        for _ in 0..length {
            res.insert(de.read::<T>()?);
        }
        Ok(res)
    }
}

impl<K: Hash + Eq + Serializable, V: Serializable> Serializable for HashMap<K, V> {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        self.len().length()
            + self
                .iter()
                .map(|(k, v)| k.length() + v.length())
                .sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        self.iter()
            .try_fold(ser.write(&self.len())?, |mut n, (k, v)| {
                n += ser
                    .write(k)
                    .map_err(|e| CryptoCoreError::GenericDeserializationError(e.to_string()))?;
                n += ser
                    .write(v)
                    .map_err(|e| CryptoCoreError::GenericDeserializationError(e.to_string()))?;
                Ok(n)
            })
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = de.read::<usize>()?;
        let mut res = HashMap::with_capacity(length);
        for _ in 0..length {
            res.insert(
                de.read::<K>()
                    .map_err(|e| CryptoCoreError::GenericDeserializationError(e.to_string()))?,
                de.read::<V>()
                    .map_err(|e| CryptoCoreError::GenericDeserializationError(e.to_string()))?,
            );
        }
        Ok(res)
    }
}

struct ByteIterator<'a>(&'a mut Deserializer<'a>);

impl<'a> ByteIterator<'a> {
    fn new(de: &'a mut Deserializer<'a>) -> Self {
        Self(de)
    }
}

impl Iterator for ByteIterator<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = [0];
        self.0.readable.read_exact(&mut buf).ok().map(|_| buf[0])
    }
}

fn pack(choices: &[bool]) -> Vec<u8> {
    let (q, r) = (choices.len().div_euclid(7), choices.len() % 7);
    let mut res = Vec::with_capacity(q + 1);
    for i in 0..q {
        // In the nominal case, the marker bit (highest bit) is 0, so we
        // just need to fill the lower ones when accumulating from 0.
        let mut a = 0u8;
        for j in 0..7 {
            if choices[i * 7 + j] {
                a += 1 << j;
            }
        }
        res.push(a);
    }

    // The last byte can contain 0 to 6 bits of data, which leaves the
    // room for the minimum-two final marker bits.
    let mut a = 0;
    for j in 0..r {
        a += (choices[q * 7 + j] as u8) << j;
    }
    // All the remaining upper bits but the one in position r are ones.
    for j in r + 1..8 {
        a += 1 << j;
    }
    res.push(a);
    res
}

fn unpack(mut bytes: impl Iterator<Item = u8>) -> Result<Vec<bool>, CryptoCoreError> {
    let mut res = Vec::new();
    loop {
        let mut byte = bytes
            .next()
            .ok_or(CryptoCoreError::DeserializationEmptyError)?;

        if byte < (1 << 7) {
            for _ in 0..7 {
                res.push(byte % 2 == 1);
                byte >>= 1;
            }
        } else {
            // The highest byte is set: this is the terminating byte. First look
            // for the position of the second terminating bit (the first 0 to
            // the left), then interpret all bits from right to left until this
            // position.
            for i in (0..8).rev() {
                if (byte >> i) % 2 == 0 {
                    return {
                        for _ in 0..i {
                            res.push(byte % 2 == 1);
                            byte >>= 1;
                        }
                        Ok(res)
                    };
                }
            }
            return Err(CryptoCoreError::GenericDeserializationError(
                "invalid packed boolean byte: marker bit 0 is missing".to_string(),
            ));
        }
    }
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
    use std::collections::{HashMap, HashSet};

    use super::{test_serialization, to_leb128_len, Deserializer, Serializable, Serializer};
    use crate::{
        bytes_ser_de::{pack, unpack},
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
            self.bytes.len().length() + self.bytes.len()
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
            let length = ser.write_leb128_u64(n as u64).unwrap();
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

    #[test]
    fn test_packing() {
        {
            // Single byte filled with ones except for the second termination
            // marker placed in second highest position.
            let bits = [true; 6];
            let res = [u8::MAX - (1 << 6)];
            assert_eq!(&pack(&bits), &res);
            assert_eq!(&bits, &*unpack(res.into_iter()).unwrap());
        }

        {
            // First byte filled with ones except for the continuation marker,
            // second byte filled with ones except for the second termination
            // marker in lowest position.
            let bits = [true; 7];
            let res = [u8::MAX - (1 << 7), u8::MAX - 1];
            assert_eq!(&pack(&bits), &res);
            assert_eq!(&bits, &*unpack(res.into_iter()).unwrap());
        }
    }

    #[test]
    fn test_boolean_serialization() {
        // Tests all vector lengths from 0 to 2^12 ~ 4096, which is a
        // significant-enough sample of values, leading to write both
        // terminating and non-terminating bytes.
        let mut rng = CsRng::from_entropy();
        for i in 0..(1 << 12) {
            let booleans = (0..i).map(|_| rng.next_u32() % 2 == 0).collect::<Vec<_>>();
            let mut ser = Serializer::new();
            ser.write_packed_booleans(&booleans).unwrap();
            let bytes = ser.finalize();
            let res = Deserializer::new(&bytes).read_packed_booleans().unwrap();
            assert_eq!(booleans, res);
        }
    }

    #[test]
    fn test_base_serializations() {
        let mut rng = CsRng::from_entropy();

        let n = 0u64;
        test_serialization(&n).unwrap();

        #[cfg(target_pointer_width = "64")]
        {
            for i in 0..64 {
                let n: u64 = 1 << i;
                assert_eq!(n.length(), to_leb128_len(n as usize))
            }
        }
        #[cfg(target_pointer_width = "32")]
        {
            for i in 0..32 {
                let n: u64 = 1 << i;
                assert_eq!(n.length(), to_leb128_len(n as usize))
            }
        }

        let string = format!(
            "{:?}",
            (0..1000).map(|_| rng.next_u64()).collect::<Vec<_>>()
        );
        test_serialization(&string).unwrap();

        let v = (0..1000).map(|_| rng.next_u64()).collect::<Vec<_>>();
        test_serialization(&v).unwrap();

        let v = <[u64; 1000]>::try_from(v.as_slice()).unwrap();
        test_serialization(&v).unwrap();

        let s = (0..1000).map(|_| rng.next_u64()).collect::<HashSet<_>>();
        test_serialization(&s).unwrap();

        let m = (0..1000)
            .map(|_| (rng.next_u64(), rng.next_u64()))
            .collect::<HashMap<_, _>>();
        test_serialization(&m).unwrap();
    }
}

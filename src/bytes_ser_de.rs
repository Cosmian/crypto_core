use crate::CryptoCoreError;
use leb128;
use std::{
    collections::{HashMap, HashSet, LinkedList},
    fmt::Debug,
    hash::Hash,
    io::{Read, Write},
    num::NonZeroUsize,
};
use zeroize::Zeroizing;

/// An object that can be used to serialize values implementing `Serializable`.
pub trait Serializer {
    type Error: std::error::Error + From<CryptoCoreError>;
    type Output;
    fn new() -> Self;
    fn with_capacity(capacity: usize) -> Self;
    fn write_leb128(&mut self, n: u64) -> Result<usize, Self::Error>;
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize, Self::Error>;
    fn finalize(self) -> Result<Self::Output, Self::Error>;
}

pub struct SecretSerializer(Zeroizing<Vec<u8>>);

impl Serializer for SecretSerializer {
    type Error = CryptoCoreError;

    type Output = Zeroizing<Vec<u8>>;

    fn new() -> Self {
        Self(Zeroizing::new(Vec::new()))
    }

    fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::from(Vec::with_capacity(capacity)))
    }

    fn write_leb128(&mut self, n: u64) -> Result<usize, Self::Error> {
        leb128::write::unsigned(&mut *self.0, n)
            .map_err(|error| CryptoCoreError::WriteLeb128Error { value: n, error })
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.0
            .write(bytes)
            .map_err(|error| CryptoCoreError::SerializationIoError {
                bytes_len: bytes.len(),
                error,
            })
    }

    fn finalize(self) -> Result<Self::Output, Self::Error> {
        Ok(self.0)
    }
}

pub struct PublicSerializer(Vec<u8>);

impl Serializer for PublicSerializer {
    type Error = CryptoCoreError;

    type Output = Vec<u8>;

    fn new() -> Self {
        Self(Vec::new())
    }

    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn write_leb128(&mut self, n: u64) -> Result<usize, Self::Error> {
        leb128::write::unsigned(&mut self.0, n)
            .map_err(|error| CryptoCoreError::WriteLeb128Error { value: n, error })
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.0
            .write(bytes)
            .map_err(|error| CryptoCoreError::SerializationIoError {
                bytes_len: bytes.len(),
                error,
            })
    }

    fn finalize(self) -> Result<Self::Output, Self::Error> {
        Ok(self.0)
    }
}

/// An object that can be used to deserialize values implementing
/// `Serializable`.
pub trait Deserializer {
    type Error: std::error::Error + From<CryptoCoreError>;
    type Input;
    fn new(input: Self::Input) -> Self;
    fn read_leb128(&mut self) -> Result<u64, Self::Error>;
    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error>;
    fn is_empty(&self) -> bool;
    fn length(&self) -> usize;
}

pub struct BytesDeserializer<'a>(&'a [u8]);

impl<'a> Deserializer for BytesDeserializer<'a> {
    type Error = CryptoCoreError;

    type Input = &'a [u8];

    fn new(bytes: Self::Input) -> Self {
        Self(bytes)
    }

    fn read_leb128(&mut self) -> Result<u64, Self::Error> {
        leb128::read::unsigned(&mut self.0).map_err(CryptoCoreError::ReadLeb128Error)
    }

    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0
            .read_exact(bytes)
            .map_err(|e| CryptoCoreError::DeserializationIoError {
                bytes_len: bytes.len(),
                error: e.to_string(),
            })
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn length(&self) -> usize {
        self.0.len()
    }
}

/// An object that can be serialized.
pub trait Serializable: Sized {
    /// Returns the length of this value once serialized.
    fn length(&self) -> usize;

    /// Writes this value to the given serializer.
    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error>;

    /// Reads a value of this type from the given deserializer.
    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error>;

    /// Serializes this value using the given serializer.
    fn serialize<S: Serializer>(&self) -> Result<S::Output, S::Error> {
        let mut ser = S::with_capacity(self.length());
        self.write(&mut ser)?;
        ser.finalize()
    }

    /// Deserializes this value using the given deserializer.
    fn deserialize<D: Deserializer>(input: D::Input) -> Result<Self, D::Error> {
        let mut de = D::new(input);
        match Self::read(&mut de) {
            Ok(result) => {
                if de.is_empty() {
                    Ok(result)
                } else {
                    Err(CryptoCoreError::DeserializationSizeError {
                        given: result.length() + de.length(),
                        expected: result.length(),
                    }
                    .into())
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl Serializable for bool {
    fn length(&self) -> usize {
        1
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        ser.write_leb128(*self as u64)
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let b = de.read_leb128()?;
        match b {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CryptoCoreError::GenericDeserializationError(format!(
                "not a valid boolean value serialization {b}"
            ))
            .into()),
        }
    }
}

impl Serializable for u64 {
    fn length(&self) -> usize {
        if *self == 0 {
            1
        } else {
            (64 - self.leading_zeros()).div_ceil(7) as usize
        }
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        ser.write_leb128(*self)
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        de.read_leb128()
    }
}

impl Serializable for usize {
    fn length(&self) -> usize {
        (*self as u64).length()
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        ser.write_leb128(*self as u64)
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        de.read_leb128().and_then(|n| {
            usize::try_from(n).map_err(|_| {
                CryptoCoreError::GenericDeserializationError("not an usize number".to_string())
                    .into()
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
    fn length(&self) -> usize {
        self.len().length() + self.len()
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        let mut n = self.len().write(ser)?;
        n += ser.write_bytes(self.as_bytes())?;
        Ok(n)
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let n = usize::read(de)?;
        let mut bytes = vec![0; n];
        de.read_bytes(&mut bytes)?;
        String::from_utf8(bytes)
            .map_err(|e| CryptoCoreError::GenericDeserializationError(e.to_string()).into())
    }
}

impl<T: Serializable> Serializable for Option<T> {
    fn length(&self) -> usize {
        1 + self.as_ref().map(|t| t.length()).unwrap_or_default()
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        if let Some(t) = self {
            Ok(true.write(ser)? + t.write(ser)?)
        } else {
            false.write(ser)
        }
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let is_some = bool::read(de)?;
        if is_some {
            T::read(de).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<const LENGTH: usize> Serializable for [u8; LENGTH] {
    fn length(&self) -> usize {
        LENGTH
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        ser.write_bytes(self)
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let mut buffer = [0; LENGTH];
        de.read_bytes(&mut buffer)?;
        Ok(buffer)
    }
}

impl<const LENGTH: usize, T: Copy + Default + Serializable> Serializable for [T; LENGTH] {
    fn length(&self) -> usize {
        self.iter().map(Serializable::length).sum()
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        self.iter().try_fold(0, |n, t| Ok(n + t.write(ser)?))
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let mut ts = [T::default(); LENGTH];
        for t in ts.iter_mut() {
            *t = T::read(de)?;
        }
        Ok(ts)
    }
}

impl<T: Serializable> Serializable for Vec<T> {
    fn length(&self) -> usize {
        self.len().length() + self.iter().map(Serializable::length).sum::<usize>()
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        self.iter()
            .try_fold(self.len().write(ser)?, |n, t| Ok(n + t.write(ser)?))
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let length = usize::read(de)?;
        (0..length).map(|_| T::read(de)).collect()
    }
}

impl<T: Serializable> Serializable for LinkedList<T> {
    fn length(&self) -> usize {
        self.len().length() + self.iter().map(Serializable::length).sum::<usize>()
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        self.iter()
            .try_fold(self.len().write(ser)?, |n, t| Ok(n + t.write(ser)?))
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let length = usize::read(de)?;
        (0..length).map(|_| T::read(de)).collect()
    }
}

impl<T: Hash + Eq + Serializable> Serializable for HashSet<T> {
    fn length(&self) -> usize {
        self.len().length() + self.iter().map(Serializable::length).sum::<usize>()
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        self.iter()
            .try_fold(self.len().write(ser)?, |n, t| Ok(n + t.write(ser)?))
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let length = usize::read(de)?;
        (0..length).map(|_| T::read(de)).collect()
    }
}

impl<K: Hash + Eq + Serializable, V: Serializable> Serializable for HashMap<K, V> {
    fn length(&self) -> usize {
        self.len().length()
            + self
                .iter()
                .map(|(k, v)| k.length() + v.length())
                .sum::<usize>()
    }

    fn write<S: Serializer>(&self, ser: &mut S) -> Result<usize, S::Error> {
        self.iter()
            .try_fold(self.len().write(ser)?, |mut n, (k, v)| {
                n += k.write(ser)?;
                n += v.write(ser)?;
                Ok(n)
            })
    }

    fn read<D: Deserializer>(de: &mut D) -> Result<Self, D::Error> {
        let length = usize::read(de)?;
        (0..length)
            .map(|_| Ok((K::read(de)?, V::read(de)?)))
            .collect()
    }
}

pub fn write_packed_booleans<S: Serializer>(
    ser: &mut S,
    choices: &[bool],
) -> Result<usize, S::Error> {
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

    ser.write_bytes(&pack(choices))
}

pub fn read_packed_booleans<D: Deserializer>(de: &mut D) -> Result<Vec<bool>, D::Error> {
    struct ByteIterator<'a, D: Deserializer>(&'a mut D);

    impl<D: Deserializer> Iterator for ByteIterator<'_, D> {
        type Item = u8;

        fn next(&mut self) -> Option<Self::Item> {
            let mut bytes = [0];
            self.0.read_bytes(&mut bytes).ok().map(|_| bytes[0])
        }
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

    unpack(ByteIterator(de)).map_err(D::Error::from)
}

/// Test that for the given value, the following holds:
///
/// - `(len ∘ serialize) = length`
/// - `serialize` is deterministic
/// - `(deserialize ∘ serialize) = Id`
pub fn test_serialization<T: PartialEq + Debug + Serializable>(v: &T) -> Result<(), String> {
    let bytes = v
        .serialize::<SecretSerializer>()
        .map_err(|e| format!("serialization failure: {e}"))?;

    let w = T::deserialize::<BytesDeserializer>(&bytes)
        .map_err(|e| format!("deserialization failure: {e}"))?;

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
    use super::{test_serialization, Deserializer, SecretSerializer, Serializer};
    use crate::{
        bytes_ser_de::{read_packed_booleans, write_packed_booleans, BytesDeserializer},
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_boolean_serialization() {
        // Tests all vector lengths from 0 to 2^12 ~ 4096, which is a
        // significant-enough sample of values, leading to write both
        // terminating and non-terminating bytes.
        let mut rng = CsRng::from_entropy();
        for i in 0..(1 << 12) {
            let booleans = (0..i).map(|_| rng.next_u32() % 2 == 0).collect::<Vec<_>>();
            let mut ser = SecretSerializer::new();
            write_packed_booleans(&mut ser, &booleans).unwrap();
            let bytes = ser.finalize().unwrap();
            let res = read_packed_booleans(&mut BytesDeserializer::new(&bytes)).unwrap();
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
                test_serialization(&n).unwrap();
            }
        }
        #[cfg(target_pointer_width = "32")]
        {
            for i in 0..32 {
                let n: u64 = 1 << i;
                test_serialization(&n).unwrap();
            }
        }

        let string = format!(
            "{:?}",
            (0..1000).map(|_| rng.next_u64()).collect::<Vec<_>>()
        );
        test_serialization(&string).unwrap();

        let v = (0..1000).map(|_| rng.next_u64()).collect::<Vec<_>>();
        test_serialization(&v).unwrap();

        let s = (0..1000).map(|_| rng.next_u64()).collect::<HashSet<_>>();
        test_serialization(&s).unwrap();

        let m = (0..1000)
            .map(|_| (rng.next_u64(), rng.next_u64()))
            .collect::<HashMap<_, _>>();
        test_serialization(&m).unwrap();
    }
}

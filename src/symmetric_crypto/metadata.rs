use crate::CryptoCoreError;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

/// Attempts to get the length of this slice as an `u32` in 4 endian bytes and
/// returns an error if it overflows
fn get_u32_len(slice: &[u8]) -> Result<[u8; 4], CryptoCoreError> {
    u32::try_from(slice.len())
        .map_err(|_| {
            CryptoCoreError::InvalidSize(
                "Slice of bytes is too big to fit in 2^32 bytes".to_string(),
            )
        })
        .map(u32::to_be_bytes)
}

/// Scans a slice sequentially, updating the cursor position on the fly
pub struct BytesScanner<'a> {
    bytes: &'a [u8],
    start: usize,
}

impl<'a> BytesScanner<'a> {
    /// Returns a new byte scanner object.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        BytesScanner { bytes, start: 0 }
    }

    /// Returns a slice of the next `size` bytes or an error if less is
    /// available
    pub fn next(&mut self, size: usize) -> Result<&'a [u8], CryptoCoreError> {
        let end = self.start + size;
        if self.bytes.len() < end {
            return Err(CryptoCoreError::InvalidSize(format!(
                "{size}, only {} bytes available",
                self.bytes.len() - self.start
            )));
        }
        let chunk = &self.bytes[self.start..end];
        self.start = end;
        Ok(chunk)
    }

    /// Reads the next 4 big endian bytes to return an u32
    pub fn read_u32(&mut self) -> Result<u32, CryptoCoreError> {
        Ok(u32::from_be_bytes(self.next(4)?.try_into().map_err(
            |_e| CryptoCoreError::ConversionError("invalid u32".to_string()),
        )?))
    }

    /// Returns the remainder of the slice
    pub fn remainder(&mut self) -> Option<&'a [u8]> {
        if self.start >= self.bytes.len() {
            None
        } else {
            let remainder = &self.bytes[self.start..];
            self.start = self.bytes.len();
            Some(remainder)
        }
    }

    /// Return `true` if there still are some bytes to read.
    pub fn has_more(&self) -> bool {
        self.start < self.bytes.len()
    }
}

/// Metadata encrypted as part of the header
///
/// The `uid` is a security parameter:
///  - when using a stream cipher such as AES, it uniquely
///    identifies a resource, such as a file, and is part of the AEAD of every
///    block when symmetrically encrypting data. It prevents an attacker from
///    moving blocks between resources.
///  - when using FPE, it is the "tweak" ([see Appendix C](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf))
///
/// The `additional_data` is not used as a security parameter. It is optional
/// data (such as index tags) symmetrically encrypted as part of the header.
#[derive(Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize)]
pub struct Metadata {
    pub uid: Vec<u8>,
    pub additional_data: Option<Vec<u8>>,
}

impl Metadata {
    /// The length in bytes of this meta data
    pub fn len(&self) -> usize {
        self.uid.len() + self.additional_data.as_ref().unwrap_or(&vec![]).len()
    }

    /// Returns `true` if the given metadata is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Encode the metadata as a byte array
    ///
    /// The first 4 bytes is the `u32` length of the UID as big endian bytes
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, CryptoCoreError> {
        if self.is_empty() {
            return Ok(vec![]);
        }
        let mut bytes = Vec::with_capacity(4 + self.len());
        bytes.append(&mut get_u32_len(&self.uid)?.to_vec());
        bytes.extend_from_slice(&self.uid);
        if let Some(ad) = &self.additional_data {
            bytes.extend_from_slice(ad);
        }
        Ok(bytes)
    }

    /// Decode the metadata from a byte array
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let mut scanner = BytesScanner::new(bytes);
        let uid_len = scanner.read_u32()? as usize;
        let uid = scanner.next(uid_len)?.to_vec();
        let additional_data = scanner.remainder().to_owned().map(|v| v.to_vec());

        Ok(Self {
            uid,
            additional_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_serialization() {
        let metadata = Metadata {
            uid: vec![1],
            additional_data: Some(vec![1, 2, 3, 4, 5]),
        };

        let bytes = metadata.try_to_bytes().unwrap();
        let res = Metadata::try_from_bytes(&bytes).unwrap();
        assert_eq!(metadata, res);
    }
}

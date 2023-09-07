use pkcs8::{
    der::asn1::BitStringRef, spki, Document, EncodePrivateKey, EncodePublicKey, ObjectIdentifier,
    PrivateKeyInfo, SecretDocument,
};

use super::key_pair::X25519Keypair;
use crate::{RandomFixedSizeCBytes, X25519PublicKey, CURVE_25519_PRIVATE_KEY_LENGTH};

impl EncodePrivateKey for X25519Keypair {
    fn to_pkcs8_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        // Serialize private key as nested OCTET STRING
        let mut private_key = [0u8; 2 + CURVE_25519_PRIVATE_KEY_LENGTH];
        private_key[0] = 0x04;
        private_key[1] = 0x20;
        private_key[2..].copy_from_slice(self.private_key.as_bytes());

        let private_key_info = PrivateKeyInfo {
            algorithm: X25519_ALGORITHM_ID,
            private_key: &private_key,
            public_key: None,
        };

        let result = SecretDocument::encode_msg(&private_key_info)?;

        Ok(result)
    }
}

/// Algorithm [`ObjectIdentifier`] for the X25519 digital signature algorithm
/// (`id-X25519`).
///
/// <http://oid-info.com/get/1.3.101.110>
pub const X25519_ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

/// X25519 Algorithm Identifier.
pub const X25519_ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> =
    pkcs8::AlgorithmIdentifierRef {
        oid: X25519_ALGORITHM_OID,
        parameters: None,
    };

impl EncodePublicKey for X25519Keypair {
    fn to_public_key_der(&self) -> spki::Result<Document> {
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: X25519_ALGORITHM_ID,
            subject_public_key: BitStringRef::new(0, self.public_key.as_bytes())?,
        }
        .try_into()
    }
}

impl EncodePublicKey for X25519PublicKey {
    fn to_public_key_der(&self) -> spki::Result<Document> {
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: X25519_ALGORITHM_ID,
            subject_public_key: BitStringRef::new(0, self.0.as_bytes())?,
        }
        .try_into()
    }
}

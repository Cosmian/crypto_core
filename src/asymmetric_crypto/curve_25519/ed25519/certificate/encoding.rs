use pkcs8::{
    der::{
        asn1::{BitString, BitStringRef},
        AnyRef,
    },
    spki::{self, AlgorithmIdentifier, SignatureAlgorithmIdentifier, SignatureBitStringEncoding},
    Document, EncodePrivateKey, EncodePublicKey, ObjectIdentifier, PrivateKeyInfo, SecretDocument,
};

use crate::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature, CURVE_25519_SECRET_LENGTH};

/// Algorithm [`ObjectIdentifier`] for the Ed25519 digital signature algorithm
/// (`id-Ed25519`).
///
/// <http://oid-info.com/get/1.3.101.112>
pub const ED25519_ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Ed25519 Algorithm Identifier.
pub const ED25519_ALGORITHM_ID: pkcs8::AlgorithmIdentifierRef<'static> =
    pkcs8::AlgorithmIdentifierRef {
        oid: ED25519_ALGORITHM_OID,
        parameters: None,
    };

impl EncodePublicKey for Ed25519Keypair {
    fn to_public_key_der(&self) -> spki::Result<Document> {
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: ED25519_ALGORITHM_ID,
            subject_public_key: BitStringRef::new(0, self.public_key.as_bytes())?,
        }
        .try_into()
    }
}

impl EncodePrivateKey for Ed25519Keypair {
    fn to_pkcs8_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        // Serialize private key as nested OCTET STRING
        let mut private_key = [0u8; 2 + CURVE_25519_SECRET_LENGTH];
        private_key[0] = 0x04;
        private_key[1] = 0x20;
        private_key[2..].copy_from_slice(self.private_key.as_bytes());

        let private_key_info = PrivateKeyInfo {
            algorithm: ED25519_ALGORITHM_ID,
            private_key: &private_key,
            public_key: None,
        };

        let result = SecretDocument::encode_msg(&private_key_info)?;

        Ok(result)
    }
}

impl SignatureAlgorithmIdentifier for Ed25519Keypair {
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = ED25519_ALGORITHM_ID;
}

impl SignatureBitStringEncoding for Ed25519Signature {
    fn to_bitstring(&self) -> pkcs8::der::Result<pkcs8::der::asn1::BitString> {
        BitString::new(0, self.to_vec())
    }
}

impl EncodePublicKey for Ed25519PublicKey {
    fn to_public_key_der(&self) -> spki::Result<Document> {
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: ED25519_ALGORITHM_ID,
            subject_public_key: BitStringRef::new(0, self.0.as_bytes())?,
        }
        .try_into()
    }
}

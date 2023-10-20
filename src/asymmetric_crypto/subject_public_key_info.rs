use crate::{
    CryptoCoreError, NistPublicKey, PublicKey, RsaPublicKey, P192_PUBLIC_KEY_LENGTH,
    P256_PUBLIC_KEY_LENGTH, P384_PUBLIC_KEY_LENGTH,
};
use const_oid::ObjectIdentifier;
use p192::NistP192;
use p256::NistP256;
use p384::NistP384;
use rsa::pkcs1::DecodeRsaPublicKey;
use spki::der::{asn1::BitString, Any};
use spki::DecodePublicKey;

impl From<&spki::SubjectPublicKeyInfo<Any, BitString>> for Box<dyn PublicKey> {
    fn from(spki: &spki::SubjectPublicKeyInfo<Any, BitString>) -> Self {
        from_subject_public_key_info(spki).unwrap()
    }
}

/// Subject Public Key Info [RFC 5280 § 4.1.2.7]
/// is the format of Public Keys found
/// in Certificates Signing Requests and Certificates.
pub fn from_subject_public_key_info(
    spki: &spki::SubjectPublicKeyInfo<Any, BitString>,
) -> Result<Box<dyn PublicKey>, CryptoCoreError> {
    match spki.algorithm.oid.to_string().as_str() {
        //id-ecPublicKey
        "1.2.840.10045.2.1" => {
            let params = spki.algorithm.parameters.as_ref().ok_or_else(|| {
                CryptoCoreError::ConversionError(
                    "No curve name parameter available for id-ecPublicKey".to_string(),
                )
            })?;
            let curve_oid = &ObjectIdentifier::from_bytes(&params.value()).map_err(|e| {
                CryptoCoreError::ConversionError(format!(
                    "Error converting curve name parameter to OID: {}",
                    e
                ))
            })?;
            // let curve_name = DB.by_oid(curve_oid).ok_or_else(|| {
            //     CryptoCoreError::ConversionError(format!("Unsupported curve OID: {}", curve_oid))
            // })?;
            match curve_oid.to_string().as_str() {
                //"secp192r1" | "ansiX9p192r1" | "prime192v1"
                "1.2.840.10045.3.1.1" => {
                    let public_key = elliptic_curve::PublicKey::<NistP192>::from_public_key_der(
                        spki.subject_public_key.as_bytes().ok_or_else(|| {
                            CryptoCoreError::ConversionError(
                                "No SubjectPublicKeyInfo available".to_string(),
                            )
                        })?,
                    )?;
                    Ok(Box::new(NistPublicKey::<NistP192, P192_PUBLIC_KEY_LENGTH>(
                        public_key,
                    )))
                }
                //"secp224r1" | "nistp224"
                "1.3.132.0.33" => {
                    let public_key = elliptic_curve::PublicKey::<NistP192>::from_public_key_der(
                        spki.subject_public_key.as_bytes().ok_or_else(|| {
                            CryptoCoreError::ConversionError(
                                "No SubjectPublicKeyInfo available".to_string(),
                            )
                        })?,
                    )?;
                    Ok(Box::new(NistPublicKey::<NistP192, P192_PUBLIC_KEY_LENGTH>(
                        public_key,
                    )))
                }
                //"secp256r1" | "prime256v1" | "nistp256"
                "1.2.840.10045.3.1.7" => {
                    let public_key = p256::PublicKey::from_public_key_der(
                        spki.subject_public_key.as_bytes().ok_or_else(|| {
                            CryptoCoreError::ConversionError(
                                "No SubjectPublicKeyInfo available".to_string(),
                            )
                        })?,
                    )?;
                    Ok(Box::new(NistPublicKey::<NistP256, P256_PUBLIC_KEY_LENGTH>(
                        public_key,
                    )))
                }
                // "secp384r1" | "ansip384r1" | "nistp284"
                "1.3.132.0.34" => {
                    let public_key = p384::PublicKey::from_public_key_der(
                        spki.subject_public_key.as_bytes().ok_or_else(|| {
                            CryptoCoreError::ConversionError(
                                "No SubjectPublicKeyInfo available".to_string(),
                            )
                        })?,
                    )?;
                    Ok(Box::new(NistPublicKey::<NistP384, P384_PUBLIC_KEY_LENGTH>(
                        public_key,
                    )))
                }
                curve_name => Err(CryptoCoreError::UnsupportedAlgorithm(
                    curve_name.to_string(),
                )),
            }
        }
        //rsaEncryption
        "1.2.840.113549.1.1.1" => {
            let rsa_public_key = RsaPublicKey(
                rsa::RsaPublicKey::from_pkcs1_der(spki.subject_public_key.as_bytes().ok_or_else(
                    || {
                        CryptoCoreError::ConversionError(
                            "No SubjectPublicKeyInfo available".to_string(),
                        )
                    },
                )?)
                .map_err(|e| {
                    CryptoCoreError::ConversionError(format!(
                        "SubjectPublicKeyInfo.PublicKey PKCS#1 error: {}",
                        e
                    ))
                })?,
            );
            Ok(Box::new(rsa_public_key))
        }
        algorithm_oid => {
            return Err(CryptoCoreError::UnsupportedAlgorithm(
                algorithm_oid.to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ecies::EciesEcPublicKey;
    use spki::{
        der::{asn1::BitString, Any},
        SubjectPublicKeyInfo,
    };

    /// Elliptic Curve (P-256) `SubjectPublicKeyInfo` encoded as ASN.1 DER
    const EC_P256_DER_EXAMPLE: &[u8] = include_bytes!("tests/spki/p256-pub.der");

    /// Ed25519 `SubjectPublicKeyInfo` encoded as ASN.1 DER
    const ED25519_DER_EXAMPLE: &[u8] = include_bytes!("tests/spki/ed25519-pub.der");

    /// RSA-2048 `SubjectPublicKeyInfo` encoded as ASN.1 DER
    const RSA_2048_DER_EXAMPLE: &[u8] = include_bytes!("tests/spki/rsa2048-pub.der");

    /// Elliptic Curve (P-256) public key encoded as PEM
    const EC_P256_PEM_EXAMPLE: &str = include_str!("tests/spki/p256-pub.pem");

    /// Ed25519 public key encoded as PEM
    const ED25519_PEM_EXAMPLE: &str = include_str!("tests/spki/ed25519-pub.pem");

    /// RSA-2048 PKCS#8 public key encoded as PEM
    const RSA_2048_PEM_EXAMPLE: &str = include_str!("tests/spki/rsa2048-pub.pem");

    #[test]
    fn test_from_subject_public_key_info() {
        let spki = SubjectPublicKeyInfo::<Any, BitString>::try_from(RSA_2048_DER_EXAMPLE).unwrap();
        println!("spki: {:?}", spki);
        let public_key = super::from_subject_public_key_info(&spki).unwrap();
    }
}

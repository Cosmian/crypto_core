mod encoding;

use std::{str::FromStr, time::Duration};

pub use encoding::ED25519_ALGORITHM_ID;
use pkcs8::{der::EncodePem, spki::SubjectPublicKeyInfoOwned, EncodePublicKey, LineEnding};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    certificate::CertificateInner,
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

use crate::{CryptoCoreError, Ed25519Keypair, Ed25519Signature};

fn default_validity_duration(expiration_in_months: u64) -> Result<Validity, CryptoCoreError> {
    // Considering bissextile year, there are in a year an average of 365+1/4 days.
    // And 365,25/12 = 30,4375 => 30d10h30m
    const SECONDS_IN_MONTH: u64 = 30 * 24 * 60 * 60 + 10 * 60 * 60 + 30 * 60;

    // Calculate the total duration in seconds
    let total_seconds: u64 = expiration_in_months * SECONDS_IN_MONTH;

    // Create a Duration instance
    let duration = Duration::from_secs(total_seconds);
    Ok(Validity::from_now(duration)?)
}

fn get_subject_public_key_info<PublicKey>(
    public_key: &PublicKey,
) -> Result<SubjectPublicKeyInfoOwned, CryptoCoreError>
where
    PublicKey: EncodePublicKey,
{
    let public_key_der = public_key.to_public_key_der()?;
    Ok(SubjectPublicKeyInfoOwned::try_from(
        public_key_der.as_bytes(),
    )?)
}

pub struct Certificate {
    inner: CertificateInner,
    pub uuid: uuid::Uuid,
}

impl Certificate {
    #[must_use]
    pub fn new(inner: CertificateInner, uuid: uuid::Uuid) -> Self {
        Self { inner, uuid }
    }

    pub fn to_pem(&self) -> Result<String, CryptoCoreError> {
        Ok(self.inner.to_pem(LineEnding::LF)?)
    }
}

pub fn build_certificate_profile(
    ca: &str,
    enable_key_agreement: bool,
    enable_key_encipherment: bool,
) -> Result<Profile, CryptoCoreError> {
    // Set certificate as a leaf certificate
    let profile = Profile::Leaf {
        issuer: Name::from_str(&format!("CN={ca}"))?,
        enable_key_agreement,
        enable_key_encipherment,
    };
    Ok(profile)
}

pub fn build_certificate<PublicKey>(
    signer: &Ed25519Keypair,
    public_key: &PublicKey,
    profile: Profile,
    subject: &str,
    expiration_in_months: u64,
) -> Result<Certificate, CryptoCoreError>
where
    PublicKey: EncodePublicKey,
{
    // Create certificate serial number
    let uuid = uuid::Uuid::new_v4();
    let serial_number = SerialNumber::new(uuid.as_bytes())?;

    // Build Subject as RdnSequence
    let subject = Name::from_str(&format!("CN={subject}"))?;

    // Build SPKI
    let spki = get_subject_public_key_info::<PublicKey>(public_key)?;

    // Build certificate
    let builder = CertificateBuilder::new(
        profile,
        serial_number,
        default_validity_duration(expiration_in_months)?,
        subject,
        spki,
        signer,
    )?;

    let certificate = builder.build::<Ed25519Signature>()?;

    Ok(Certificate {
        inner: certificate,
        uuid,
    })
}

#[cfg(test)]
mod tests {
    use openssl::{pkey::PKey, stack::Stack, x509::X509};
    use pkcs8::{
        der::pem::PemLabel, EncodePrivateKey, EncodePublicKey, LineEnding, PrivateKeyInfo,
        SubjectPublicKeyInfoRef,
    };
    use rand_core::SeedableRng;
    use tempfile::TempDir;
    use x509_cert::builder::Profile;

    use crate::{
        asymmetric_crypto::curve_25519::{ed25519::build_certificate, x25519::X25519Keypair},
        CryptoCoreError, CsRng, Ed25519Keypair, X25519PublicKey,
    };

    #[test]
    fn test_certificate() -> Result<(), CryptoCoreError> {
        // Init
        let tmp_dir = TempDir::new().unwrap();
        let tmp_path = tmp_dir.into_path();

        let export_public_key_filename =
            tmp_path.join("public_key.pem").to_str().unwrap().to_owned();
        let export_private_key_filename = tmp_path
            .join("private_key.pem")
            .to_str()
            .unwrap()
            .to_owned();
        let export_cert_filename = tmp_path.join("cert.pem").to_str().unwrap().to_owned();
        let export_pkcs12_filename = tmp_path.join("final.p12").to_str().unwrap().to_owned();

        let mut rng = CsRng::from_entropy();
        let key_pair = X25519Keypair::new(&mut rng)?;
        let ca_signer = Ed25519Keypair::new(&mut rng)?;

        // Export public key
        let public_key_as_der = key_pair.to_public_key_der()?;
        let _public_key_as_pem =
            public_key_as_der.to_pem(SubjectPublicKeyInfoRef::PEM_LABEL, LineEnding::LF)?;

        public_key_as_der.write_pem_file(
            export_public_key_filename,
            SubjectPublicKeyInfoRef::PEM_LABEL,
            LineEnding::LF,
        )?;

        // Export certificate
        let certificate = build_certificate::<X25519PublicKey>(
            &ca_signer,
            &key_pair.public_key,
            Profile::Root,
            "My Subject",
            3,
        )?;
        let certificate_string = certificate.to_pem()?;

        std::fs::write(export_cert_filename, &certificate_string).unwrap();

        // Export private key
        let private_key_as_der = key_pair.to_pkcs8_der()?;
        let private_key_as_pem =
            private_key_as_der.to_pem(PrivateKeyInfo::PEM_LABEL, LineEnding::LF)?;

        private_key_as_der.write_pem_file(
            export_private_key_filename,
            PrivateKeyInfo::PEM_LABEL,
            LineEnding::LF,
        )?;

        // Create PKCS12
        const PASSWORD: &str = "secret";

        // Convert to Rust-OpenSSL objects
        let pkey = PKey::private_key_from_pem(private_key_as_pem.as_bytes()).unwrap();
        let cert = X509::from_pem(certificate_string.as_bytes()).unwrap();
        let mut cas = Stack::<X509>::new().unwrap();
        cas.push(cert.clone()).unwrap();

        // Create the PKCS12
        let pkcs12 = openssl::pkcs12::Pkcs12::builder()
            .pkey(&pkey)
            .cert(&cert)
            .ca(cas)
            // .key_algorithm(openssl::nid::Nid::AES_256_GCM)
            .build2(PASSWORD)
            .unwrap();

        // The DER-encoded bytes of the archive
        let der = pkcs12.to_der().unwrap();
        std::fs::write(export_pkcs12_filename, &der).unwrap();

        let pkcs12_parser = openssl::pkcs12::Pkcs12::from_der(&der).unwrap();
        pkcs12_parser.parse2(PASSWORD).unwrap();
        Ok(())
    }
}

// certs/builder.rs

use crate::Error;
use crate::Serilizaton;
use crate::algs::{UniversalKeypair, SignAlgorithm};
use crate::certs::Version;
use crate::certs::certificate::Certificate;
use crate::certs::distinguished_name::DistinguishedName;
use crate::certs::tbs_certificate::TbsCertificate;
use crate::certs::validity::Validity;
use crate::extensions::Extensions;
use crate::highlevel_keys::AlgorithmIdentifier;
use crate::highlevel_keys::privatekey::PrivateKeyInfo;
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct CertificateBuilder {
    version: Version,
    serial_number: u64,
    signature_algorithm: AlgorithmIdentifier,
    validity: Validity,
    subject_public_key_info: SubjectPublicKeyInfo,
    extensions: Option<Extensions>,
    issuer: Option<DistinguishedName>,
    subject: Option<DistinguishedName>,
    certificate: Option<Certificate>,
}

impl CertificateBuilder {
    pub fn new(
        serial_number: u64,
        signature_algorithm: AlgorithmIdentifier,
        subject_public_key_info_der: &[u8],
        not_before: u64,
        not_after: u64,
        extensions: Option<Extensions>,
    ) -> Result<Self, Error> {
        let spki = SubjectPublicKeyInfo::from_der(subject_public_key_info_der)?;

        Ok(Self {
            version: Version::V3,
            serial_number,
            signature_algorithm,
            validity: Validity::new(not_before, not_after),
            subject_public_key_info: spki,
            extensions,
            issuer: None,
            subject: None,
            certificate: None,
        })
    }

    pub fn issuer(&mut self, issuer: DistinguishedName) -> &mut Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn subject(&mut self, subject: DistinguishedName) -> &mut Self {
        self.subject = Some(subject);
        self
    }

    /// Sign the TBS certificate using a PKCS#8 private key DER (PrivateKeyInfo)
    /// The builder already contains the public key (SPKI DER passed to `new`).
    /// After successful sign the built `Certificate` is stored and can be retrieved by `as_struct()`.
    pub fn sign(&mut self, private_key_pkcs8_der: &[u8]) -> Result<(), Error> {
        // Ensure issuer and subject present
        let issuer = self
            .issuer
            .clone()
            .ok_or_else(|| Error::PrivateKeyError("Issuer not set".to_string()))?;
        let subject = self
            .subject
            .clone()
            .ok_or_else(|| Error::PrivateKeyError("Subject not set".to_string()))?;

        // Build TBS
        let tbs = TbsCertificate::new(
            self.version.clone(),
            self.serial_number,
            self.signature_algorithm.clone(),
            issuer.clone(),
            self.validity.clone(),
            subject.clone(),
            self.subject_public_key_info.clone(),
            self.extensions.clone(),
        );

        let tbs_der = tbs.to_der();

        // Parse private key PKCS#8 (PrivateKeyInfo)
        let private_info = PrivateKeyInfo::from_der(private_key_pkcs8_der)?;

        // Determine algorithm from OID
        let algorithm = SignAlgorithm::algorithm_from_oid(
            private_info.private_key_algorithm().algorithm().clone(),
            private_info.private_key_algorithm().parameters().as_ref().and_then(|p| {
                yasna::parse_ber(p, |reader| reader.read_oid()).ok()
            }),
        )?;

        let public_der = self.subject_public_key_info.to_der();

        // Create UniversalKeypair from DER and sign
        let keypair = UniversalKeypair::from_keypair_der(
            private_key_pkcs8_der.to_vec(),
            public_der,
            algorithm,
        )?;

        let signature_value = keypair.sign(&tbs_der)?;

        let cert = Certificate::new(tbs, self.signature_algorithm.clone(), &signature_value);
        self.certificate = Some(cert);

        Ok(())
    }

    pub fn as_struct(&self) -> Option<Certificate> {
        self.certificate.clone()
    }
}

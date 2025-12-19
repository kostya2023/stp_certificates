// certs/builder.rs

use crate::Error;
use crate::algs::AlgKeypair;
use crate::certs::tbs_certificate::TbsCertificate;
use crate::certs::distinguished_name::DistinguishedName;
use crate::certs::validity::Validity;
use crate::certs::Version;
use crate::certs::certificate::Certificate;
use crate::extensions::Extensions;
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;
use crate::highlevel_keys::privatekey::PrivateKeyInfo;
use crate::highlevel_keys::AlgorithmIdentifier;
use std::time::SystemTime;


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
        not_after: SystemTime,
        extensions: Option<Extensions>,
    ) -> Result<Self, Error> {
        let spki = SubjectPublicKeyInfo::from_der(subject_public_key_info_der)?;

        Ok(Self {
            version: Version::V3,
            serial_number,
            signature_algorithm,
            validity: Validity::new(not_after),
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

        let tbs_der = tbs.to_der()?;

        // Parse private key PKCS#8 (PrivateKeyInfo)
        let private_info = PrivateKeyInfo::from_der(private_key_pkcs8_der)?;

        // We'll pick key implementation based on OID found in private_info
        // For each supported algorithm we call its `from_keypair_der(private_der, public_der)`
        // then `sign` the tbs_der.

        let public_der = self.subject_public_key_info.to_der();

        let signature_value = match private_info.private_key_algorithm.algorithm {
            a if a == crate::oid::ED25519.clone() => {
                let kp = crate::algs::eddsa::Ed25519::from_keypair_der(
                    private_key_pkcs8_der.to_vec(),
                    public_der.clone(),
                )?;
                kp.sign(&tbs_der)?
            }
            a if a == crate::oid::FNDSA_512.clone() => {
                let kp = crate::algs::fndsa::FNDSA512Keypair::from_keypair_der(
                    private_key_pkcs8_der.to_vec(),
                    public_der.clone(),
                )?;
                kp.sign(&tbs_der)?
            }
            a if a == crate::oid::FNDSA_1024.clone() => {
                let kp = crate::algs::fndsa::FNDSA1024Keypair::from_keypair_der(
                    private_key_pkcs8_der.to_vec(),
                    public_der.clone(),
                )?;
                kp.sign(&tbs_der)?
            }
            a if a == crate::oid::MLDSA_44.clone() => {
                let kp = crate::algs::mldsa::MLDSA44Keypair::from_keypair_der(
                    private_key_pkcs8_der.to_vec(),
                    public_der.clone(),
                )?;
                kp.sign(&tbs_der)?
            }
            a if a == crate::oid::MLDSA_65.clone() => {
                let kp = crate::algs::mldsa::MLDSA65Keypair::from_keypair_der(
                    private_key_pkcs8_der.to_vec(),
                    public_der.clone(),
                )?;
                kp.sign(&tbs_der)?
            }
            a if a == crate::oid::MLDSA_87.clone() => {
                let kp = crate::algs::mldsa::MLDSA87Keypair::from_keypair_der(
                    private_key_pkcs8_der.to_vec(),
                    public_der.clone(),
                )?;
                kp.sign(&tbs_der)?
            }
            a if a == crate::oid::SLHDSA_128F.clone() => {
                // try SHA2 implementation first, fallback to SHAKE
                let try_sha2 = crate::algs::slh_dsa_sha2::SLHDSA128FKeypair::from_keypair_der(
                    private_key_pkcs8_der.to_vec(),
                    public_der.clone(),
                );
                match try_sha2 {
                    Ok(kp) => kp.sign(&tbs_der)?,
                    Err(_) => {
                        let kp = crate::algs::slh_dsa_shake::SLHDSA128FKeypair::from_keypair_der(
                            private_key_pkcs8_der.to_vec(),
                            public_der.clone(),
                        )?;
                        kp.sign(&tbs_der)?
                    }
                }
            }
            a if a == crate::oid::SLHDSA_192F.clone() => {
                let try_sha2 = crate::algs::slh_dsa_sha2::SLHDSA192FKeypair::from_keypair_der(
                    private_key_pkcs8_der.to_vec(),
                    public_der.clone(),
                );
                match try_sha2 {
                    Ok(kp) => kp.sign(&tbs_der)?,
                    Err(_) => {
                        let kp = crate::algs::slh_dsa_shake::SLHDSA192FKeypair::from_keypair_der(
                            private_key_pkcs8_der.to_vec(),
                            public_der.clone(),
                        )?;
                        kp.sign(&tbs_der)?
                    }
                }
            }
            a if a == crate::oid::SLHDSA_256F.clone() => {
                let try_sha2 = crate::algs::slh_dsa_sha2::SLHDSA256FKeypair::from_keypair_der(
                    private_key_pkcs8_der.to_vec(),
                    public_der.clone(),
                );
                match try_sha2 {
                    Ok(kp) => kp.sign(&tbs_der)?,
                    Err(_) => {
                        let kp = crate::algs::slh_dsa_shake::SLHDSA256FKeypair::from_keypair_der(
                            private_key_pkcs8_der.to_vec(),
                            public_der.clone(),
                        )?;
                        kp.sign(&tbs_der)?
                    }
                }
            }
            _ => {
                return Err(Error::UnknownOID(format!(
                    "Unsupported signing algorithm: {:?}",
                    private_info.private_key_algorithm.algorithm
                )));
            }
        };

        let cert = Certificate::new(tbs, self.signature_algorithm.clone(), &signature_value);
        self.certificate = Some(cert);

        Ok(())
    }

    pub fn as_struct(&self) -> Option<Certificate> {
        self.certificate.clone()
    }
}

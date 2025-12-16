// certs/tbs_certificate.rs

use crate::Error;
use crate::certs::{Version, distinguished_name::DistinguishedName, validity::Validity};
use crate::extensions::Extensions;
use crate::highlevel_keys::AlgorithmIdentifier;
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;
use yasna;

pub struct TbsCertificate {
    version: Version,
    serial_number: u64,
    signature: AlgorithmIdentifier,
    issuer: DistinguishedName,
    validity: Validity,
    subject: DistinguishedName,
    subject_public_key_info: SubjectPublicKeyInfo,
    extensions: Option<Extensions>,
}

impl TbsCertificate {
    pub fn new(
        version: Version,
        serial_number: u64,
        signature: AlgorithmIdentifier,
        issuer: DistinguishedName,
        validity: Validity,
        subject: DistinguishedName,
        subject_public_key_info: SubjectPublicKeyInfo,
        extensions: Option<Extensions>,
    ) -> Self {
        Self {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions,
        }
    }

    pub fn version(&self) -> Version {
        self.version.clone()
    }

    pub fn serial_number(&self) -> u64 {
        self.serial_number.clone()
    }

    pub fn signature(&self) -> AlgorithmIdentifier {
        self.signature.clone()
    }

    pub fn issuer(&self) -> DistinguishedName {
        self.issuer.clone()
    }

    pub fn validity(&self) -> Validity {
        self.validity.clone()
    }

    pub fn subject(&self) -> DistinguishedName {
        self.subject.clone()
    }

    pub fn subject_public_key_info(&self) -> SubjectPublicKeyInfo {
        self.subject_public_key_info.clone()
    }

    pub fn extensions(&self) -> Option<Extensions> {
        self.extensions.clone()
    }
}

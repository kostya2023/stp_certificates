// certs/tbs_certificate.rs

use crate::certs::{Version, distinguished_name::DistinguishedName, validity::Validity};
use crate::extensions::Extensions;
use crate::highlevel_keys::AlgorithmIdentifier;
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;
use crate::{Error, Serilizaton};
use yasna;
use yasna::ASN1ErrorKind;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
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
        self.serial_number
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

// Serilizaton
impl Serilizaton for TbsCertificate {
    fn to_der(&self) -> Vec<u8> {
        let validity_der = self.validity.to_der();
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_tagged(yasna::Tag::context(0), |tagged| {
                    tagged.write_i64(self.version.number().clone());
                });

                seq.next().write_u64(self.serial_number.clone());

                seq.next().write_der(&self.signature.to_der());

                seq.next().write_der(&self.issuer.to_der());

                seq.next().write_der(&validity_der);

                seq.next().write_der(&self.subject.to_der());

                seq.next().write_der(&self.subject_public_key_info.to_der());

                if let Some(ext) = &self.extensions {
                    seq.next().write_tagged(yasna::Tag::context(3), |tagged| {
                        tagged.write_der(&ext.to_der());
                    });
                }
            })
        })
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let result = yasna::parse_der(&der, |reader| {
            let result = reader.read_sequence(|seq| {
                let version = seq.next().read_tagged(yasna::Tag::context(0), |tagged| {
                    let version = tagged.read_i64()?;
                    Ok(version)
                })?;

                let serial_number = seq.next().read_u64()?;

                let signature = seq.next().read_der()?;

                let issuer = seq.next().read_der()?;

                let validity = seq.next().read_der()?;

                let subject = seq.next().read_der()?;

                let spki = seq.next().read_der()?;

                let extensions: Option<Extensions> =
                    match seq.next().read_tagged(yasna::Tag::context(3), |tagged| {
                        let ext_der = tagged.read_der()?;
                        Extensions::from_der(&ext_der)
                            .map_err(|_| yasna::ASN1Error::new(ASN1ErrorKind::Invalid))
                    }) {
                        Ok(ext) => Some(ext),
                        Err(_) => None,
                    };
                Ok((
                    version,
                    serial_number,
                    signature,
                    issuer,
                    validity,
                    subject,
                    spki,
                    extensions,
                ))
            })?;
            Ok(result)
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;

        let version = Version::from_number(result.0)?;

        let serial_number = result.1;

        let signature = AlgorithmIdentifier::from_der(result.2.as_slice())?;

        let issuer = DistinguishedName::from_der(result.3.as_slice())?;

        let validity = Validity::from_der(result.4.as_slice())?;

        let subject = DistinguishedName::from_der(result.5.as_slice())?;

        let subject_public_key_info = SubjectPublicKeyInfo::from_der(result.6.as_slice())?;

        let extensions = result.7;

        Ok(Self {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions,
        })
    }
}

// highlevel_keys/publickey.rs

use crate::{ASN1Wrapper, Error, highlevel_keys::AlgorithmIdentifier};
use yasna::{ASN1Error, ASN1ErrorKind};

#[derive(Debug, Clone)]
pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: Vec<u8>,
}

impl SubjectPublicKeyInfo {
    pub fn new(algorithm: AlgorithmIdentifier, subject_public_key: &[u8]) -> Self {
        Self {
            algorithm,
            subject_public_key: subject_public_key.to_vec(),
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_der(&self.algorithm.to_der().as_slice());
                seq.next().write_bitvec_bytes(
                    &self.subject_public_key,
                    self.subject_public_key.len() * 8,
                );
            })
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let info = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq| {
                let alg_der = seq.next().read_der()?;
                let algorithm = AlgorithmIdentifier::from_der(&alg_der)
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;

                let (subject_public_key, _) = seq
                    .next()
                    .read_bitvec_bytes()
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;

                Ok(Self {
                    algorithm,
                    subject_public_key,
                })
            })
        })
        .map_err(|e| Error::ASN1Error(ASN1Wrapper(e)))?;

        Ok(info)
    }
}

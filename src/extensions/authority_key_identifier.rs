// extensions/authority_key_identifier.rs

use crate::{Error, Serilizaton};
use yasna;
use yasna::models::ObjectIdentifier;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct AuthorityKeyIdentifier {
    hash_algorithm: ObjectIdentifier,
    key_identifier: Vec<u8>,
}

impl AuthorityKeyIdentifier {
    pub fn new(hash_algorithm: ObjectIdentifier, key_identifier: Vec<u8>) -> Self {
        Self {
            hash_algorithm,
            key_identifier,
        }
    }

    pub fn hash_algorithm(&self) -> ObjectIdentifier {
        self.hash_algorithm.clone()
    }

    pub fn key_identifier(&self) -> Vec<u8> {
        self.key_identifier.clone()
    }
}

impl Serilizaton for AuthorityKeyIdentifier {
    fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_oid(&self.hash_algorithm);
                seq.next().write_bytes(&self.key_identifier);
            })
        })
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let result = yasna::parse_der(&der, |reader| {
            reader.read_sequence(|seq_reader| {
                let hi = seq_reader.next().read_oid()?;
                let ki = seq_reader.next().read_bytes()?;
                Ok((hi, ki))
            })
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;
        Ok(Self {
            hash_algorithm: result.0,
            key_identifier: result.1,
        })
    }
}

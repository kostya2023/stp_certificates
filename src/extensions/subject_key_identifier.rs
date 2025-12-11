// extensions/subject_key_identifier.rs

use crate::Error;
use crate::extensions::ExtensionTrait;
use yasna;

pub struct SubjectKeyIdentifier {
    key_identifier: Vec<u8>,
}

impl SubjectKeyIdentifier {
    pub fn new(key_identifier: Vec<u8>) -> Self {
        Self { key_identifier }
    }

    pub fn key_identifier(&self) -> Vec<u8> {
        self.key_identifier.clone()
    }
}

impl ExtensionTrait for SubjectKeyIdentifier {
    fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_bytes(&self.key_identifier.as_slice());
            })
        })
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let result = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq_read| {
                let ki = seq_read.next().read_bytes()?;
                Ok(ki)
            })
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;
        Ok(Self {
            key_identifier: result,
        })
    }
}

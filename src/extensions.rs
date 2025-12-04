// extensions.rs

use yasna::{ASN1Error, ASN1ErrorKind, models::ObjectIdentifier};

use crate::{ASN1Wrapper, Error};

pub struct Extension {
    pub extn_id: ObjectIdentifier,
    pub critical: bool,
    pub extn_value: Vec<u8>, // OCTET STRING
}

pub struct Extensions {
    pub extensions: Vec<Extension>,
}

impl Extension {
    pub fn new(extn_id: ObjectIdentifier, critical: bool, extn_value: Vec<u8>) -> Self {
        Self {
            extn_id,
            critical,
            extn_value,
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_oid(&self.extn_id);
                seq.next().write_bool(self.critical);
                seq.next().write_bytes(&self.extn_value);
            })
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let extension = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq_read| {
                let extn_id = seq_read
                    .next()
                    .read_oid()
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                let critical = seq_read
                    .next()
                    .read_bool()
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                let extn_value = seq_read
                    .next()
                    .read_bytes()
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                Ok(Self {
                    extn_id,
                    critical,
                    extn_value,
                })
            })
        })
        .map_err(|e| Error::ASN1Error(ASN1Wrapper(e)))?;
        Ok(extension)
    }
}

// certs/mod.rs

pub mod distinguished_name;
pub mod generate;
pub mod tbs_certificate;
pub mod validity;
pub mod verify;

use yasna;
use yasna::DERWriterSeq;
use yasna::models::ObjectIdentifier;

use crate::Error;

#[derive(Debug, Clone)]
pub enum Version {
    V3,
}

impl Version {
    pub fn number(&self) -> i64 {
        match self {
            Version::V3 => 2,
        }
    }

    pub fn from_number(number: i64) -> Result<Self, Error> {
        match number {
            2 => Ok(Version::V3),
            _ => Err(Error::VersionParsingError),
        }
    }
}

pub fn write_secific(seq: &mut DERWriterSeq<'_>, oid: ObjectIdentifier, value: &str) {
    seq.next().write_sequence(|s| {
        s.next().write_oid(&oid);
        s.next().write_utf8string(value);
    });
}

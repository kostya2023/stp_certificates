// certs/mod.rs

pub mod distinguished_name;
pub mod generate;
pub mod tbs_certificate;
pub mod validity;
pub mod verify;

use yasna;
use yasna::DERWriterSeq;
use yasna::models::ObjectIdentifier;

#[derive(Debug, Clone)]
pub enum Version {
    V3,
}

impl Version {
    pub fn number(version: Version) -> u64 {
        match version {
            Version::V3 => 2,
        }
    }
}

pub fn write_secific(seq: &mut DERWriterSeq<'_>, oid: ObjectIdentifier, value: &str) {
    seq.next().write_sequence(|s| {
        s.next().write_oid(&oid);
        s.next().write_utf8string(value);
    });
}

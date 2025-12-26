// certs/validity.rs

use crate::{Error, Serilizaton};
use yasna;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct Validity {
    not_before: u64,
    not_after: u64,
}

impl Validity {
    pub fn new(not_before: u64, not_after: u64) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    pub fn check_expired(&self, now: u64) -> Result<bool, Error> {
        if now < self.not_before || now > self.not_after {
            return Err(Error::CheckExpiredError("Validity time".to_string()));
        }

        Ok(true)
    }
}

// Serilization
impl Serilizaton for Validity {
    fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_u64(self.not_before);
                seq.next().write_u64(self.not_after);
            })
        })
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let (not_before, not_after) = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq| {
                let nb = seq.next().read_u64()?;
                let na = seq.next().read_u64()?;
                Ok((nb, na))
            })
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;

        Ok(Self {
            not_before,
            not_after,
        })
    }
}

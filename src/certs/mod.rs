use std::time::{SystemTime, UNIX_EPOCH};

use crate::Error;

pub mod generate;
pub mod verify;

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

pub struct Validity {
    not_before: SystemTime,
    not_after: SystemTime,
}

impl Validity {
    pub fn new(not_after: SystemTime) -> Self {
        let not_before = SystemTime::now();
        Self { not_before, not_after }
    }

    pub fn not_before(&self) -> SystemTime {
        self.not_before.clone()
    }

    pub fn not_after(&self) -> SystemTime {
        self.not_after.clone()
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let not_bfr = self.not_before.duration_since(UNIX_EPOCH).map_err(|_| Error::DurationSinceError)?.as_secs() as i64;
        let not_ftr = self.not_after.duration_since(UNIX_EPOCH).map_err(|_| Error::DurationSinceError)?.as_secs() as i64;
        let result = yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_i64(not_bfr);
                seq.next().write_i64(not_ftr);
            })
        });
        Ok(result)
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let (not_before_secs, not_after_secs) = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq| {
                let nb = seq.next().read_i64()?;
                let na = seq.next().read_i64()?;
                Ok((nb, na))
            })
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;

        let not_before = UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(not_before_secs as u64))
            .ok_or(Error::DurationSinceError)?;

        let not_after = UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(not_after_secs as u64))
            .ok_or(Error::DurationSinceError)?;

        Ok(Self {
            not_before,
            not_after,
        })
    }

    pub fn check_expired(&self, now: SystemTime) -> Result<bool, Error> {
        if now < self.not_before || now > self.not_after {
            return Err(Error::CheckExpiredError("Validity time".to_string()));
        }

        Ok(true)
    }
}

// extensions/crl_distribution_points.rs

use crate::{Error, Serilizaton};
use yasna;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct CRLDistributionPoints {
    uri: String,
}

impl CRLDistributionPoints {
    pub fn new(uri: &str) -> Self {
        Self {
            uri: uri.to_string(),
        }
    }

    pub fn uri(&self) -> String {
        self.uri.clone()
    }
}

impl Serilizaton for CRLDistributionPoints {
    fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_utf8_string(&self.uri);
            })
        })
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let result = yasna::parse_der(&der, |reader| {
            reader.read_sequence(|seq_reader| {
                let uri = seq_reader.next().read_utf8string()?;
                Ok(uri)
            })
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;
        Ok(Self { uri: result })
    }
}

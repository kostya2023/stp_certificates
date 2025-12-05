// extensions/basic_constraints.rs

use crate::extensions::ExtensionTrait;
use yasna;
use crate::Error;

pub struct BasicConstraints {
    ca: bool,
    path_len_constraint: Option<u64>,
}

impl BasicConstraints {
    pub fn new(ca: bool, path_len_constraint: Option<u64>) -> Self {
        Self { ca, path_len_constraint }
    }

    pub fn is_ca(&self) -> bool {
        self.ca
    }

    pub fn path_len_constraint(&self) -> Option<u64> {
        self.path_len_constraint
    }
}

impl ExtensionTrait for BasicConstraints {
    fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_bool(self.ca);
                if let Some(len) = self.path_len_constraint {
                    seq.next().write_u64(len);
                }
            })
        })
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let result = yasna::parse_der(&der, |reader| {
            reader.read_sequence(|seq_read| {
                let ca = seq_read.next().read_bool()?;
                let len = seq_read.read_optional(|read_option| {
                    let len2 = read_option.read_u64()?;
                    Ok(len2)
                })?;
                Ok((ca, len))
            })
        }).map_err(|e| crate::Error::ASN1Error(crate::ASN1Wrapper(e)))?;
        Ok(BasicConstraints { ca: result.0, path_len_constraint: result.1})
    }
}

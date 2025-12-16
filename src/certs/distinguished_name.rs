// certs/distinguished_name.rs

use crate::{Error, certs::write_secific};
use yasna;

pub struct DistinguishedName {
    common_name: String,
    country: Option<String>,
    state_or_province: Option<String>,
    locallity: Option<String>,
    organization: Option<String>,
    organization_unit: Option<String>,
    street_addres: Option<String>,
    serial_number: Option<String>,
}

impl DistinguishedName {
    pub fn new(
        common_name: String,
        country: Option<String>,
        state_or_province: Option<String>,
        locallity: Option<String>,
        organization: Option<String>,
        organization_unit: Option<String>,
        street_addres: Option<String>,
        serial_number: Option<String>,
    ) -> Self {
        Self {
            common_name,
            country,
            state_or_province,
            locallity,
            organization,
            organization_unit,
            street_addres,
            serial_number,
        }
    }

    pub fn common_name(&self) -> String {
        self.common_name.clone()
    }

    pub fn country(&self) -> Option<String> {
        self.country.clone()
    }

    pub fn state_or_province(&self) -> Option<String> {
        self.state_or_province.clone()
    }

    pub fn locallity(&self) -> Option<String> {
        self.locallity.clone()
    }

    pub fn organization(&self) -> Option<String> {
        self.organization.clone()
    }

    pub fn organization_unit(&self) -> Option<String> {
        self.organization_unit.clone()
    }

    pub fn street_addres(&self) -> Option<String> {
        self.street_addres.clone()
    }

    pub fn serial_number(&self) -> Option<String> {
        self.serial_number.clone()
    }
}

// Serilizaton
impl DistinguishedName {
    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence_of(|seq_of| {
                write_secific(seq_of, crate::oid::COMMON_NAME.clone(), &self.common_name);
                if let Some(con) = &self.country {
                    write_secific(seq_of, crate::oid::COUNTRY.clone(), &con);
                }
                if let Some(sop) = &self.state_or_province {
                    write_secific(seq_of, crate::oid::STATE.clone(), &sop);
                }
                if let Some(loc) = &self.locallity {
                    write_secific(seq_of, crate::oid::LOCALITY.clone(), &loc);
                }
                if let Some(org) = &self.organization {
                    write_secific(seq_of, crate::oid::ORGANIZATION.clone(), &org);
                }
                if let Some(oru) = &self.organization_unit {
                    write_secific(seq_of, crate::oid::ORG_UNIT.clone(), &oru);
                }
                if let Some(sta) = &self.street_addres {
                    write_secific(seq_of, crate::oid::STREET.clone(), &sta);
                }
                if let Some(snu) = &self.serial_number {
                    write_secific(seq_of, crate::oid::SERIAL_NUMBER.clone(), &snu);
                }
            })
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let result = yasna::parse_der(der, |reader| {
            let pairs = reader.collect_sequence_of(|seq_read| {
                seq_read.read_sequence(|seq| {
                    let oid = seq.next().read_oid()?;
                    let val = seq.next().read_utf8string()?;
                    Ok((oid, val.to_owned()))
                })
            })?;

            Ok(pairs)
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;

        let mut dn = DistinguishedName {
            common_name: String::new(),
            country: None,
            state_or_province: None,
            locallity: None,
            organization: None,
            organization_unit: None,
            street_addres: None,
            serial_number: None,
        };

        for (oid, val) in result {
            match oid {
                o if o == *crate::oid::COMMON_NAME => dn.common_name = val,
                o if o == *crate::oid::STATE => dn.state_or_province = Some(val),
                o if o == *crate::oid::LOCALITY => dn.locallity = Some(val),
                o if o == *crate::oid::COUNTRY => dn.country = Some(val),
                o if o == *crate::oid::ORGANIZATION => dn.organization = Some(val),
                o if o == *crate::oid::ORG_UNIT => dn.organization_unit = Some(val),
                o if o == *crate::oid::STREET => dn.street_addres = Some(val),
                o if o == *crate::oid::SERIAL_NUMBER => dn.serial_number = Some(val),
                o => return Err(Error::UnknownOID(o.to_string())),
            }
        }

        Ok(dn)
    }
}

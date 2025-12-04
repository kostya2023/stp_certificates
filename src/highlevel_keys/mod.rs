// mod.rs
pub mod pem;
pub mod privatekey;
pub mod publickey;

use crate::{ASN1Wrapper, Error};
use yasna::models::ObjectIdentifier;
use yasna::{ASN1Error, ASN1ErrorKind};

#[derive(Debug, Clone)]
pub struct AttributeValue {
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub attr_type: ObjectIdentifier,
    pub attr_val: Vec<AttributeValue>,
}

impl AttributeValue {
    pub fn new(attr_data: &[u8]) -> Self {
        Self {
            value: attr_data.to_vec(),
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_bytes(&self.value);
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let val = yasna::parse_der(der, |reader| {
            let bytes = reader
                .read_bytes()
                .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
            Ok(bytes)
        })
        .map_err(|e| Error::ASN1Error(ASN1Wrapper(e)))?;
        Ok(Self { value: val })
    }
}

impl Attribute {
    pub fn new(attr_type: ObjectIdentifier, attr_val: &[AttributeValue]) -> Self {
        Self {
            attr_type,
            attr_val: attr_val.to_vec(),
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_oid(&self.attr_type);
                seq.next().write_set_of(|set| {
                    for val in &self.attr_val {
                        set.next().write_bytes(&val.to_der());
                    }
                });
            })
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let attr = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq| {
                let attr_type = seq
                    .next()
                    .read_oid()
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                let attr_val = seq
                    .next()
                    .collect_set_of(|set| {
                        let val_der = set
                            .read_bytes()
                            .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                        Ok(AttributeValue::from_der(&val_der)
                            .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?)
                    })
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                Ok(Attribute {
                    attr_type,
                    attr_val,
                })
            })
        })
        .map_err(|e| Error::ASN1Error(ASN1Wrapper(e)))?;
        Ok(attr)
    }
}

#[derive(Debug, Clone)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Vec<u8>>,
}

impl AlgorithmIdentifier {
    pub fn new(algorithm: ObjectIdentifier, parameters: Option<Vec<u8>>) -> Self {
        Self {
            algorithm,
            parameters,
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|der| {
            der.write_sequence(|seq| {
                seq.next().write_oid(&self.algorithm);
                if let Some(ref params) = self.parameters {
                    seq.next().write_der(params);
                }
            })
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let alg = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq| {
                let algorithm = seq
                    .next()
                    .read_oid()
                    .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                let parameters = match seq.next().read_der() {
                    Ok(der) => Some(der),
                    Err(_) => None,
                };
                Ok(AlgorithmIdentifier {
                    algorithm,
                    parameters,
                })
            })
        })
        .map_err(|e| Error::ASN1Error(ASN1Wrapper(e)))?;
        Ok(alg)
    }
}

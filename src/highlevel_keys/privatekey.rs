// good_api/privatekey.rs

use crate::{
    Error,
    highlevel_keys::{AlgorithmIdentifier, Attribute},
};

pub struct PrivateKeyInfo {
    pub version: u64,
    pub private_key_algorithm: AlgorithmIdentifier,
    pub private_key: Vec<u8>,
    pub attributes: Option<Vec<Attribute>>,
}

impl PrivateKeyInfo {
    pub fn new(
        version: u64,
        privatekey_alg: AlgorithmIdentifier,
        privatekey: &[u8],
        attrbutes: Option<Vec<Attribute>>,
    ) -> Self {
        Self {
            version,
            private_key_algorithm: privatekey_alg,
            private_key: privatekey.to_vec(),
            attributes: attrbutes,
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|der| {
            der.write_sequence(|seq| {
                seq.next().write_u64(self.version.clone());
                seq.next()
                    .write_der(&self.private_key_algorithm.to_der().as_slice());
                seq.next().write_bytes(&self.private_key.as_slice());

                if let Some(attrs) = &self.attributes {
                    seq.next().write_tagged(yasna::Tag::context(0), |writer| {
                        writer.write_set_of(|set| {
                            for attr in attrs {
                                set.next().write_der(&attr.to_der());
                            }
                        });
                    });
                }
            })
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let info = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq| {
                let version = seq.next().read_u64()?;
                let alg_der = seq.next().read_der()?;
                let private_key_algorithm = AlgorithmIdentifier::from_der(&alg_der)
                    .map_err(|_| yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid))?;
                let private_key = seq.next().read_bytes()?;

                let attributes =
                    match seq
                        .next()
                        .read_tagged_implicit(yasna::Tag::context(0), |reader| {
                            reader.collect_set_of(|set| {
                                let der = set.read_der()?;
                                Ok(Attribute::from_der(&der).map_err(|_| {
                                    yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid)
                                })?)
                            })
                        }) {
                        Ok(attrs) => Some(attrs),
                        Err(_) => None,
                    };

                Ok(Self {
                    version,
                    private_key_algorithm,
                    private_key,
                    attributes,
                })
            })
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;

        Ok(info)
    }
}

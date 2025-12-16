// extensions/key_usage.rs

use crate::Error;
use crate::extensions::ExtensionTrait;
use yasna;

#[derive(Debug, Clone)]
pub struct KeyUsage {
    digital_signature: bool,
    key_cert_sign: bool,
    crl_sign: bool,
}

impl KeyUsage {
    pub fn new(digital_signature: bool, key_cert_sign: bool, crl_sign: bool) -> Self {
        return KeyUsage {
            digital_signature,
            key_cert_sign,
            crl_sign,
        };
    }

    pub fn is_digital_signature(&self) -> bool {
        self.digital_signature
    }

    pub fn is_key_cert_sign(&self) -> bool {
        self.key_cert_sign
    }

    pub fn is_crl_sign(&self) -> bool {
        self.crl_sign
    }
}

impl ExtensionTrait for KeyUsage {
    fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_bool(self.digital_signature);
                seq.next().write_bool(self.key_cert_sign);
                seq.next().write_bool(self.crl_sign);
            })
        })
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let result = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq_read| {
                let ds = seq_read.next().read_bool()?;
                let kcs = seq_read.next().read_bool()?;
                let cs = seq_read.next().read_bool()?;
                Ok((ds, kcs, cs))
            })
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;
        Ok(Self {
            digital_signature: result.0,
            key_cert_sign: result.1,
            crl_sign: result.2,
        })
    }
}

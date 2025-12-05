// extensions/extended_key_usage.rs

use crate::Error;
use crate::extensions::ExtensionTrait;
use yasna;

pub struct ExtendedKeyUsage {
    server_auth: bool,
    client_auth: bool,
    code_signing: bool,
    ocsp_signing: bool,
}

impl ExtendedKeyUsage {
    pub fn new(
        server_auth: bool,
        client_auth: bool,
        code_signing: bool,
        ocsp_signing: bool,
    ) -> Self {
        Self {
            server_auth,
            client_auth,
            code_signing,
            ocsp_signing,
        }
    }

    pub fn is_server_auth(&self) -> bool {
        self.server_auth
    }

    pub fn is_client_auth(&self) -> bool {
        self.client_auth
    }

    pub fn is_code_signing(&self) -> bool {
        self.code_signing
    }

    pub fn is_ocsp_signing(&self) -> bool {
        self.ocsp_signing
    }
}

impl ExtensionTrait for ExtendedKeyUsage {
    fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_bool(self.server_auth);
                seq.next().write_bool(self.client_auth);
                seq.next().write_bool(self.code_signing);
                seq.next().write_bool(self.ocsp_signing);
            });
        })
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let result = yasna::parse_der(der, |reader| {
            reader.read_sequence(|seq_read| {
                let sa = seq_read.next().read_bool()?;
                let clia = seq_read.next().read_bool()?;
                let coda = seq_read.next().read_bool()?;
                let oa = seq_read.next().read_bool()?;
                Ok((sa, clia, coda, oa))
            })
        })
        .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;
        Ok(Self {
            server_auth: result.0,
            client_auth: result.1,
            code_signing: result.2,
            ocsp_signing: result.3,
        })
    }
}

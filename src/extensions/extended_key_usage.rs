// extensions/extended_key_usage.rs

use yasna;
use crate::Error;
use crate::extensions::ExtensionTrait;

pub struct ExtendedKeyUsage {
    server_auth: bool,
    client_auth: bool,
    code_signing: bool,
    ocsp_signing: bool,
}

impl ExtendedKeyUsage {
    pub fn new(server_auth: bool, client_auth: bool, code_signing: bool, ocsp_signing: bool) -> Self {
        Self { server_auth, client_auth, code_signing, ocsp_signing }
    }
}
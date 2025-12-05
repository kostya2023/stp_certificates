// extensions/key_usage.rs

use yasna;
use crate::Error;
use crate::extensions::ExtensionTrait;


pub struct KeyUsage {
    digital_signature: bool,
    key_cert_sign: bool,
    crl_sign: bool
}

impl KeyUsage {
    pub fn new(digital_signature: bool, key_cert_sign: bool, crl_sign: bool) -> Self {
        return KeyUsage { digital_signature, key_cert_sign, crl_sign }
    }
}

// impl ExtensionTrait for KeyUsage {

// }
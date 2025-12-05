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

    pub fn is_digital_signature(&self) -> bool {
        self.digital_signature
    }

    pub fn is_key_cert_sign(&self) -> bool {
        self.key_cert_sign
    }

}

// impl ExtensionTrait for KeyUsage {

// }
// extensions/key_usage.rs

use yasna;
use crate::Error;
use crate::extensions::ExtensionTrait;


pub struct KeyUsage {
    digital_signature: bool,
    key_cert_sign: bool,
    crl_sign: bool
}


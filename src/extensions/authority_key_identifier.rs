// extensions/authority_key_identifier.rs

use crate::Error;
use crate::extensions::ExtensionTrait;
use yasna;
use yasna::models::ObjectIdentifier;

pub struct AuthorityKeyIdentifier {
    hash_algorithm: ObjectIdentifier,
    key_identifier: Vec<u8>,
}


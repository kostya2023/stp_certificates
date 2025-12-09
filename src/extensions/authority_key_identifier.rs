// extensions/authority_key_identifier.rs

use crate::Error;
use crate::extensions::ExtensionTrait;
use yasna;
use yasna::models::ObjectIdentifier;

pub struct AuthorityKeyIdentifier {
    hash_algorithm: ObjectIdentifier,
    key_identifier: Vec<u8>,
}

impl AuthorityKeyIdentifier {
    pub fn new(hash_algorithm: ObjectIdentifier, key_identifier: Vec<u8>) -> Self {
        Self { hash_algorithm, key_identifier }
    }

    pub fn hash_algorithm(&self) -> ObjectIdentifier {
        self.hash_algorithm.clone()
    }

    pub fn key_identifier(&self) -> Vec<u8> {
        self.key_identifier.clone()
    }
}
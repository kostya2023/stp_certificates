// extensions/subject_alternative_name.rs

use crate::Error;
use crate::extensions::ExtensionTrait;
use yasna;
use std::net::IpAddr;

/// X.509 GeneralName (RFC 5280, §4.2.1.6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralName {
    OtherName(String),            // [0]  OtherName
    RFC822Name(String),           // [1]  IA5String  (email)
    DNSName(String),              // [2]  IA5String
    DirectoryName(String),        // [4]  Name
    URI(String),                  // [6]  IA5String
    IPAddress(IpAddr),            // [7]  OCTET STRING (IPv4/IPv6)
    RegisteredID(String),         // [8]  OBJECT IDENTIFIER
}

/// X.509 SubjectAlternativeName ::= SEQUENCE OF GeneralName
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectAlternativeName {
    pub names: Vec<GeneralName>,
}

impl SubjectAlternativeName {
    pub fn new(names: Vec<GeneralName>) -> Self {
        SubjectAlternativeName { names }
    }

    pub fn add(&mut self, name: GeneralName) {
        self.names.push(name);
    }
}



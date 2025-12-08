// extensions/subject_alternative_name.rs

use crate::Error;
use crate::extensions::ExtensionTrait;
use yasna;

pub struct SubjectAlternativeName {
    dns_name: String,
    // ip_address: 
}
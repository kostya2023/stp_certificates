// certs/certificate.rs

use crate::{Error, certs::tbs_certificate::TbsCertificate, highlevel_keys::AlgorithmIdentifier};

#[derive(Debug, Clone)]
pub struct Certificate {
    tbs_certificate: TbsCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: Vec<u8>,
}
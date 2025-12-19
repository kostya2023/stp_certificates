// certs/certificate.rs

use crate::{Error, certs::tbs_certificate::TbsCertificate, highlevel_keys::AlgorithmIdentifier};

#[derive(Debug, Clone)]
pub struct Certificate {
    tbs_certificate: TbsCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: Vec<u8>,
}

impl Certificate {
    pub fn new(
        tbs_certificate: TbsCertificate,
        signature_algorithm: AlgorithmIdentifier,
        signature_value: &[u8]
    ) -> Self {
        Self { tbs_certificate, signature_algorithm, signature_value: signature_value.to_vec() }
    }

    pub fn tbs_certificate(&self) -> TbsCertificate {
        self.tbs_certificate.clone()
    }

    pub fn signature_algorithm(&self) -> AlgorithmIdentifier {
        self.signature_algorithm.clone()
    }

    pub fn signature_value(&self) -> Vec<u8> {
        self.signature_value.clone()
    }
}



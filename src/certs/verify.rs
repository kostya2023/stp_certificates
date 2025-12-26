// certs/verify.rs

use crate::Serilizaton;
use crate::{Error, certs::certificate::Certificate};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct Verifier {}

impl Verifier {
    pub fn check_certificate_singature(
        certificate: &Certificate,
        verifying_key: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        let tbs_certificate = certificate.tbs_certificate();
        let tbs_cert_algorithm = tbs_certificate.signature();
        let der_tbs = tbs_certificate.to_der();

        let algorithm = certificate.signature_algorithm();

        todo!()
    }
}

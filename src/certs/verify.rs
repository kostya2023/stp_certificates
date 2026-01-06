// certs/verify.rs

use crate::Serilizaton;
use crate::{Error, certs::certificate::Certificate};
use crate::algs::{UniversalKeypair, SignAlgorithm};
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct Verifier {}

impl Verifier {
    pub fn check_certificate_singature(
        certificate: &Certificate,
        verifying_key: &[u8],
        _now: u64,
    ) -> Result<(), Error> {
        let tbs_certificate = certificate.tbs_certificate();
        let tbs_cert_algorithm = tbs_certificate.signature();
        let der_tbs = tbs_certificate.to_der();

        let algorithm = certificate.signature_algorithm();

        if algorithm != tbs_cert_algorithm {
            return Err(Error::InvalidAlgorithmError);
        }

        // Parse the public key SPKI to determine algorithm
        let spki = SubjectPublicKeyInfo::from_der(verifying_key)?;
        let alg = SignAlgorithm::algorithm_from_oid(
            spki.algorithm().algorithm().clone(),
            spki.algorithm().parameters().as_ref().and_then(|p| {
                yasna::parse_ber(p, |reader| reader.read_oid()).ok()
            }),
        )?;

        // Create UniversalKeypair from public key and verify signature
        let keypair = UniversalKeypair::from_keypair_der(
            vec![], // empty private key for verification
            verifying_key.to_vec(),
            alg,
        )?;

        let is_valid = keypair.verify(&der_tbs, &certificate.signature_value())?;

        if is_valid {
            Ok(())
        } else {
            Err(Error::VerifySignatureError("Signature verification failed".to_string()))
        }
    }
}

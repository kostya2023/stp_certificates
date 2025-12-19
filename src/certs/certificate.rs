// certs/certificate.rs

use crate::{Error, certs::tbs_certificate::TbsCertificate, highlevel_keys::AlgorithmIdentifier};
use yasna;

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

// Serilizaton
impl Certificate {
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let tbs_certificate = self.tbs_certificate.to_der()?;
        let result = yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_der(&tbs_certificate);
                seq.next().write_der(&self.signature_algorithm.to_der());
                seq.next().write_bitvec_bytes(&self.signature_value, self.signature_value.len() * 8);
            })
        });
        Ok(result)
    }

    pub fn from_der(der: Vec<u8>) -> Result<Self, Error> {
        let result = yasna::parse_ber(&der, |reader| {
            let result = reader.read_sequence(|seq_read| {
                let tbs= seq_read.next().read_der()?;
                let salg = seq_read.next().read_der()?;
                let sval = seq_read.next().read_bitvec_bytes()?;
                Ok((tbs, salg, sval.0))
            })?;

            Ok(result)
        }).map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;

        let tbs_certificate = TbsCertificate::from_der(&result.0)?;
        let signature_algorithm = AlgorithmIdentifier::from_der(&result.1)?;
        let signature_value = result.2;

        Ok(Self { tbs_certificate, signature_algorithm, signature_value })
    }
}
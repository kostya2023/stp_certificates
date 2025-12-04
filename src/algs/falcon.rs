// algs/falcon.rs

use crate::algs::AlgKeypair;
use crate::highlevel_keys::AlgorithmIdentifier;
use crate::highlevel_keys::privatekey::PrivateKeyInfo;
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;
use pqcrypto_falcon::falcon512;
use pqcrypto_falcon::falcon512::DetachedSignature as DetachedSignatureF512;
use pqcrypto_falcon::falcon512::PublicKey as PublicKeyF512;
use pqcrypto_falcon::falcon512::SecretKey as SecretKeyF512;
use pqcrypto_falcon::falcon1024;
use pqcrypto_falcon::falcon1024::DetachedSignature as DetachedSignatureF1024;
use pqcrypto_falcon::falcon1024::PublicKey as PublicKeyF1024;
use pqcrypto_falcon::falcon1024::SecretKey as SecretKeyF1024;
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};
use zeroize::{Zeroize, Zeroizing};

pub struct Falcon512Keypair {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

pub struct Falcon1024Keypair {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl AlgKeypair for Falcon512Keypair {
    // FNDSA
    fn generate() -> Result<Self, crate::Error> {
        let (public, private) = falcon512::keypair();
        Ok(Self {
            public_key: public.as_bytes().to_vec(),
            private_key: Zeroizing::new(private.as_bytes().to_vec()),
        })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, crate::Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        Ok(PrivateKeyInfo::new(
            0u64,
            AlgorithmIdentifier::new(crate::oid::FNDSA_512.clone(), None),
            &self.private_key,
            None,
        )
        .to_der())
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, crate::Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        // PKCS#8 check
        if private.version != 0 {
            return Err(crate::Error::PKCS8VersionInvalid);
        }
        if private.private_key_algorithm.algorithm != crate::oid::FNDSA_512.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        // SPKI check
        if public.algorithm.algorithm != crate::oid::FNDSA_512.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        Ok(Self {
            public_key: public.subject_public_key,
            private_key: Zeroizing::new(private.private_key),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, crate::Error> {
        if self.public_key.is_empty() {
            return Err(crate::Error::PublicKeyError(
                "Public key not init!".to_string(),
            ));
        }

        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(crate::oid::FNDSA_512.clone(), None),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, crate::Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        if self.public_key.is_empty() {
            return Err(crate::Error::PublicKeyError(
                "Public key not init!".to_string(),
            ));
        }

        let signature = falcon512::detached_sign(
            &msg,
            &SecretKeyF512::from_bytes(&self.private_key).map_err(|_| {
                crate::Error::PrivateKeyError(
                    "Error restore secret key from bytes before sign!".to_string(),
                )
            })?,
        );
        Ok(signature.as_bytes().to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, crate::Error> {
        let public_key = PublicKeyF512::from_bytes(
            SubjectPublicKeyInfo::from_der(public_key_der)?
                .subject_public_key
                .as_slice(),
        )
        .map_err(|_| {
            crate::Error::PublicKeyError(
                "Error restore public key from bytes before verify!".to_string(),
            )
        })?;
        let sign = DetachedSignatureF512::from_bytes(sign).map_err(|_| {
            crate::Error::VerifySignatureError(
                "Error restoring signature before verify!".to_string(),
            )
        })?;
        match falcon512::verify_detached_signature(&sign, &msg, &public_key) {
            Ok(_) => {
                return Ok(true);
            }
            Err(_) => {
                return Err(crate::Error::VerifySignatureError(
                    "Message corrupted! Signature invalid!".to_string(),
                ));
            }
        }
    }

    fn zeroize_private(&mut self) {
        self.private_key.zeroize();
    }
}

impl AlgKeypair for Falcon1024Keypair {
    // FNDSA
    fn generate() -> Result<Self, crate::Error> {
        let (public, private) = falcon1024::keypair();
        Ok(Self {
            public_key: public.as_bytes().to_vec(),
            private_key: Zeroizing::new(private.as_bytes().to_vec()),
        })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, crate::Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        Ok(PrivateKeyInfo::new(
            0u64,
            AlgorithmIdentifier::new(crate::oid::FNDSA_1024.clone(), None),
            &self.private_key,
            None,
        )
        .to_der())
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, crate::Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        // PKCS#8 check
        if private.version != 0 {
            return Err(crate::Error::PKCS8VersionInvalid);
        }
        if private.private_key_algorithm.algorithm != crate::oid::FNDSA_1024.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        // SPKI check
        if public.algorithm.algorithm != crate::oid::FNDSA_1024.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        Ok(Self {
            public_key: public.subject_public_key,
            private_key: Zeroizing::new(private.private_key),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, crate::Error> {
        if self.public_key.is_empty() {
            return Err(crate::Error::PublicKeyError(
                "Public key not init!".to_string(),
            ));
        }

        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(crate::oid::FNDSA_1024.clone(), None),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, crate::Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        let signature = falcon1024::detached_sign(
            &msg,
            &SecretKeyF1024::from_bytes(&self.private_key).map_err(|_| {
                crate::Error::PrivateKeyError(
                    "Error restore secret key from bytes before sign!".to_string(),
                )
            })?,
        );
        Ok(signature.as_bytes().to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, crate::Error> {
        let public_key = PublicKeyF1024::from_bytes(
            SubjectPublicKeyInfo::from_der(public_key_der)?
                .subject_public_key
                .as_slice(),
        )
        .map_err(|_| {
            crate::Error::PublicKeyError(
                "Error restore public key from bytes before verify!".to_string(),
            )
        })?;
        let sign = DetachedSignatureF1024::from_bytes(sign).map_err(|_| {
            crate::Error::VerifySignatureError(
                "Error restoring signature before verify!".to_string(),
            )
        })?;
        match falcon1024::verify_detached_signature(&sign, &msg, &public_key) {
            Ok(_) => {
                return Ok(true);
            }
            Err(_) => {
                return Err(crate::Error::VerifySignatureError(
                    "Message corrupted! Signature invalid!".to_string(),
                ));
            }
        }
    }

    fn zeroize_private(&mut self) {
        self.private_key.zeroize();
    }
}

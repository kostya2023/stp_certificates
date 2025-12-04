// algs/mldsa.rs

use crate::Error;
use crate::algs::AlgKeypair;
use crate::highlevel_keys::AlgorithmIdentifier;
use crate::highlevel_keys::privatekey::PrivateKeyInfo;
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;
use pqcrypto_mldsa::mldsa44::DetachedSignature as DetachedSignatureD2;
use pqcrypto_mldsa::mldsa44::PublicKey as PublicKeyD2;
use pqcrypto_mldsa::mldsa44::SecretKey as SecretKeyD2;
use pqcrypto_mldsa::mldsa65::DetachedSignature as DetachedSignatureD3;
use pqcrypto_mldsa::mldsa65::PublicKey as PublicKeyD3;
use pqcrypto_mldsa::mldsa65::SecretKey as SecretKeyD3;
use pqcrypto_mldsa::mldsa87::DetachedSignature as DetachedSignatureD5;
use pqcrypto_mldsa::mldsa87::PublicKey as PublicKeyD5;
use pqcrypto_mldsa::mldsa87::SecretKey as SecretKeyD5;
use pqcrypto_mldsa::mldsa44;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};
use zeroize::{Zeroize, Zeroizing};


pub struct MLDSA44Keypair {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>
}

pub struct MLDSA65Keypair {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>
}

pub struct MLDSA87Keypair {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>
}

impl AlgKeypair for MLDSA44Keypair {
    fn generate() -> Result<Self, Error> {
        let (public, private) = mldsa44::keypair();
        Ok(Self { public_key: public.as_bytes().to_vec(), private_key: Zeroizing::new(private.as_bytes().to_vec()) })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        Ok(
            PrivateKeyInfo::new(
                0u64, 
                AlgorithmIdentifier::new(crate::oid::MLDSA_44.clone(), None), 
                &self.private_key, 
                None
            ).to_der()
        )
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        // PKCS#8 check
        if private.version != 0 {
            return Err(crate::Error::PKCS8VersionInvalid);
        }
        if private.private_key_algorithm.algorithm != crate::oid::MLDSA_44.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        // SPKI check
        if public.algorithm.algorithm != crate::oid::MLDSA_44.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        Ok(Self {
            public_key: public.subject_public_key,
            private_key: Zeroizing::new(private.private_key),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.public_key.is_empty() {
            return Err(crate::Error::PublicKeyError(
                "Public key not init!".to_string(),
            ));
        }

        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(crate::oid::MLDSA_44.clone(), None),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        let signature = mldsa44::detached_sign(
            &msg,
            &SecretKeyD2::from_bytes(&self.private_key).map_err(|_| {
                crate::Error::PrivateKeyError(
                    "Error restore secret key from bytes before sign!".to_string(),
                )
            })?,
        );

        Ok(signature.as_bytes().to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, Error> {
        let public_key = PublicKeyD2::from_bytes(
            SubjectPublicKeyInfo::from_der(public_key_der)?
                .subject_public_key
                .as_slice(),
        )
        .map_err(|_| {
            crate::Error::PublicKeyError(
                "Error restore public key from bytes before verify!".to_string(),
            )
        })?;
        let sign = DetachedSignatureD2::from_bytes(sign).map_err(|_| {
            crate::Error::VerifySignatureError(
                "Error restoring signature before verify!".to_string(),
            )
        })?;
        match mldsa44::verify_detached_signature(&sign, &msg, &public_key) {
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



impl AlgKeypair for MLDSA65Keypair {
    fn generate() -> Result<Self, Error> {
        let (public, private) = mldsa65::keypair();
        Ok(Self { public_key: public.as_bytes().to_vec(), private_key: Zeroizing::new(private.as_bytes().to_vec()) })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        Ok(
            PrivateKeyInfo::new(
                0u64, 
                AlgorithmIdentifier::new(crate::oid::MLDSA_65.clone(), None), 
                &self.private_key, 
                None
            ).to_der()
        )
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        // PKCS#8 check
        if private.version != 0 {
            return Err(crate::Error::PKCS8VersionInvalid);
        }
        if private.private_key_algorithm.algorithm != crate::oid::MLDSA_65.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        // SPKI check
        if public.algorithm.algorithm != crate::oid::MLDSA_65.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        Ok(Self {
            public_key: public.subject_public_key,
            private_key: Zeroizing::new(private.private_key),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.public_key.is_empty() {
            return Err(crate::Error::PublicKeyError(
                "Public key not init!".to_string(),
            ));
        }

        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(crate::oid::MLDSA_65.clone(), None),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        let signature = mldsa65::detached_sign(
            &msg,
            &SecretKeyD3::from_bytes(&self.private_key).map_err(|_| {
                crate::Error::PrivateKeyError(
                    "Error restore secret key from bytes before sign!".to_string(),
                )
            })?,
        );

        Ok(signature.as_bytes().to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, Error> {
        let public_key = PublicKeyD3::from_bytes(
            SubjectPublicKeyInfo::from_der(public_key_der)?
                .subject_public_key
                .as_slice(),
        )
        .map_err(|_| {
            crate::Error::PublicKeyError(
                "Error restore public key from bytes before verify!".to_string(),
            )
        })?;
        let sign = DetachedSignatureD3::from_bytes(sign).map_err(|_| {
            crate::Error::VerifySignatureError(
                "Error restoring signature before verify!".to_string(),
            )
        })?;
        match mldsa65::verify_detached_signature(&sign, &msg, &public_key) {
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




impl AlgKeypair for MLDSA87Keypair {
    fn generate() -> Result<Self, Error> {
        let (public, private) = mldsa87::keypair();
        Ok(Self { public_key: public.as_bytes().to_vec(), private_key: Zeroizing::new(private.as_bytes().to_vec()) })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        Ok(
            PrivateKeyInfo::new(
                0u64, 
                AlgorithmIdentifier::new(crate::oid::MLDSA_87.clone(), None), 
                &self.private_key, 
                None
            ).to_der()
        )
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        // PKCS#8 check
        if private.version != 0 {
            return Err(crate::Error::PKCS8VersionInvalid);
        }
        if private.private_key_algorithm.algorithm != crate::oid::MLDSA_87.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        // SPKI check
        if public.algorithm.algorithm != crate::oid::MLDSA_87.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        Ok(Self {
            public_key: public.subject_public_key,
            private_key: Zeroizing::new(private.private_key),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.public_key.is_empty() {
            return Err(crate::Error::PublicKeyError(
                "Public key not init!".to_string(),
            ));
        }

        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(crate::oid::MLDSA_87.clone(), None),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(crate::Error::PrivateKeyError(
                "Private key not init!".to_string(),
            ));
        }

        let signature = mldsa87::detached_sign(
            &msg,
            &SecretKeyD5::from_bytes(&self.private_key).map_err(|_| {
                crate::Error::PrivateKeyError(
                    "Error restore secret key from bytes before sign!".to_string(),
                )
            })?,
        );

        Ok(signature.as_bytes().to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, Error> {
        let public_key = PublicKeyD5::from_bytes(
            SubjectPublicKeyInfo::from_der(public_key_der)?
                .subject_public_key
                .as_slice(),
        )
        .map_err(|_| {
            crate::Error::PublicKeyError(
                "Error restore public key from bytes before verify!".to_string(),
            )
        })?;
        let sign = DetachedSignatureD5::from_bytes(sign).map_err(|_| {
            crate::Error::VerifySignatureError(
                "Error restoring signature before verify!".to_string(),
            )
        })?;
        match mldsa87::verify_detached_signature(&sign, &msg, &public_key) {
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
// algs/eddsa.rs

use crate::Error;
use crate::algs::AlgKeypair;
use crate::highlevel_keys::AlgorithmIdentifier;
use crate::highlevel_keys::privatekey::PrivateKeyInfo;
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{SECRET_KEY_LENGTH, Signature, SigningKey, Verifier, VerifyingKey};
use rand::TryRngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

pub struct Ed25519 {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl AlgKeypair for Ed25519 {
    fn generate() -> Result<Self, Error> {
        let mut csprng = OsRng;
        let mut random: [u8; 32] = [0; SECRET_KEY_LENGTH];
        let _ = csprng.try_fill_bytes(&mut random).map_err(|_| Error::RandError)?;
        let private = SigningKey::from_bytes(&random);
        let public = private.verifying_key();
        Ok(Self {
            public_key: public.as_bytes().to_vec(),
            private_key: Zeroizing::new(private.as_bytes().to_vec()),
        })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, Error> {
        Ok(PrivateKeyInfo::new(
            0u64,
            AlgorithmIdentifier::new(crate::oid::ED25519.clone(), None),
            &self.private_key,
            None,
        )
        .to_der())
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        // PKCS#8 check
        if private.version != 0 {
            return Err(crate::Error::PKCS8VersionInvalid);
        }
        if private.private_key_algorithm.algorithm != crate::oid::ED25519.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        // SPKI check
        if public.algorithm.algorithm != crate::oid::ED25519.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        Ok(Self {
            public_key: public.subject_public_key,
            private_key: Zeroizing::new(private.private_key),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(crate::oid::ED25519.clone(), None),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(Error::PrivateKeyError("Private key not init!".to_string()));
        }

        let sk: [u8; 32] = self.private_key.as_slice().try_into().map_err(|_| {
            Error::PrivateKeyError("Invalid ed25519 private key length".to_string())
        })?;

        let signature = SigningKey::from_bytes(&sk).sign(msg);

        Ok(signature.to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, Error> {
        let pk: [u8; 32] = SubjectPublicKeyInfo::from_der(&public_key_der)?
            .subject_public_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                Error::PrivateKeyError("Invalid ed25519 private key length".to_string())
            })?;

        let public_key = VerifyingKey::from_bytes(&pk).map_err(|_| {
            Error::PublicKeyError("Error restore public key from bytes before verify!".to_string())
        })?;

        let signature: [u8; 64] = sign.try_into().map_err(|_| {
            Error::PublicKeyError("Error restore public key from bytes before verify!".to_string())
        })?;

        match public_key.verify(msg, &Signature::from_bytes(&signature)) {
            Ok(_) => return Ok(true),
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




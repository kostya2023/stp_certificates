// algs/eddsa.rs
use crate::Error;
use crate::algs::AlgKeypair;
use crate::highlevel_keys::AlgorithmIdentifier;
use crate::highlevel_keys::privatekey::PrivateKeyInfo;
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{SECRET_KEY_LENGTH, Signature, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};
use ed448_rust::{PrivateKey, PublicKey, KEY_LENGTH, SIG_LENGTH};

pub struct Ed25519 {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

pub struct Ed448 {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl AlgKeypair for Ed25519 {
    fn generate() -> Result<Self, Error> {
        let mut csprng = OsRng::new().map_err(|_| Err(crate::Error::RandError));
        let mut random: [u8; 32] = [0; SECRET_KEY_LENGTH];
        let _ = csprng.try_fill_bytes(&mut random);
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



impl AlgKeypair for Ed448 {
    fn generate() -> Result<Self, Error> {
        // Создаём приватный ключ и берём публичный
        let mut rng = OsRng;
        let privk = PrivateKey::new(&mut rng);
        let pubk = PublicKey::from(&privk);

        Ok(Self {
            public_key: pubk.as_byte().to_vec(),
            private_key: Zeroizing::new(privk.as_bytes().to_vec()),
        })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(Error::PrivateKeyError("Private key not init!".to_string()));
        }

        // PKCS#8 PrivateKeyInfo version = 0 (RFC 8410). Algorithm OID — ED448 (1.3.101.113).
        Ok(PrivateKeyInfo::new(
            0u64,
            AlgorithmIdentifier::new(crate::oid::ED448.clone(), None),
            &self.private_key,
            None,
        )
        .to_der())
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        // PKCS#8 check: version == 0
        if private.version != 0 {
            return Err(crate::Error::PKCS8VersionInvalid);
        }
        if private.private_key_algorithm.algorithm != crate::oid::ED448.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        // SPKI check
        if public.algorithm.algorithm != crate::oid::ED448.clone() {
            return Err(crate::Error::InvalidAlgorithmError);
        }

        // приватные байты должны иметь KEY_LENGTH
        if private.private_key.len() != KEY_LENGTH {
            return Err(crate::Error::PrivateKeyError("Invalid Ed448 private key length".to_string()));
        }

        Ok(Self {
            public_key: public.subject_public_key,
            private_key: Zeroizing::new(private.private_key),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.public_key.is_empty() {
            return Err(Error::PublicKeyError("Public key not init!".to_string()));
        }

        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(crate::oid::ED448.clone(), None),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(Error::PrivateKeyError("Private key not init!".to_string()));
        }

        // Восстанавливаем PrivateKey из сырых байт (crate предоставляет try_from / try_into semantics)
        // `PrivateKey::try_from` или `PrivateKey::try_from(slice)` в зависимости от версии; тут общий подход:
        let priv_bytes = self.private_key.as_slice();

        // Попробуем восстановить объект PrivateKey из байт
        let privk = PrivateKey::try_from(priv_bytes).map_err(|_| {
            Error::PrivateKeyError("Invalid Ed448 private key bytes".to_string())
        })?;

        // Подпись — используем без контекста (None). Возвращает slice длины SIG_LENGTH.
        let sig = privk
            .sign(msg, None)
            .map_err(|_| Error::PrivateKeyError("Failed to sign with Ed448".to_string()))?;

        Ok(sig.to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, Error> {
        // Десериализуем SPKI
        let spki = SubjectPublicKeyInfo::from_der(public_key_der)?;

        // Проверим длину публичного ключа
        if spki.subject_public_key.len() != KEY_LENGTH {
            return Err(Error::PublicKeyError("Invalid Ed448 public key length".to_string()));
        }

        // Восстанавливаем PublicKey
        let pubk = PublicKey::try_from(spki.subject_public_key.as_slice()).map_err(|_| {
            Error::PublicKeyError("Error restore Ed448 public key from bytes".to_string())
        })?;

        // Проверим подпись: sign должно быть SIG_LENGTH
        if sign.len() != SIG_LENGTH {
            return Err(Error::VerifySignatureError("Invalid Ed448 signature length".to_string()));
        }

        pubk
            .verify(msg, sign, None)
            .map(|_| true)
            .map_err(|_| Error::VerifySignatureError("Message corrupted! Signature invalid!".to_string()))
    }

    fn zeroize_private(&mut self) {
        self.private_key.zeroize();
    }
}
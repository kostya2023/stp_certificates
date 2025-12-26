// algs/slh_dsa_shake.rs

use crate::Error;
use crate::Serilizaton;
use crate::algs::AlgKeypair;
use crate::highlevel_keys::AlgorithmIdentifier;
use crate::highlevel_keys::privatekey::PrivateKeyInfo;
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;
use pqcrypto_sphincsplus::sphincsshake128fsimple;
use pqcrypto_sphincsplus::sphincsshake128fsimple::{
    DetachedSignature as DetachedSignatureSDSA128, PublicKey as PublicKeySDSA128,
    SecretKey as SecretKeySDSA128,
};
use pqcrypto_sphincsplus::sphincsshake192fsimple;
use pqcrypto_sphincsplus::sphincsshake192fsimple::{
    DetachedSignature as DetachedSignatureSDSA192, PublicKey as PublicKeySDSA192,
    SecretKey as SecretKeySDSA192,
};
use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_sphincsplus::sphincsshake256fsimple::{
    DetachedSignature as DetachedSignatureSDSA256, PublicKey as PublicKeySDSA256,
    SecretKey as SecretKeySDSA256,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};
use yasna::models::ObjectIdentifier;
use zeroize::{Zeroize, Zeroizing};

fn read_slhdsa_hasher(der: Vec<u8>) -> Result<ObjectIdentifier, crate::Error> {
    let slh_dsa_hash = yasna::parse_der(&der, |reader| {
        let slh_dsa = reader.read_oid()?;
        Ok(slh_dsa)
    })
    .map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;
    Ok(slh_dsa_hash)
}

fn write_slhdsa_hasher(oid: ObjectIdentifier) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_oid(&oid);
    })
}

/* ============================================================
 * SLHDSA 128F
 * ============================================================ */

pub struct SLHDSA128FKeypair {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl AlgKeypair for SLHDSA128FKeypair {
    fn generate() -> Result<Self, Error> {
        let (public, private) = sphincsshake128fsimple::keypair();
        Ok(Self {
            public_key: public.as_bytes().to_vec(),
            private_key: Zeroizing::new(private.as_bytes().to_vec()),
        })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(Error::PrivateKeyError("Private key not init!".into()));
        }

        Ok(PrivateKeyInfo::new(
            0,
            AlgorithmIdentifier::new(
                crate::oid::SLHDSA_128F.clone(),
                Some(write_slhdsa_hasher(crate::oid::SLHDSA_HASH_SHAKE.clone())),
            ),
            &self.private_key,
            None,
        )
        .to_der())
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        // ----- PKCS8 -----
        if private.version() != 0 {
            return Err(Error::PKCS8VersionInvalid);
        }

        if private.private_key_algorithm().algorithm() != crate::oid::SLHDSA_128F.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        // check hasher
        let hasher_oid = read_slhdsa_hasher(
            private
                .private_key_algorithm()
                .parameters()
                .clone()
                .ok_or(Error::InvalidAlgorithmError)?,
        )?;

        if hasher_oid != crate::oid::SLHDSA_HASH_SHAKE.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        // ----- SPKI -----
        if public.algorithm().algorithm() != crate::oid::SLHDSA_128F.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        let hasher_oid_pub = read_slhdsa_hasher(
            public
                .algorithm()
                .parameters()
                .clone()
                .ok_or(Error::InvalidAlgorithmError)?,
        )?;

        if hasher_oid_pub != crate::oid::SLHDSA_HASH_SHAKE.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        Ok(Self {
            public_key: public.subject_public_key(),
            private_key: Zeroizing::new(private.private_key()),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        if self.public_key.is_empty() {
            return Err(Error::PublicKeyError("Public key not init!".into()));
        }

        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(
                crate::oid::SLHDSA_128F.clone(),
                Some(write_slhdsa_hasher(crate::oid::SLHDSA_HASH_SHAKE.clone())),
            ),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if self.private_key.is_empty() {
            return Err(Error::PrivateKeyError("Private key not init!".into()));
        }

        let secret = SecretKeySDSA128::from_bytes(&self.private_key)
            .map_err(|_| Error::PrivateKeyError("Error restore secret key".into()))?;

        let signature = sphincsshake128fsimple::detached_sign(msg, &secret);

        Ok(signature.as_bytes().to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, Error> {
        let public_der = SubjectPublicKeyInfo::from_der(public_key_der)?;

        let pk = PublicKeySDSA128::from_bytes(public_der.subject_public_key().as_slice())
            .map_err(|_| Error::PublicKeyError("Error restore PK".into()))?;

        let sig = DetachedSignatureSDSA128::from_bytes(sign)
            .map_err(|_| Error::VerifySignatureError("Error restoring signature".into()))?;

        sphincsshake128fsimple::verify_detached_signature(&sig, msg, &pk)
            .map(|_| true)
            .map_err(|_| Error::VerifySignatureError("Signature invalid!".into()))
    }

    fn zeroize_private(&mut self) {
        self.private_key.zeroize();
    }
}

/* ============================================================
 * SLHDSA 192F
 * ============================================================ */

pub struct SLHDSA192FKeypair {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl AlgKeypair for SLHDSA192FKeypair {
    fn generate() -> Result<Self, Error> {
        let (public, private) = sphincsshake192fsimple::keypair();
        Ok(Self {
            public_key: public.as_bytes().to_vec(),
            private_key: Zeroizing::new(private.as_bytes().to_vec()),
        })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, Error> {
        Ok(PrivateKeyInfo::new(
            0,
            AlgorithmIdentifier::new(
                crate::oid::SLHDSA_192F.clone(),
                Some(write_slhdsa_hasher(crate::oid::SLHDSA_HASH_SHAKE.clone())),
            ),
            &self.private_key,
            None,
        )
        .to_der())
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        if private.version() != 0 {
            return Err(Error::PKCS8VersionInvalid);
        }
        if private.private_key_algorithm().algorithm() != crate::oid::SLHDSA_192F.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        let hasher_oid = read_slhdsa_hasher(
            private
                .private_key_algorithm()
                .parameters()
                .clone()
                .ok_or(Error::InvalidAlgorithmError)?,
        )?;
        if hasher_oid != crate::oid::SLHDSA_HASH_SHAKE.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        if public.algorithm().algorithm() != crate::oid::SLHDSA_192F.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        let hasher_oid_pub = read_slhdsa_hasher(
            public
                .algorithm()
                .parameters()
                .clone()
                .ok_or(Error::InvalidAlgorithmError)?,
        )?;
        if hasher_oid_pub != crate::oid::SLHDSA_HASH_SHAKE.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        Ok(Self {
            public_key: public.subject_public_key(),
            private_key: Zeroizing::new(private.private_key()),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(
                crate::oid::SLHDSA_192F.clone(),
                Some(write_slhdsa_hasher(crate::oid::SLHDSA_HASH_SHAKE.clone())),
            ),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let sk = SecretKeySDSA192::from_bytes(&self.private_key)
            .map_err(|_| Error::PrivateKeyError("Error restore SK".into()))?;
        let sig = sphincsshake192fsimple::detached_sign(msg, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, Error> {
        let spki = SubjectPublicKeyInfo::from_der(public_key_der)?;
        let pk = PublicKeySDSA192::from_bytes(spki.subject_public_key().as_slice())
            .map_err(|_| Error::PublicKeyError("Error restore PK".into()))?;
        let sig = DetachedSignatureSDSA192::from_bytes(sign)
            .map_err(|_| Error::VerifySignatureError("Error restore signature".into()))?;

        sphincsshake192fsimple::verify_detached_signature(&sig, msg, &pk)
            .map(|_| true)
            .map_err(|_| Error::VerifySignatureError("Signature invalid!".into()))
    }

    fn zeroize_private(&mut self) {
        self.private_key.zeroize();
    }
}

/* ============================================================
 * SLHDSA 256F
 * ============================================================ */

pub struct SLHDSA256FKeypair {
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl AlgKeypair for SLHDSA256FKeypair {
    fn generate() -> Result<Self, Error> {
        let (public, private) = sphincsshake256fsimple::keypair();
        Ok(Self {
            public_key: public.as_bytes().to_vec(),
            private_key: Zeroizing::new(private.as_bytes().to_vec()),
        })
    }

    fn private_key_der(&self) -> Result<Vec<u8>, Error> {
        Ok(PrivateKeyInfo::new(
            0,
            AlgorithmIdentifier::new(
                crate::oid::SLHDSA_256F.clone(),
                Some(write_slhdsa_hasher(crate::oid::SLHDSA_HASH_SHAKE.clone())),
            ),
            &self.private_key,
            None,
        )
        .to_der())
    }

    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, Error> {
        let private = PrivateKeyInfo::from_der(&private_key)?;
        let public = SubjectPublicKeyInfo::from_der(&public_key)?;

        if private.version() != 0 {
            return Err(Error::PKCS8VersionInvalid);
        }

        if private.private_key_algorithm().algorithm() != crate::oid::SLHDSA_256F.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        let hasher_oid = read_slhdsa_hasher(
            private
                .private_key_algorithm()
                .parameters()
                .clone()
                .ok_or(Error::InvalidAlgorithmError)?,
        )?;
        if hasher_oid != crate::oid::SLHDSA_HASH_SHAKE.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        if public.algorithm().algorithm() != crate::oid::SLHDSA_256F.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        let hasher_oid_pub = read_slhdsa_hasher(
            public
                .algorithm()
                .parameters()
                .clone()
                .ok_or(Error::InvalidAlgorithmError)?,
        )?;
        if hasher_oid_pub != crate::oid::SLHDSA_HASH_SHAKE.clone() {
            return Err(Error::InvalidAlgorithmError);
        }

        Ok(Self {
            public_key: public.subject_public_key(),
            private_key: Zeroizing::new(private.private_key()),
        })
    }

    fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        Ok(SubjectPublicKeyInfo::new(
            AlgorithmIdentifier::new(
                crate::oid::SLHDSA_256F.clone(),
                Some(write_slhdsa_hasher(crate::oid::SLHDSA_HASH_SHAKE.clone())),
            ),
            &self.public_key,
        )
        .to_der())
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let sk = SecretKeySDSA256::from_bytes(&self.private_key)
            .map_err(|_| Error::PrivateKeyError("Error restore SK".into()))?;

        let signature = sphincsshake256fsimple::detached_sign(msg, &sk);

        Ok(signature.as_bytes().to_vec())
    }

    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, Error> {
        let spki = SubjectPublicKeyInfo::from_der(public_key_der)?;

        let pk = PublicKeySDSA256::from_bytes(spki.subject_public_key().as_slice())
            .map_err(|_| Error::PublicKeyError("Error restore PK".into()))?;

        let sig = DetachedSignatureSDSA256::from_bytes(sign)
            .map_err(|_| Error::VerifySignatureError("Error restore signature".into()))?;

        sphincsshake256fsimple::verify_detached_signature(&sig, msg, &pk)
            .map(|_| true)
            .map_err(|_| Error::VerifySignatureError("Signature invalid!".into()))
    }

    fn zeroize_private(&mut self) {
        self.private_key.zeroize();
    }
}

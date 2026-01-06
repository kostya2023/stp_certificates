// algs/mod.rs

#![allow(unused_variables)]

pub mod eddsa;

#[cfg(feature = "pqcrypto")]
pub mod fndsa;
#[cfg(feature = "pqcrypto")]
pub mod mldsa;
#[cfg(feature = "pqcrypto")]
pub mod slh_dsa_sha2;
#[cfg(feature = "pqcrypto")]
pub mod slh_dsa_shake;

use yasna::models::ObjectIdentifier;
use zeroize::{Zeroizing, Zeroize};
use crate::highlevel_keys::publickey::SubjectPublicKeyInfo;
use crate::{Error, Serilizaton, oid};
use crate::algs::eddsa::Ed25519Keypair;

#[cfg(feature = "pqcrypto")]
use crate::algs::fndsa::{FNDSA512Keypair, FNDSA1024Keypair};
#[cfg(feature = "pqcrypto")]
use crate::algs::mldsa::{MLDSA44Keypair, MLDSA65Keypair, MLDSA87Keypair};
#[cfg(feature = "pqcrypto")]
use crate::algs::slh_dsa_sha2::{
    SLHDSA128FKeypair as SLHDSA128FSHA2Keypair,
    SLHDSA192FKeypair as SLHDSA192FSHA2Keypair,
    SLHDSA256FKeypair as SLHDSA256FSHA2Keypair,
};
#[cfg(feature = "pqcrypto")]
use crate::algs::slh_dsa_shake::{
    SLHDSA128FKeypair as SLHDSA128FSHAKEKeypair,
    SLHDSA192FKeypair as SLHDSA192FSHAKEKeypair,
    SLHDSA256FKeypair as SLHDSA256FSHAKEKeypair,
};

pub trait AlgKeypair: Sized {
    /// Генерация новой пары ключей
    fn generate() -> Result<Self, Error>;

    /// Подписывает сообщение своим приватным ключом
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error>;

    /// Возвращает ASN.1 DER приватного ключа (OCTET STRING внутри PrivateKeyInfo)
    fn private_key_der(&self) -> Result<Vec<u8>, Error>;

    /// Принимает ASN.1 DER приватный и публичный ключи и создаёт экземпляр
    fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Self, Error>;

    /// Возвращает ASN.1 DER публичного ключа (BIT STRING внутри SubjectPublicKeyInfo)
    fn public_key_der(&self) -> Result<Vec<u8>, Error>;

    /// Проверяет подпись данным публичным ключом
    fn verify(public_key_der: &[u8], msg: &[u8], sign: &[u8]) -> Result<bool, Error>;

    /// Зануляет Private_Key
    fn zeroize_private(&mut self);
}

pub enum SignAlgorithm {
    Ed25519,

    #[cfg(feature = "pqcrypto")]
    FnDSA512,
    #[cfg(feature = "pqcrypto")]
    FnDSA1024,

    #[cfg(feature = "pqcrypto")]
    MlDSA44,
    #[cfg(feature = "pqcrypto")]
    MlDSA65,
    #[cfg(feature = "pqcrypto")]
    MlDSA87,

    #[cfg(feature = "pqcrypto")]
    SlhDSA128Sha2,
    #[cfg(feature = "pqcrypto")]
    SlhDSA192Sha2,
    #[cfg(feature = "pqcrypto")]
    SlhDSA256Sha2,

    #[cfg(feature = "pqcrypto")]
    SlhDSA128SHAKE,
    #[cfg(feature = "pqcrypto")]
    SlhDSA192SHAKE,
    #[cfg(feature = "pqcrypto")]
    SlhDSA256SHAKE,
}

impl SignAlgorithm {
    pub fn algorithm_from_oid(
        alg_id: ObjectIdentifier,
        param: Option<ObjectIdentifier>,
    ) -> Result<SignAlgorithm, Error> {
        match alg_id {
            oid if oid == *oid::ED25519 => Ok(SignAlgorithm::Ed25519),

            #[cfg(feature = "pqcrypto")]
            oid if oid == *oid::FNDSA_512 => Ok(SignAlgorithm::FnDSA512),
            #[cfg(feature = "pqcrypto")]
            oid if oid == *oid::FNDSA_1024 => Ok(SignAlgorithm::FnDSA1024),

            #[cfg(feature = "pqcrypto")]
            oid if oid == *oid::MLDSA_44 => Ok(SignAlgorithm::MlDSA44),
            #[cfg(feature = "pqcrypto")]
            oid if oid == *oid::MLDSA_65 => Ok(SignAlgorithm::MlDSA65),
            #[cfg(feature = "pqcrypto")]
            oid if oid == *oid::MLDSA_87 => Ok(SignAlgorithm::MlDSA87),

            #[cfg(feature = "pqcrypto")]
            oid if oid == *oid::SLHDSA_128F => match param {
                Some(p) if p == *oid::SLHDSA_HASH_SHA2 => Ok(SignAlgorithm::SlhDSA128Sha2),
                Some(p) if p == *oid::SLHDSA_HASH_SHAKE => Ok(SignAlgorithm::SlhDSA128SHAKE),
                _ => Err(Error::InvalidAlgorithmError),
            },

            #[cfg(feature = "pqcrypto")]
            oid if oid == *oid::SLHDSA_192F => match param {
                Some(p) if p == *oid::SLHDSA_HASH_SHA2 => Ok(SignAlgorithm::SlhDSA192Sha2),
                Some(p) if p == *oid::SLHDSA_HASH_SHAKE => Ok(SignAlgorithm::SlhDSA192SHAKE),
                _ => Err(Error::InvalidAlgorithmError),
            },

            #[cfg(feature = "pqcrypto")]
            oid if oid == *oid::SLHDSA_256F => match param {
                Some(p) if p == *oid::SLHDSA_HASH_SHA2 => Ok(SignAlgorithm::SlhDSA256Sha2),
                Some(p) if p == *oid::SLHDSA_HASH_SHAKE => Ok(SignAlgorithm::SlhDSA256SHAKE),
                _ => Err(Error::InvalidAlgorithmError),
            },

            _ => Err(Error::InvalidAlgorithmError),
        }
    }

    pub fn oid_from_algorithm(
        algorithm: SignAlgorithm,
    ) -> (ObjectIdentifier, Option<ObjectIdentifier>) {
        match algorithm {
            SignAlgorithm::Ed25519 => (oid::ED25519.clone(), None),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA512 => (oid::FNDSA_512.clone(), None),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA1024 => (oid::FNDSA_1024.clone(), None),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA44 => (oid::MLDSA_44.clone(), None),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA65 => (oid::MLDSA_65.clone(), None),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA87 => (oid::MLDSA_87.clone(), None),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128Sha2 => (
                oid::SLHDSA_128F.clone(),
                Some(oid::SLHDSA_HASH_SHA2.clone()),
            ),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192Sha2 => (
                oid::SLHDSA_192F.clone(),
                Some(oid::SLHDSA_HASH_SHA2.clone()),
            ),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256Sha2 => (
                oid::SLHDSA_256F.clone(),
                Some(oid::SLHDSA_HASH_SHA2.clone()),
            ),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128SHAKE => (
                oid::SLHDSA_128F.clone(),
                Some(oid::SLHDSA_HASH_SHAKE.clone()),
            ),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192SHAKE => (
                oid::SLHDSA_192F.clone(),
                Some(oid::SLHDSA_HASH_SHAKE.clone()),
            ),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256SHAKE => (
                oid::SLHDSA_256F.clone(),
                Some(oid::SLHDSA_HASH_SHAKE.clone()),
            ),
        }
    }
}

pub struct UniversalKeypair {
    pub public_key: Vec<u8>,
    pub algorithm: SignAlgorithm,
    public_key_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
}

macro_rules! generate_keypair {
    ($kp_type:ty, $alg_variant:expr) => {{
        let keypair = <$kp_type>::generate()?;
        let private_key_der = keypair.private_key_der()?;
        let public_key_der = keypair.public_key_der()?;
        UniversalKeypair {
            public_key: keypair.public_key.clone(),
            algorithm: $alg_variant,
            public_key_der,
            private_key_der: Zeroizing::new(private_key_der),
        }
    }};
}

macro_rules! call_sign {
    ($kp_type:ty, $pub_der:expr, $priv_der:expr, $msg:expr) => {{
        let keypair: $kp_type = <$kp_type>::from_keypair_der((&*$priv_der).to_vec(), $pub_der.clone())?;
        keypair.sign($msg)?
    }};
}

macro_rules! call_private_key_der {
    ($kp_type:ty, $pub_der:expr, $priv_der:expr) => {{
        let keypair: $kp_type = <$kp_type>::from_keypair_der((&*$priv_der).to_vec(), $pub_der.clone())?;
        keypair.private_key_der()?
    }};
}

macro_rules! call_verify {
    ($kp_type:ty, $pub_der:expr, $msg:expr, $sign:expr) => {{
        <$kp_type>::verify($pub_der, $msg, $sign)?
    }};
}

macro_rules! generate_keypair_from_der {
    ($kp_type:ty, $alg_variant:expr, $private:expr, $public:expr) => {{
        let spki = SubjectPublicKeyInfo::from_der(&$public)?;
        let (oid, param) = SignAlgorithm::oid_from_algorithm($alg_variant);
        let expected_param = param.as_ref().map(|p| yasna::construct_der(|w| w.write_oid(p)));
        if spki.algorithm().algorithm() != oid || spki.algorithm().parameters() != expected_param {
            return Err(Error::InvalidAlgorithmError);
        }

        let keypair: $kp_type = <$kp_type>::from_keypair_der($private.to_vec(), $public.to_vec())?;

        let private_key_der = keypair.private_key_der()?;
        let public_key_der = keypair.public_key_der()?;

        Self {
            public_key: keypair.public_key.clone(),
            algorithm: $alg_variant,
            public_key_der,
            private_key_der: Zeroizing::new(private_key_der),
        }
    }};
}

impl UniversalKeypair {
    pub fn generate(algorithm: SignAlgorithm) -> Result<Self, Error> {
        match algorithm {
            SignAlgorithm::Ed25519 => Ok(generate_keypair!(Ed25519Keypair, SignAlgorithm::Ed25519)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA512 => Ok(generate_keypair!(FNDSA512Keypair, SignAlgorithm::FnDSA512)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA1024 => Ok(generate_keypair!(FNDSA1024Keypair, SignAlgorithm::FnDSA1024)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA44 => Ok(generate_keypair!(MLDSA44Keypair, SignAlgorithm::MlDSA44)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA65 => Ok(generate_keypair!(MLDSA65Keypair, SignAlgorithm::MlDSA65)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA87 => Ok(generate_keypair!(MLDSA87Keypair, SignAlgorithm::MlDSA87)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128Sha2 => Ok(generate_keypair!(SLHDSA128FSHA2Keypair, SignAlgorithm::SlhDSA128Sha2)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192Sha2 => Ok(generate_keypair!(SLHDSA192FSHA2Keypair, SignAlgorithm::SlhDSA192Sha2)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256Sha2 => Ok(generate_keypair!(SLHDSA256FSHA2Keypair, SignAlgorithm::SlhDSA256Sha2)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128SHAKE => Ok(generate_keypair!(SLHDSA128FSHAKEKeypair, SignAlgorithm::SlhDSA128SHAKE)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192SHAKE => Ok(generate_keypair!(SLHDSA192FSHAKEKeypair, SignAlgorithm::SlhDSA192SHAKE)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256SHAKE => Ok(generate_keypair!(SLHDSA256FSHAKEKeypair, SignAlgorithm::SlhDSA256SHAKE)),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        match self.algorithm {
            SignAlgorithm::Ed25519 => Ok(call_sign!(Ed25519Keypair, self.public_key_der, self.private_key_der, msg)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA512 => Ok(call_sign!(FNDSA512Keypair, self.public_key_der, self.private_key_der, msg)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA1024 => Ok(call_sign!(FNDSA1024Keypair, self.public_key_der, self.private_key_der, msg)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA44 => Ok(call_sign!(MLDSA44Keypair, self.public_key_der, self.private_key_der, msg)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA65 => Ok(call_sign!(MLDSA65Keypair, self.public_key_der, self.private_key_der, msg)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA87 => Ok(call_sign!(MLDSA87Keypair, self.public_key_der, self.private_key_der, msg)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128Sha2 => Ok(call_sign!(SLHDSA128FSHA2Keypair, self.public_key_der, self.private_key_der, msg)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192Sha2 => Ok(call_sign!(SLHDSA192FSHA2Keypair, self.public_key_der, self.private_key_der, msg)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256Sha2 => Ok(call_sign!(SLHDSA256FSHA2Keypair, self.public_key_der, self.private_key_der, msg)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128SHAKE => Ok(call_sign!(SLHDSA128FSHAKEKeypair, self.public_key_der, self.private_key_der, msg)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192SHAKE => Ok(call_sign!(SLHDSA192FSHAKEKeypair, self.public_key_der, self.private_key_der, msg)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256SHAKE => Ok(call_sign!(SLHDSA256FSHAKEKeypair, self.public_key_der, self.private_key_der, msg)),
        }
    }

    pub fn private_key_der(&self) -> Result<Vec<u8>, Error> {
        match self.algorithm {
            SignAlgorithm::Ed25519 => Ok(call_private_key_der!(Ed25519Keypair, self.public_key_der, self.private_key_der)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA512 => Ok(call_private_key_der!(FNDSA512Keypair, self.public_key_der, self.private_key_der)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA1024 => Ok(call_private_key_der!(FNDSA1024Keypair, self.public_key_der, self.private_key_der)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA44 => Ok(call_private_key_der!(MLDSA44Keypair, self.public_key_der, self.private_key_der)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA65 => Ok(call_private_key_der!(MLDSA65Keypair, self.public_key_der, self.private_key_der)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA87 => Ok(call_private_key_der!(MLDSA87Keypair, self.public_key_der, self.private_key_der)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128Sha2 => Ok(call_private_key_der!(SLHDSA128FSHA2Keypair, self.public_key_der, self.private_key_der)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192Sha2 => Ok(call_private_key_der!(SLHDSA192FSHA2Keypair, self.public_key_der, self.private_key_der)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256Sha2 => Ok(call_private_key_der!(SLHDSA256FSHA2Keypair, self.public_key_der, self.private_key_der)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128SHAKE => Ok(call_private_key_der!(SLHDSA128FSHAKEKeypair, self.public_key_der, self.private_key_der)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192SHAKE => Ok(call_private_key_der!(SLHDSA192FSHAKEKeypair, self.public_key_der, self.private_key_der)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256SHAKE => Ok(call_private_key_der!(SLHDSA256FSHAKEKeypair, self.public_key_der, self.private_key_der)),
        }
    }

    pub fn public_key_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self.public_key_der.clone())
    }

    pub fn verify(&self, msg: &[u8], sign: &[u8]) -> Result<bool, Error> {
        match self.algorithm {
            SignAlgorithm::Ed25519 => Ok(call_verify!(Ed25519Keypair, &self.public_key_der, msg, sign)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA512 => Ok(call_verify!(FNDSA512Keypair, &self.public_key_der, msg, sign)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA1024 => Ok(call_verify!(FNDSA1024Keypair, &self.public_key_der, msg, sign)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA44 => Ok(call_verify!(MLDSA44Keypair, &self.public_key_der, msg, sign)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA65 => Ok(call_verify!(MLDSA65Keypair, &self.public_key_der, msg, sign)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA87 => Ok(call_verify!(MLDSA87Keypair, &self.public_key_der, msg, sign)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128Sha2 => Ok(call_verify!(SLHDSA128FSHA2Keypair, &self.public_key_der, msg, sign)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192Sha2 => Ok(call_verify!(SLHDSA192FSHA2Keypair, &self.public_key_der, msg, sign)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256Sha2 => Ok(call_verify!(SLHDSA256FSHA2Keypair, &self.public_key_der, msg, sign)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128SHAKE => Ok(call_verify!(SLHDSA128FSHAKEKeypair, &self.public_key_der, msg, sign)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192SHAKE => Ok(call_verify!(SLHDSA192FSHAKEKeypair, &self.public_key_der, msg, sign)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256SHAKE => Ok(call_verify!(SLHDSA256FSHAKEKeypair, &self.public_key_der, msg, sign)),
        }
    }

    pub fn zeroize_private(&mut self) {
        self.private_key_der.zeroize();
    }

    pub fn from_keypair_der(private_key: Vec<u8>, public_key: Vec<u8>, algorithm: SignAlgorithm) -> Result<Self, Error> {
        match algorithm {
            SignAlgorithm::Ed25519 => Ok(generate_keypair_from_der!(Ed25519Keypair, SignAlgorithm::Ed25519, private_key, public_key)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA512 => Ok(generate_keypair_from_der!(FNDSA512Keypair, SignAlgorithm::FnDSA512, private_key, public_key)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::FnDSA1024 => Ok(generate_keypair_from_der!(FNDSA1024Keypair, SignAlgorithm::FnDSA1024, private_key, public_key)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA44 => Ok(generate_keypair_from_der!(MLDSA44Keypair, SignAlgorithm::MlDSA44, private_key, public_key)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA65 => Ok(generate_keypair_from_der!(MLDSA65Keypair, SignAlgorithm::MlDSA65, private_key, public_key)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::MlDSA87 => Ok(generate_keypair_from_der!(MLDSA87Keypair, SignAlgorithm::MlDSA87, private_key, public_key)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128Sha2 => Ok(generate_keypair_from_der!(SLHDSA128FSHA2Keypair, SignAlgorithm::SlhDSA128Sha2, private_key, public_key)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192Sha2 => Ok(generate_keypair_from_der!(SLHDSA192FSHA2Keypair, SignAlgorithm::SlhDSA192Sha2, private_key, public_key)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256Sha2 => Ok(generate_keypair_from_der!(SLHDSA256FSHA2Keypair, SignAlgorithm::SlhDSA256Sha2, private_key, public_key)),

            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA128SHAKE => Ok(generate_keypair_from_der!(SLHDSA128FSHAKEKeypair, SignAlgorithm::SlhDSA128SHAKE, private_key, public_key)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA192SHAKE => Ok(generate_keypair_from_der!(SLHDSA192FSHAKEKeypair, SignAlgorithm::SlhDSA192SHAKE, private_key, public_key)),
            #[cfg(feature = "pqcrypto")]
            SignAlgorithm::SlhDSA256SHAKE => Ok(generate_keypair_from_der!(SLHDSA256FSHAKEKeypair, SignAlgorithm::SlhDSA256SHAKE, private_key, public_key)),
        }
    }
}
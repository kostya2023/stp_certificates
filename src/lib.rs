// lib.rs
use thiserror::Error;
use yasna;

// Error
#[derive(Debug, Error)]
pub enum Error {
    #[error("Pem error: {0}")]
    PemError(String),
    #[error("ASN1 Parse Error: {0}")]
    ASN1Error(#[from] ASN1Wrapper),

    #[error("Error keypair generation: {0}")]
    KeypairGenerateError(String),
    #[error("Sign error: {0}")]
    SignError(String),
    #[error("Publickey error: {0}")]
    PublicKeyError(String),
    #[error("Verify error: {0}")]
    VerifySignatureError(String),
    #[error("PrivateKey error: {0}")]
    PrivateKeyError(String),
    #[error("PKCS#8 version invalid")]
    PKCS8VersionInvalid,
    #[error("Invalid algorithm")]
    InvalidAlgorithmError,
    #[error("Rand Error")]
    RandError,

    #[error("Duration Since Error")]
    DurationSinceError,
    #[error("Expired error: {0}")]
    CheckExpiredError(String),
}

// mods
pub mod algs;
pub mod certs;
pub mod extensions;
pub mod highlevel_keys;
pub mod oid;

/// Types and enums...


/// Костыль, но жить можно.
#[derive(Debug)]
pub struct ASN1Wrapper(yasna::ASN1Error);

impl std::fmt::Display for ASN1Wrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ASN1 parse error: {:?}", self.0)
    }
}

impl std::error::Error for ASN1Wrapper {}

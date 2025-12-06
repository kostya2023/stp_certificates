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

    #[error("Parse IPVersion error")]
    IPVersionError,
}

// mods
pub mod algs;
pub mod certs;
pub mod extensions;
pub mod highlevel_keys;
pub mod oid;

/// Types and enums...
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IPVersion {
    V4,
    V6,
}

impl IPVersion {
    #[inline]
    pub fn to_int(&self) -> u8 {
        match self {
            IPVersion::V4 => 4,
            IPVersion::V6 => 6,
        }
    }

    #[inline]
    pub fn from_int(int: u8) -> Result<Self, Error> {
        match int {
            4 => Ok(IPVersion::V4),
            6 => Ok(IPVersion::V6),
            _ => Err(Error::IPVersionError)
        }
    }
}


/// Костыль
#[derive(Debug)]
pub struct ASN1Wrapper(yasna::ASN1Error);

impl std::fmt::Display for ASN1Wrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ASN1 parse error: {:?}", self.0)
    }
}

impl std::error::Error for ASN1Wrapper {}

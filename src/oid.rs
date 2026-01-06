// oid.rs

use once_cell::sync::Lazy;
use yasna::models::ObjectIdentifier;

// === DIGESTS ===
pub static SHA3_256: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 8]));
pub static SHA3_512: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 10]));

// === EDDSA ===
pub static ED25519: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 101, 112]));

// === EXTENSIONS ===
pub static SUBJECT_KEY_ID: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 50, 1]));
pub static KEY_USAGE: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 50, 2]));
pub static SUBJECT_ALT_NAME: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 50, 3]));
pub static BASIC_CONSTRAINTS: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 50, 4]));
pub static NAME_CONSTRAINTS: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 50, 5]));
pub static CRL_DISTRIBUTION_POINTS: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 50, 6]));
pub static CERT_POLICIES: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 50, 7]));
pub static AUTH_KEY_ID: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 50, 8]));
pub static EXT_KEY_USAGE: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 50, 9]));

// === EXT KEY USAGE ===
pub static ANY_EXT_KEY_USAGE: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 37, 0]));
pub static SERVER_AUTH: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 3, 1]));
pub static CLIENT_AUTH: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 3, 2]));
pub static CODE_SIGNING: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 3, 3]));
pub static EMAIL_PROTECTION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 3, 4]));
pub static TIME_STAMPING: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 3, 8]));
pub static OCSP_SIGNING: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 3, 9]));

// === ATTRIBUTE TYPES ===
pub static COUNTRY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 4, 6]));
pub static ORGANIZATION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 4, 10]));
pub static ORG_UNIT: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 4, 11]));
pub static COMMON_NAME: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
pub static LOCALITY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 4, 7]));
pub static STATE: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 4, 8]));
pub static STREET: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 4, 9]));
pub static SERIAL_NUMBER: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 4, 5]));
pub static EMAIL: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 1]));

// === FNDSA ===
#[cfg(feature = "pqcrypto")]
pub static FNDSA: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1]));

#[cfg(feature = "pqcrypto")]
pub static PKCS8_FNDSA_PUBLIC_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1, 10, 2]));

#[cfg(feature = "pqcrypto")]
pub static PKCS8_FNDSA_PRIVATE_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1, 10, 1]));

#[cfg(feature = "pqcrypto")]
pub static FNDSA_512: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1, 5, 1]));

#[cfg(feature = "pqcrypto")]
pub static FNDSA_1024: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1, 5, 2]));

// === MLDSA ===
#[cfg(feature = "pqcrypto")]
pub static MLDSA: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2]));

#[cfg(feature = "pqcrypto")]
pub static PKCS8_MLDSA_PUBLIC_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 10, 2]));

#[cfg(feature = "pqcrypto")]
pub static PKCS8_MLDSA_PRIVATE_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 10, 1]));

#[cfg(feature = "pqcrypto")]
pub static MLDSA_44: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 5, 1]));

#[cfg(feature = "pqcrypto")]
pub static MLDSA_65: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 5, 2]));

#[cfg(feature = "pqcrypto")]
pub static MLDSA_87: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 5, 3]));

// === SLHDSA ===
#[cfg(feature = "pqcrypto")]
pub static SLHDSA: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3]));

#[cfg(feature = "pqcrypto")]
pub static PKCS8_SLHDSA_PUBLIC_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 10, 2]));

#[cfg(feature = "pqcrypto")]
pub static PKCS8_SLHDSA_PRIVATE_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 10, 1]));

#[cfg(feature = "pqcrypto")]
pub static SLHDSA_128F: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 5, 1]));

#[cfg(feature = "pqcrypto")]
pub static SLHDSA_192F: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 5, 2]));

#[cfg(feature = "pqcrypto")]
pub static SLHDSA_256F: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 5, 3]));

// === SLHDSA HASH PARAMETERS ===
#[cfg(feature = "pqcrypto")]
pub static SLHDSA_HASH_SHA2: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 20, 1]));

#[cfg(feature = "pqcrypto")]
pub static SLHDSA_HASH_SHAKE: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 20, 2]));

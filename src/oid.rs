use once_cell::sync::Lazy;
use yasna::models::ObjectIdentifier;

// === RSA (PKCS#1) ===
pub static RSA_ENCRYPTION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]));
pub static MD5_WITH_RSA_ENCRYPTION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 4]));
pub static SHA1_WITH_RSA_ENCRYPTION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 5]));
pub static SHA224_WITH_RSA_ENC: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 14]));
pub static SHA256_WITH_RSA_ENC: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 11]));
pub static SHA384_WITH_RSA_ENC: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 12]));
pub static SHA512_WITH_RSA_ENC: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 13]));
pub static RSASSA_PSS: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 10]));

// === DIGESTS ===
pub static SHA1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 14, 3, 2, 26]));
pub static SHA224: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 4]));
pub static SHA256: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 1]));
pub static SHA384: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 2]));
pub static SHA512: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 3]));

// === ECDSA ===
pub static EC_PUBLIC_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));
pub static ECDSA_WITH_SHA1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 1]));
pub static ECDSA_WITH_SHA224: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 1]));
pub static ECDSA_WITH_SHA256: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]));
pub static ECDSA_WITH_SHA384: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 3]));
pub static ECDSA_WITH_SHA512: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 4]));

// === EC CURVES ===
pub static PRIME256V1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));
pub static SECP384R1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 34]));
pub static SECP521R1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 35]));

// === EDDSA ===
pub static ED25519: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 101, 112]));
pub static ED448: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 101, 113]));

// === PKCS#8 ===
pub static PKCS8_PRIVATE_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 5, 13]));

// === EXTENSIONS (RFC 5280) ===
pub static SUBJECT_KEY_ID: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 14]));
pub static KEY_USAGE: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 15]));
pub static SUBJECT_ALT_NAME: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 17]));
pub static BASIC_CONSTRAINTS: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 19]));
pub static NAME_CONSTRAINTS: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 30]));
pub static CRL_DISTRIBUTION_POINTS: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 31]));
pub static CERT_POLICIES: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 32]));
pub static AUTH_KEY_ID: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 35]));
pub static EXT_KEY_USAGE: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 5, 29, 37]));

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
pub static FNDSA: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1]));

pub static PKCS8_FNDSA_PUBLIC_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1, 10, 2]));
pub static PKCS8_FNDSA_PRIVATE_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1, 10, 1]));

pub static FNDSA_512: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1, 5, 1]));
pub static FNDSA_1024: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 1, 5, 2]));

// === MLDSA ===
pub static MLDSA: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2]));

pub static PKCS8_MLDSA_PUBLIC_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 10, 2]));
pub static PKCS8_MLDSA_PRIVATE_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 10, 1]));

pub static MLDSA_44: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 5, 1]));
pub static MLDSA_65: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 5, 2]));
pub static MLDSA_87: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 2, 5, 3]));

// === SLHDSA ===
pub static SLHDSA: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3]));

pub static PKCS8_SLHDSA_PUBLIC_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 10, 2]));
pub static PKCS8_SLHDSA_PRIVATE_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 10, 1]));

pub static SLHDSA_128F: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 5, 1]));
pub static SLHDSA_192F: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 5, 2]));
pub static SLHDSA_256F: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 5, 3]));

// === SLHDSA HASH PARAMETERS ===
pub static SLHDSA_HASH_SHA2: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 20, 1]));
pub static SLHDSA_HASH_SHAKE: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 64696, 3, 20, 2]));

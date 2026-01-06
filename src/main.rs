// main.rs (unused)

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use stp_certificates::Serilizaton;
use stp_certificates::algs::{UniversalKeypair, SignAlgorithm};
use stp_certificates::certs::distinguished_name::DistinguishedName;
use stp_certificates::certs::generate::CertificateBuilder;
use stp_certificates::extensions::{Extension, Extensions};
use stp_certificates::highlevel_keys::AlgorithmIdentifier;
use stp_certificates::highlevel_keys::pem::pem_encode;
use stp_certificates::{extensions, oid};

fn main() {
    let keypair = UniversalKeypair::generate(SignAlgorithm::FnDSA512).unwrap();
    // let public_key = keypair.public_key_der().unwrap();

    let universal_issuer = DistinguishedName::new(
        "Test Certificate".to_string(),
        Some("Moscow".to_string()),
        Some("Russian Federation".to_string()),
        Some("RU".to_string()),
        Some("Foo org".to_string()),
        Some("Foo unit".to_string()),
        Some("Foo, Foo, foo bar 12".to_string()),
        Some("WTF? FOOO!!".to_string()),
    );

    let extension_san = extensions::subject_alternative_name::SubjectAlternativeName::new(
        "example.com".to_string(),
        std::net::IpAddr::V4(Ipv4Addr::from_bits(0x1234567)),
        "foo@example.com".to_string(),
        "example.com".to_string(),
        "directory_name foo".to_string(),
        "kavo?".to_string(),
        "Bar/Baz ;)".to_string(),
    );

    let extension = Extension::new(oid::SUBJECT_ALT_NAME.clone(), true, extension_san.to_der());

    let extensions = Extensions::new(vec![extension]);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build certificate using CertificateBuilder
    let spki_der = keypair.public_key_der().unwrap();
    let sig_alg = AlgorithmIdentifier::new(oid::FNDSA_512.clone(), None);

    let mut builder = CertificateBuilder::new(
        999999666666444444u64,
        sig_alg.clone(),
        &spki_der,
        now,
        now + 10 * 365 * 24 * 60 * 60,
        Some(extensions),
    )
    .expect("builder new");

    builder
        .issuer(universal_issuer.clone())
        .subject(universal_issuer.clone());

    let priv_der = keypair.private_key_der().unwrap();
    builder.sign(&priv_der).unwrap();

    let certificate = builder.as_struct().expect("signed certificate");

    println!("der encoded:\n {:?}\n", certificate.to_der());
    let pem = pem_encode("CERTIFICATE", certificate.to_der());
    println!("pem encoded:\n {}\n", pem);
}

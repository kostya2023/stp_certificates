// main.rs (unused)

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use stp_certificates::algs::AlgKeypair;
use stp_certificates::algs::fndsa::FNDSA512Keypair;
use stp_certificates::certs::Version;
use stp_certificates::certs::certificate::Certificate;
use stp_certificates::certs::distinguished_name::DistinguishedName;
use stp_certificates::certs::tbs_certificate::TbsCertificate;
use stp_certificates::certs::validity::Validity;
use stp_certificates::extensions::{Extension, ExtensionTrait, Extensions};
use stp_certificates::highlevel_keys::AlgorithmIdentifier;
use stp_certificates::highlevel_keys::pem::pem_encode;
use stp_certificates::highlevel_keys::publickey::SubjectPublicKeyInfo;
use stp_certificates::{extensions, oid};

fn main() {
    let keypair = FNDSA512Keypair::generate().unwrap();
    let public_key = keypair.public_key_der().unwrap();

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

    let extension = Extension::new(
        oid::SUBJECT_ALT_NAME.clone(), 
        true, 
        extension_san.to_der()
    );

    let extensions = Extensions::new(vec![extension]);

    let tbs_certificate = TbsCertificate::new(
        Version::V3, 
        999999666666444444u64, 
        AlgorithmIdentifier::new(oid::FNDSA_512.clone(), None), 
        universal_issuer.clone(), 
        Validity::new(SystemTime::now() + Duration::from_secs(10 * 365 * 24 * 60 * 60)), 
        universal_issuer.clone(), 
        SubjectPublicKeyInfo::from_der(&public_key).unwrap(), 
        Some(extensions),
    );

    let signature_value = keypair.sign(&tbs_certificate.to_der().unwrap()).unwrap();

    let certificate = Certificate::new(
        tbs_certificate, 
        AlgorithmIdentifier::new(oid::FNDSA_512.clone(), None), 
        &signature_value
    );


    println!("der encoded:\n {:?}\n", certificate.to_der().unwrap());
    let pem = pem_encode("CERTIFICATE", certificate.to_der().unwrap());
    println!("pem encoded:\n {}\n", pem);
    
}

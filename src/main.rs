// main.rs (unused)

use pqcrypto_falcon;
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use stp_certificates::highlevel_keys::AlgorithmIdentifier;
use stp_certificates::highlevel_keys::pem::pem_encode;
use stp_certificates::highlevel_keys::privatekey::PrivateKeyInfo;
use stp_certificates::highlevel_keys::publickey::SubjectPublicKeyInfo;

fn main() {
    let (public, private) = pqcrypto_falcon::falcon512::keypair();

    // Создание SigningKey
    let der = PrivateKeyInfo::new(
        0u64,
        AlgorithmIdentifier::new(stp_certificates::oid::FNDSA_512.clone(), None),
        &private.as_bytes(),
        None,
    )
    .to_der();
    println!("Privatekey der: {:?}\n", der);
    let pem = pem_encode("PRIVATE KEY", der);
    println!("Privatekey pem: \n{}\n", pem);

    // Получение публичного ключа
    let der = SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::new(stp_certificates::oid::FNDSA_512.clone(), None),
        &public.as_bytes(),
    )
    .to_der();
    println!("Publickey der: {:?}\n", der);
    let pem = pem_encode("PUBLIC KEY", der);
    println!("Publickey pem: \n{}\n", pem);
}

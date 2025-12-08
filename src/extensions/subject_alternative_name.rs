// extensions/subject_alternative_name.rs

use crate::Error;
use crate::extensions::ExtensionTrait;
use yasna;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectAlternativeName {
    pub dns_name: String,
    pub ip_address: IpAddr,
    pub email: String,
    pub uri: String,
    pub directory_name: String,
    pub registered_id: String,
    pub other_name: String,
}

impl SubjectAlternativeName {
    pub fn new(
        dns_name: String,
        ip_address: IpAddr,
        email: String,
        uri: String,
        directory_name: String,
        registered_id: String,
        other_name: String,
    ) -> Self {
        Self {
            dns_name,
            ip_address,
            email,
            uri,
            directory_name,
            registered_id,
            other_name,
        }
    }
}

impl ExtensionTrait for SubjectAlternativeName {
    fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|seq| {
                seq.next().write_ia5_string(&self.dns_name);

                // IP
                match self.ip_address {
                    IpAddr::V4(v4) => seq.next().write_bytes(&v4.octets()),
                    IpAddr::V6(v6) => seq.next().write_bytes(&v6.octets()),
                }

                seq.next().write_ia5_string(&self.email);
                seq.next().write_ia5_string(&self.uri);
                seq.next().write_utf8_string(&self.directory_name);
                seq.next().write_utf8_string(&self.registered_id);
                seq.next().write_utf8_string(&self.other_name);
            });
        })
    }

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let (dns, ip, email, uri, dn, rid, on) =
            yasna::parse_der(der, |reader| {
                reader.read_sequence(|seq| {
                    let dns = seq.next().read_ia5_string()?;

                    let ip_bytes = seq.next().read_bytes()?;
                    let ip = match ip_bytes.len() {
                        4 => IpAddr::V4(Ipv4Addr::new(
                            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                        )),
                        16 => {
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(&ip_bytes);
                            IpAddr::V6(Ipv6Addr::from(arr))
                        }
                        _ => return Err(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid)),
                    };

                    let email = seq.next().read_ia5_string()?;
                    let uri = seq.next().read_ia5_string()?;
                    let dn = seq.next().read_utf8string()?;
                    let rid = seq.next().read_utf8string()?;
                    let on = seq.next().read_utf8string()?;

                    Ok((dns, ip, email, uri, dn, rid, on))
                })
            }).map_err(|e| Error::ASN1Error(crate::ASN1Wrapper(e)))?;

        Ok(Self {
            dns_name: dns,
            ip_address: ip,
            email,
            uri,
            directory_name: dn,
            registered_id: rid,
            other_name: on,
        })
    }
}

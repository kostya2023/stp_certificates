// good_api/pem.rs
use crate::Error;
/// Реализация удобного API для pem энкодинга и декодинга.
use pem::{Pem, encode, parse};

/// Функция для encode любых байтовых данных в PEM
pub fn pem_encode<T: ToString, B: AsRef<[u8]>>(tag: T, data: B) -> String {
    let tag_string = tag.to_string();
    let pem_data = Pem::new(&tag_string, data.as_ref());
    encode(&pem_data)
}

/// Функция для декодирования любых байтовых данных из PEM.
pub fn pem_decode<B: AsRef<[u8]>>(pem_data: B) -> Result<(String, Vec<u8>), Error> {
    let pem_parsed = parse(pem_data).map_err(|e| Error::PemError(e.to_string()))?;
    Ok((pem_parsed.tag().to_string(), pem_parsed.into_contents()))
}

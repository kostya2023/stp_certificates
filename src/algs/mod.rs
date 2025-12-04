pub mod eddsa;
pub mod falcon;
use crate::Error;

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

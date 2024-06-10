use aes_gcm::aead::{AeadInPlace, KeyInit, OsRng};
use aes_gcm::Aes256Gcm;
use base64::{decode, encode};
use generic_array::GenericArray;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::error::Error;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_SIZE: usize = 32;

#[derive(Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    pub id: i32,
    pub site: String,
    pub username: String,
    pub password: String,
}

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

pub fn encrypt(password: &str, data: &str) -> Result<String, Box<dyn Error>> {
    let salt: [u8; 16] = OsRng.gen();
    let key = derive_key_from_password(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let nonce: [u8; 12] = OsRng.gen();
    let mut buffer = data.as_bytes().to_vec();
    cipher
        .encrypt_in_place(&GenericArray::from_slice(&nonce), b"", &mut buffer)
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut result = vec![];
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&buffer);
    Ok(encode(&result))
}

pub fn decrypt(password: &str, encrypted_data: &str) -> Result<String, Box<dyn Error>> {
    let data = decode(encrypted_data)?;
    let (salt, rest) = data.split_at(16);
    let (nonce, ciphertext) = rest.split_at(12);

    let key = derive_key_from_password(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place(&GenericArray::from_slice(nonce), b"", &mut buffer)
        .map_err(|e| format!("Decryption error: {}", e))?;

    Ok(String::from_utf8(buffer)?)
}

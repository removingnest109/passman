use serde::{Serialize, Deserialize};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{KeyInit, OsRng, AeadInPlace, Nonce};
use rand::Rng;
use sha2::Sha256;
use pbkdf2::pbkdf2;
use base64::{encode, decode};
use std::fs;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

#[derive(Serialize, Deserialize)]
pub struct PasswordEntry {
    pub site: String,
    pub username: String,
    pub password: String,
}

pub struct PasswordManager {
    pub entries: Vec<PasswordEntry>,
}

impl PasswordManager {
    pub fn new() -> Self {
        PasswordManager { entries: Vec::new() }
    }

    pub fn add_entry(&mut self, site: String, username: String, password: String) {
        self.entries.push(PasswordEntry { site, username, password });
    }

    pub fn remove_entry(&mut self, site: &str) {
        self.entries.retain(|entry| entry.site != site);
    }

    pub fn update_entry(&mut self, site: &str, username: String, password: String) {
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.site == site) {
            entry.username = username;
            entry.password = password;
        }
    }

    pub fn get_entry(&self, site: &str) -> Option<&PasswordEntry> {
        self.entries.iter().find(|entry| entry.site == site)
    }

    pub fn save_to_file(&self, file_path: &str, master_password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&self.entries)?;
        let encrypted_data = encrypt(master_password, &json)?;
        fs::write(file_path, encrypted_data)?;
        Ok(())
    }

    pub fn load_from_file(file_path: &str, master_password: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let encrypted_data = fs::read_to_string(file_path)?;
        let json = decrypt(master_password, &encrypted_data)?;
        let entries: Vec<PasswordEntry> = serde_json::from_str(&json)?;
        Ok(PasswordManager { entries })
    }
}

fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

fn encrypt(password: &str, data: &str) -> Result<String, Box<dyn std::error::Error>> {
    let salt: [u8; 16] = OsRng.gen();
    let key = derive_key_from_password(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let nonce: [u8; NONCE_SIZE] = OsRng.gen();
    let mut buffer = data.as_bytes().to_vec();
    cipher.encrypt_in_place(&Nonce::from_slice(&nonce), b"", &mut buffer)
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut result = vec![];
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&buffer);
    Ok(encode(&result))
}

fn decrypt(password: &str, encrypted_data: &str) -> Result<String, Box<dyn std::error::Error>> {
    let data = decode(encrypted_data)?;
    let (salt, rest) = data.split_at(16);
    let (nonce, ciphertext) = rest.split_at(NONCE_SIZE);

    let key = derive_key_from_password(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let mut buffer = ciphertext.to_vec();
    cipher.decrypt_in_place(&Nonce::from_slice(nonce), b"", &mut buffer)
        .map_err(|e| format!("Decryption error: {}", e))?;

    Ok(String::from_utf8(buffer)?)
}

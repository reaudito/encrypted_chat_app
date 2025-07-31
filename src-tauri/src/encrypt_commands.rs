use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTicket {
    room_address: String,
    encrypted_keys: HashMap<String, String>, // pubkey_base64 -> encrypted AES key (base64)
}

#[tauri::command]
fn encrypt_message(msg: String, room_key_b64: String) -> Result<String, String> {
    let key_bytes = STANDARD.decode(&room_key_b64).map_err(|e| e.to_string())?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, msg.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{}:{}",
        STANDARD.encode(nonce),
        STANDARD.encode(ciphertext)
    ))
}

#[tauri::command]
fn decrypt_message(enc_msg: String, room_key_b64: String) -> Result<String, String> {
    let parts: Vec<&str> = enc_msg.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid encrypted message format".into());
    }
    let nonce_bytes = STANDARD.decode(parts[0]).map_err(|e| e.to_string())?;
    let cipher_bytes = STANDARD.decode(parts[1]).map_err(|e| e.to_string())?;
    let key_bytes = STANDARD.decode(&room_key_b64).map_err(|e| e.to_string())?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|e| e.to_string())?;
    String::from_utf8(plaintext).map_err(|e| e.to_string())
}

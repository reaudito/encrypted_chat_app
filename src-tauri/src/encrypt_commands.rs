use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::collections::HashMap;
use tauri::AppHandle;
use tauri_plugin_store::StoreExt;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTicket {
    pub room_name: String,
    encrypted_keys: HashMap<String, String>,
}
#[tauri::command]
pub fn encrypt_message(msg: String, room_key_b64: String) -> Result<String, String> {
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
pub fn decrypt_message(enc_msg: String, room_key_b64: String) -> Result<String, String> {
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

#[tauri::command]
pub fn generate_identity_keypair() -> Result<(String, String), String> {
    let secret = StaticSecret::new(OsRng);
    let public = PublicKey::from(&secret);
    Ok((
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(public.as_bytes()),
    ))
}

#[tauri::command]
pub fn encrypt_room_key_for_user(
    room_key_b64: String,
    user_pub_b64: String,
    sender_secret_b64: String,
) -> Result<String, String> {
    let room_key = STANDARD.decode(&room_key_b64).map_err(|e| e.to_string())?;
    let user_pub_bytes = STANDARD.decode(&user_pub_b64).map_err(|e| e.to_string())?;
    let sender_secret_bytes = STANDARD
        .decode(&sender_secret_b64)
        .map_err(|e| e.to_string())?;

    let user_pub = PublicKey::from(
        <[u8; 32]>::try_from(user_pub_bytes.as_slice()).map_err(|_| "invalid pubkey")?,
    );
    let sender_secret = StaticSecret::from(
        <[u8; 32]>::try_from(sender_secret_bytes.as_slice()).map_err(|_| "invalid secret")?,
    );

    let shared_secret = sender_secret.diffie_hellman(&user_pub);
    let shared_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(shared_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted = cipher
        .encrypt(&nonce, room_key.as_slice())
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{}:{}",
        STANDARD.encode(nonce),
        STANDARD.encode(encrypted)
    ))
}

#[tauri::command]
pub fn decrypt_room_key_from_sender(
    encrypted_room_key: String,
    sender_pub_b64: String,
    receiver_secret_b64: String,
) -> Result<String, String> {
    let parts: Vec<&str> = encrypted_room_key.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid encrypted format".into());
    }
    let nonce_bytes = STANDARD.decode(parts[0]).map_err(|e| e.to_string())?;
    let cipher_bytes = STANDARD.decode(parts[1]).map_err(|e| e.to_string())?;

    let sender_pub_bytes = STANDARD
        .decode(&sender_pub_b64)
        .map_err(|e| e.to_string())?;
    let receiver_secret_bytes = STANDARD
        .decode(&receiver_secret_b64)
        .map_err(|e| e.to_string())?;

    let sender_pub = PublicKey::from(
        <[u8; 32]>::try_from(sender_pub_bytes.as_slice()).map_err(|_| "Invalid pubkey")?,
    );
    let receiver_secret = StaticSecret::from(
        <[u8; 32]>::try_from(receiver_secret_bytes.as_slice()).map_err(|_| "Invalid secret")?,
    );

    let shared_secret = receiver_secret.diffie_hellman(&sender_pub);
    let shared_key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(shared_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let decrypted = cipher
        .decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|e| e.to_string())?;

    Ok(STANDARD.encode(decrypted))
}

#[tauri::command]
pub async fn store_access_ticket(app: AppHandle, ticket: AccessTicket) -> Result<(), String> {
    let store = app.store("tickets.json").map_err(|e| e.to_string())?;

    let mut list: Vec<AccessTicket> = store
        .get("tickets")
        .unwrap_or(json!([]))
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .collect();

    list.push(ticket);
    store.set("tickets", json!(list));
    store.save().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn get_all_access_tickets(app: AppHandle) -> Result<String, String> {
    let store = app.store("tickets.json").map_err(|e| e.to_string())?;
    let val = store.get("tickets").unwrap_or_default();
    Ok(val.to_string())
}

#[tauri::command]
pub async fn load_access_ticket_by_room(
    app: AppHandle,
    room_name: String,
) -> Result<Option<AccessTicket>, String> {
    let store = app.store("tickets.json").map_err(|e| e.to_string())?;
    let list: Vec<AccessTicket> = store
        .get("tickets")
        .unwrap_or(json!([]))
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect();

    Ok(list.into_iter().find(|t| t.room_name == room_name))
}

#[tauri::command]
pub async fn remove_access_ticket_by_room(app: AppHandle, room_name: String) -> Result<(), String> {
    let store = app.store("tickets.json").map_err(|e| e.to_string())?;

    let list: Vec<AccessTicket> = store
        .get("tickets")
        .unwrap_or(json!([]))
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .filter(|t: &AccessTicket| t.room_name != room_name)
        .collect();

    store.set("tickets", json!(list));
    store.save().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn update_access_ticket(app: AppHandle, updated: AccessTicket) -> Result<(), String> {
    let store = app.store("tickets.json").map_err(|e| e.to_string())?;

    let mut list: Vec<AccessTicket> = store
        .get("tickets")
        .unwrap_or(json!([]))
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect();

    let index = list
        .iter()
        .position(|t: &AccessTicket| t.room_name == updated.room_name);

    if let Some(i) = index {
        list[i] = updated;
    } else {
        list.push(updated);
    }

    store.set("tickets", json!(list));
    store.save().map_err(|e| e.to_string())?;
    Ok(())
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
pub mod encrypt_commands;

use crate::encrypt_commands::{
    decrypt_message, decrypt_room_key_from_sender, encrypt_message, encrypt_room_key_for_user,
    generate_identity_keypair, get_all_access_tickets, greet, load_access_ticket_by_room,
    remove_access_ticket_by_room, store_access_ticket, update_access_ticket,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            decrypt_message,
            decrypt_room_key_from_sender,
            encrypt_message,
            encrypt_room_key_for_user,
            generate_identity_keypair,
            get_all_access_tickets,
            greet,
            load_access_ticket_by_room,
            remove_access_ticket_by_room,
            store_access_ticket,
            update_access_ticket
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

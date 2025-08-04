use crate::components::common::global_state::{GlobalState, GlobalStateStoreFields};
use crate::components::navigation::nav::Nav;
use crate::components::signing::accounts_store::AccountStore;
use codee::string::JsonSerdeCodec;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos_use::storage::use_local_storage;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use reactive_stores::Store;
use serde::{Deserialize, Serialize};
use subxt_core::utils::AccountId32;
use subxt_signer::{bip39::Mnemonic, sr25519::Keypair};
use thiserror::Error;

#[derive(Error, Debug, Clone, Deserialize, Serialize)]
pub enum PhraseFromPassError {
    #[error("Password is empty")]
    PasswordEmpty,
    #[error("Error parsing to number: `{0}`")]
    ParseIntError(String),
}

#[component]
pub fn SetPhraseFromPass() -> impl IntoView {
    let (password, set_password) = signal(Ok("".to_string()));
    let state = expect_context::<Store<GlobalState>>();
    let (error, set_error) = signal("".to_string());

    let account = state.account_address();
    let mnemonic_phrase = state.mnemonic_phrase();
    let phase_exists_in_state = state.phase_exists_in_state();
    let (account_store, _set_account_store, _reset_account_store) =
        use_local_storage::<AccountStore, JsonSerdeCodec>("account-store-state");

    let set_password_input = move |ev| {
        let password_string = event_target_value(&ev);
        gloo::console::log!(password_string.clone());
        let result = if password_string.is_empty() {
            gloo::console::log!("String is empty");

            Err(PhraseFromPassError::PasswordEmpty)
        } else {
            Ok(password_string)
        };
        set_password(result);
    };
    let handle_select_account = move |hash: String, address: String| {
        let mc = new_magic_crypt!(password().unwrap(), 256);
        match mc.decrypt_base64_to_string(&hash) {
            Ok(seed) => {
                *account.write() = address;
                *mnemonic_phrase.write() = Some(seed);
                *phase_exists_in_state.write() = true;
            }
            Err(e) => {
                gloo::console::error!("Failed to decrypt seed:", e.to_string());
                set_error("Failed to decrypt seed".to_string());
            }
        }
    };
    view! {
        <>
            <main class="p-6 max-w-4xl mx-auto bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 min-h-screen transition-colors duration-300">
                <div>
                    <form class="max-w-sm mx-auto" id="seed-submit-form">
                        <div class="mb-5">
                            <label
                                for="password"
                                class="block mb-2 text-sm font-medium text-gray-900 dark:text-white"
                            >
                                Your password
                            </label>

                            <input
                                type="password"
                                id="password"
                                class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                                required
                                prop:value=move || password().clone().unwrap_or_default()
                                on:input=move |e| {
                                    set_password_input(e);
                                    set_error(String::new());
                                }
                            />
                        </div>
                    </form>
                    <div>

                        {move || {
                            if !error().is_empty() {
                                view! {
                                    <div
                                        role="alert"
                                        class="flex  p-4 items-center gap-3 border-l-4 border-yellow-500 bg-yellow-100 text-yellow-800 rounded-xl shadow-md dark:bg-yellow-900 dark:text-yellow-200"
                                    >
                                        {error()}
                                    </div>
                                }
                                    .into_view()
                                    .into_any()
                            } else {
                                view! { <></> }.into_view().into_any()
                            }
                        }}
                    </div>

                    {move || {
                        if let Ok(ref pwd) = password() {
                            if !pwd.is_empty() {
                                view! {
                                    <div class="mt-6 max-w-4xl mx-auto">
                                        <h3 class="text-lg font-semibold mb-2 text-gray-900 dark:text-white">
                                            Select Account
                                        </h3>
                                        <ul class="space-y-2">
                                            {move || {
                                                account_store
                                                    .with(|store| {
                                                        store
                                                            .accounts
                                                            .iter()
                                                            .map(|a| {
                                                                let hash = a.hash.clone();
                                                                let address = a.account_address.clone();
                                                                let name = a.name.clone();

                                                                view! {
                                                                    <li>
                                                                        <button
                                                                            type="button"
                                                                            class="w-full text-left p-2 rounded-md hover:bg-blue-100 dark:hover:bg-gray-700 text-gray-900 dark:text-white"
                                                                            id={format!("account-{}", address.clone())}
                                                                            on:click=move |_| {
                                                                                handle_select_account(hash.clone(), address.clone());
                                                                            }
                                                                        >
                                                                            {name.clone()}
                                                                            :
                                                                            {address.clone()}
                                                                        </button>
                                                                    </li>
                                                                }
                                                            })
                                                            .collect::<Vec<_>>()
                                                    })
                                            }}
                                        </ul>
                                    </div>
                                }
                                    .into_any()
                            } else {
                                ().into_any()
                            }
                        } else {
                            ().into_any()
                        }
                    }}
                </div>
            </main>
        </>
    }
}

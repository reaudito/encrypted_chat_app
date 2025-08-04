use crate::components::navigation::nav::Nav;
use crate::components::signing::accounts_store::{Account, AccountStore};
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::use_local_storage;
use serde::{Deserialize, Serialize};

#[component]
pub fn DeleteAccount() -> impl IntoView {
    let (account_store, set_account_store, _) =
        use_local_storage::<AccountStore, JsonSerdeCodec>("account-store-state");

    // Function to handle deleting an account
    let delete_account = move |address_to_delete: String| {
        set_account_store.update(move |store| {
            store
                .accounts
                .retain(|acc| acc.account_address != address_to_delete);
        });
    };

    view! {
        <>
            <Nav />
            <div class="p-6 max-w-4xl mx-auto bg-white dark:bg-gray-800 rounded-lg shadow-md">
                <h2 class="text-xl font-bold mb-4 text-gray-900 dark:text-white">Delete Account</h2>

                {move || {
                    let accounts = account_store().accounts;
                    if accounts.is_empty() {

                        view! { <p class="text-gray-700 dark:text-gray-300">No accounts found.</p> }
                            .into_any()
                    } else {
                        accounts
                            .into_iter()
                            .map(|account| {
                                let address = account.account_address.clone();
                                let name = account.name.clone();

                                view! {
                                    <div class="flex justify-between items-center p-2 border-b border-gray-300 dark:border-gray-600">
                                        <div>
                                            <p class="font-medium text-gray-900 dark:text-white">
                                                {name}
                                            </p>
                                            <p class="text-sm text-gray-500 dark:text-gray-400">
                                                {address.clone()}
                                            </p>
                                        </div>
                                        <button
                                            type="button"
                                            class="px-3 py-1 bg-red-600 text-white text-sm rounded hover:bg-red-700 focus:outline-none"
                                            on:click=move |_| delete_account(address.clone())
                                        >
                                            Delete
                                        </button>
                                    </div>
                                }
                            })
                            .collect::<Vec<_>>()
                            .into_any()
                    }
                }}
            </div>
        </>
    }
}

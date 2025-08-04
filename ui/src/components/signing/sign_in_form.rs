use crate::components::common::global_state::{GlobalState, GlobalStateStoreFields};
use crate::components::navigation::nav::Nav;
use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;
use reactive_stores::Store;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;
}

#[derive(Serialize, Deserialize)]
struct SignInArgs {
    seed: String,
    account_id: String,
}

#[component]
pub fn SignInForm() -> impl IntoView {
    let (seed, set_seed) = signal(String::new());
    let (account_id, set_account_id) = signal(String::new());
    let (loading, set_loading) = signal(false);
    let (message, set_message) = signal::<Option<Result<String, String>>>(None);
    let state = expect_context::<Store<GlobalState>>();

    let account = state.account_state();

    let handle_submit = move |ev: SubmitEvent| {
        ev.prevent_default();

        let current_seed = seed.get();
        let current_account_id = account_id.get();

        if current_seed.is_empty() || current_account_id.is_empty() {
            set_message.set(Some(Err("Both fields are required".into())));
            return;
        }

        set_loading.set(true);
        set_message.set(None);

        spawn_local(async move {
            let args = SignInArgs {
                seed: current_seed,
                account_id: current_account_id,
            };

            let js_args = match serde_wasm_bindgen::to_value(&args) {
                Ok(v) => v,
                Err(e) => {
                    set_message.set(Some(Err(format!("Serialization error: {}", e))));
                    set_loading.set(false);
                    return;
                }
            };

            let result = invoke("sign_in", js_args).await;

            if let Some(account_id) = result.as_string() {
                set_message.set(Some(Ok(account_id.clone())));
                *account.write() = account_id;
            } else {
                set_message.set(Some(Err("Invalid response format".into())));
            }

            set_loading.set(false);
        });
    };

    view! {
        <>
            <Nav />
            <div class="min-h-screen bg-white dark:bg-gray-900">
                <br />
                <br />
                <form on:submit=handle_submit class="max-w-md mx-auto p-4 space-y-4">
                    <div class="space-y-2">
                        <label class="block text-sm font-medium dark:text-white" for="seed">
                            Seed Phrase
                        </label>
                        <input
                            id="seed"
                            type="text"
                            class="w-full p-2 border rounded dark:bg-gray-800 dark:text-white"
                            prop:value=seed
                            on:input=move |e| set_seed.set(event_target_value(&e))
                        />
                    </div>

                    <div class="space-y-2">
                        <label class="block text-sm font-medium dark:text-white" for="account_id">
                            Account ID
                        </label>
                        <input
                            id="account_id"
                            type="text"
                            class="w-full p-2 border rounded dark:bg-gray-800 dark:text-white"
                            prop:value=account_id
                            on:input=move |e| set_account_id.set(event_target_value(&e))
                        />
                    </div>

                    <button
                        type="submit"
                        class="w-full px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:bg-gray-400"
                        disabled=move || loading.get()
                    >
                        {move || { if loading.get() { "Signing In..." } else { "Sign In" } }}
                    </button>

                    {move || {
                        message
                            .get()
                            .map(|msg| match msg {
                                Ok(account_id) => {
                                    view! {
                                        <div class="mt-4 p-2 bg-green-100 text-green-700 rounded">
                                            "Signed in successfully! Account ID: " {account_id}
                                        </div>
                                    }
                                        .into_view()
                                        .into_any()
                                }
                                Err(err) => {
                                    view! {
                                        <div class="mt-4 p-2 bg-red-100 text-red-700 rounded">
                                            {err}
                                        </div>
                                    }
                                        .into_view()
                                        .into_any()
                                }
                            })
                    }}
                </form>
            </div>
        </>
    }
}

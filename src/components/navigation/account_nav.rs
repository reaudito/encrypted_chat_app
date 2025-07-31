use crate::components::common::global_state::{GlobalState, GlobalStateStoreFields};
use crate::components::signing::accounts_store::AccountStore;
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_icons::*;
use leptos_use::storage::use_local_storage;
use reactive_stores::Store;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;

use leptos_use::{
    use_clipboard_with_options, use_permission, UseClipboardOptions, UseClipboardReturn,
};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke)]
    async fn invoke_without_args(cmd: &str) -> JsValue;
}

#[component]
pub fn AccountNav() -> impl IntoView {
    let state = expect_context::<Store<GlobalState>>();

    let account = state.account_address();

    let UseClipboardReturn {
        is_supported,
        text,
        copied,
        copy,
    } = use_clipboard_with_options(UseClipboardOptions::default().read(true));

    view! {
        <>
            {move || {
                let full_id = account.get();
                let shortened_id = if full_id.len() > 8 {
                    format!("{}...{}", &full_id[..8], &full_id[full_id.len() - 4..])
                } else {
                    full_id.clone()
                };
                if !shortened_id.is_empty() {
                    view! {
                        <>
                            <span>{shortened_id}</span>

                            <button on:click={
                                let copy = copy.clone();
                                move |_| copy(&full_id)
                            }>
                                <Show
                                    when=copied
                                    fallback=|| {
                                        view! { <Icon icon=icondata::AiCopyOutlined /> }
                                    }
                                >
                                    Copied!
                                </Show>
                            </button>
                        </>
                    }
                        .into_any()
                } else {
                    view! {
                        <>
                        <a
                            href="/sign-in"
                        >
                            "Sign In"
                        </a>
                        </>
                    }
                        .into_any()
                }
            }}
        </>
    }
}

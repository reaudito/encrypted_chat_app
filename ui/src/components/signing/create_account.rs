use crate::components::navigation::nav::Nav;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_icons::*;
use leptos_use::{use_clipboard_with_options, UseClipboardOptions, UseClipboardReturn};

use wasm_bindgen::prelude::*;

mod commands {
    use super::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = invoke)]
        async fn invoke_without_args(cmd: &str) -> JsValue;
    }

    pub async fn create_seed() -> String {
        invoke_without_args("create_seed")
            .await
            .as_string()
            .unwrap()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum AppState {
    Idle,
    ShowingSeed,
    ConfirmingSeed,
}

#[component]
pub fn CreateAccount() -> impl IntoView {
    let (app_state, set_app_state) = signal(AppState::Idle);
    let (seed_phrase, set_seed_phrase) = signal(None::<String>);
    let (word_inputs, set_word_inputs) = signal(vec![String::new(); 12]);
    let (is_match, set_is_match) = signal(None::<bool>);

    let UseClipboardReturn {
        is_supported,
        text,
        copied,
        copy,
    } = use_clipboard_with_options(UseClipboardOptions::default().read(true));

    let generate_seed = move |_| {
        spawn_local(async move {
            let s = commands::create_seed().await;
            set_seed_phrase.set(Some(s));
            set_app_state.set(AppState::ShowingSeed);
        });
    };

    let confirm_seed = move |_| {
        if let Some(ref phrase) = seed_phrase.get() {
            let original_words: Vec<String> = phrase.split_whitespace().map(String::from).collect();
            let entered_words: Vec<String> = word_inputs.get().into_iter().collect();

            set_is_match.set(Some(original_words == entered_words));
        }
    };

    let confirm_seed_button = move |_| {
        set_app_state.set(AppState::ConfirmingSeed);
    };

    let update_word_input = move |index: usize, value: String| {
        set_word_inputs.update(move |words| {
            words[index] = value;
        });
    };

    view! {
        <>
            <Nav />
            <main class="p-6 max-w-2xl mx-auto bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 min-h-screen transition-colors duration-300">
                <h1 class="text-2xl font-bold mb-4 text-center">Seed Phrase Verification</h1>

                {move || match app_state.get() {
                    AppState::Idle => {
                        view! {
                            <>
                                <button
                                    on:click=generate_seed
                                    class="w-full bg-blue-500 hover:bg-blue-600 dark:bg-blue-600 dark:hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded shadow transition"
                                >
                                    Generate Seed
                                </button>

                                <p class="mt-4 text-center text-gray-600 dark:text-gray-400">
                                    "Click 'Generate Seed' to begin."
                                </p>
                            </>
                        }
                            .into_view()
                            .into_any()
                    }
                    AppState::ShowingSeed => {
                        match seed_phrase.get() {
                            Some(ref phrase) => {

                                view! {
                                    <div class="mt-6 space-y-6 animate-fade-in-down">
                                        <div class="space-y-2">
                                            <p class="font-semibold text-center">
                                                Please save this seed:
                                            </p>
                                            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                                                <pre class="bg-gray-100 dark:bg-gray-800 p-4 rounded-md overflow-x-auto font-mono text-sm border border-gray-300 dark:border-gray-700 flex-1">
                                                    {phrase.clone()}

                                                </pre>

                                                <button
                                                    on:click={
                                                        let copy = copy.clone();
                                                        move |_| copy(&seed_phrase().unwrap())
                                                    }
                                                    class="whitespace-nowrap self-end bg-blue-500 hover:bg-blue-600 dark:bg-blue-600 dark:hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded transition"
                                                >
                                                    <Show
                                                        when=copied
                                                        fallback=|| {
                                                            view! { <Icon icon=icondata::AiCopyOutlined /> }
                                                        }
                                                    >
                                                        Copied!
                                                    </Show>
                                                </button>
                                            </div>
                                        </div>

                                        <hr class="my-6 border-gray-300 dark:border-gray-700" />

                                        <button
                                            on:click=confirm_seed_button
                                            class="w-full bg-blue-500 hover:bg-blue-600 dark:bg-blue-600 dark:hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded shadow transition"
                                        >
                                            "Confirm Seed"
                                        </button>

                                    </div>
                                }
                                    .into_view()
                                    .into_any()
                            }
                            None => {

                                view! {
                                    <p class="mt-4 text-center text-gray-600 dark:text-gray-400">
                                        "Error: Seed not found."
                                    </p>
                                }
                                    .into_view()
                                    .into_any()
                            }
                        }
                    }
                    AppState::ConfirmingSeed => {

                        view! {
                            <div class="mt-6 space-y-6 animate-fade-in-down">
                                <div class="space-y-4">
                                    <h2 class="text-xl font-semibold text-center">Confirm Seed</h2>
                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                        {move || {
                                            word_inputs
                                                .get()
                                                .into_iter()
                                                .enumerate()
                                                .map(|(i, val)| {
                                                    view! {
                                                        <input
                                                            on:input=move |ev| update_word_input(
                                                                i,
                                                                event_target_value(&ev),
                                                            )
                                                            prop:value=val
                                                            placeholder=format!("Word {}", i + 1)
                                                            type="text"
                                                            class="p-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 transition"
                                                        />
                                                    }
                                                })
                                                .collect::<Vec<_>>()
                                        }}

                                    </div>

                                    <button
                                        on:click=confirm_seed
                                        class="w-full bg-green-500 hover:bg-green-600 dark:bg-green-600 dark:hover:bg-green-700 text-white font-semibold py-2 px-4 rounded shadow transition mt-4"
                                    >
                                        Confirm
                                    </button>
                                </div>

                                {move || match is_match.get() {
                                    Some(true) => {
                                        view! {
                                            <p class="text-green-600 dark:text-green-400 mt-2 text-center font-medium">
                                                "✅ Match confirmed!"
                                            </p>
                                        }
                                            .into_any()
                                    }
                                    Some(false) => {
                                        view! {
                                            <p class="text-red-600 dark:text-red-400 mt-2 text-center font-medium">
                                                "❌ One or more words do not match."
                                            </p>
                                        }
                                            .into_any()
                                    }
                                    None => ().into_view().into_any(),
                                }}
                            </div>
                        }
                            .into_view()
                            .into_any()
                    }
                }}
            </main>
        </>
    }
}

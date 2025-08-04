use crate::components::common::global_state::{GlobalState, GlobalStateStoreFields};
use crate::components::navigation::nav::Nav;
use leptos::prelude::*;
use reactive_stores::Store;

#[component]
pub fn SignOut() -> impl IntoView {
    let state = expect_context::<Store<GlobalState>>();
    let account = state.account_address();
    let mnemonic_phrase = state.mnemonic_phrase();
    let phase_exists_in_state = state.phase_exists_in_state();
    let navigate = leptos_router::hooks::use_navigate();
    view! {
        <>
            <Nav />
            <main class="p-6 max-w-4xl mx-auto bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 min-h-screen transition-colors duration-300">
                <div>
                    <button
                        class="px-4 py-2 bg-red-600 text-white font-semibold rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
                        on:click=move |_| {
                            *account.write() = "".to_string();
                            *mnemonic_phrase.write() = None;
                            *phase_exists_in_state.write() = false;
                            navigate("/sign-in", Default::default());

                        }
                    >
                        "Sign Out"
                    </button>
                </div>
            </main>
        </>
    }
}

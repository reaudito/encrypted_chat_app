use crate::components::navigation::nav::Nav;
use crate::components::signing::set_phrase_from_pass::SetPhraseFromPass;
use leptos::prelude::*;

#[component]
pub fn EnterPassWithNav() -> impl IntoView {
    view! {
        <>
            <Nav />

            <div class="flex justify-center">
                <h2 class="bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100">"Sign In with Password"</h2>
            </div>
            <SetPhraseFromPass />
        </>
    }
}

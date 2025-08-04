use crate::components::navigation::nav::Nav;
use crate::pages::background::Background;
use crate::pages::features::Features;
use crate::pages::milestone::MilestoneTimeline;
use leptos::prelude::*;

#[component]
pub fn Home() -> impl IntoView {
    view! {
        <>
            <Nav />

            <Background />

            // <!-- Hero Section -->
            <section class="bg-white dark:bg-slate-800 py-12">
                <div class="container mx-auto px-6">
                    <div class="flex flex-col items-center">
                        <h1 class="text-4xl font-bold text-gray-800 mb-4 text-2xl dark:text-white">
                            "Encrypted Chat App"
                        </h1>

                    </div>
                </div>
            </section>


            // <!-- Footer -->
            <footer class="bg-white dark:bg-slate-800 py-6">
                <div class="container mx-auto px-6 text-center">
                    <p class="text-gray-600 dark:text-white">
                        "2024, Encrypted Chat App,  This work is licensed under a "
                        <a rel="license" href="https://creativecommons.org/licenses/by/4.0/">
                            "Creative Commons Attribution 4.0 License"
                        </a>
                    </p>
                </div>
            </footer>
        </>
    }
}

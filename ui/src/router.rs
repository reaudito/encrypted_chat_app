use crate::components::signing::add_account::AddAccount;
use crate::components::signing::create_account::CreateAccount;
use crate::components::signing::enter_pass_with_nav::EnterPassWithNav;

use crate::components::signing::delete_account::DeleteAccount;
use crate::components::signing::sign_out::SignOut;
use crate::pages::home::Home;
use leptos::prelude::*;
use leptos_router::components::*;
use leptos_router::path;
#[component]
pub fn RouterApp() -> impl IntoView {
    view! {
        <Router>
            <Routes fallback=|| "Not Found.">
                <Route path=path!("/") view=Home />
                // <Route path=path!("/sign-in") view=SignInForm />
                <Route path=path!("/create-account") view=CreateAccount />
                <Route path=path!("/sign-in") view=EnterPassWithNav />
                <Route path=path!("/add-account") view=AddAccount />

                <Route path=path!("/delete-account") view=DeleteAccount />
                <Route path=path!("/sign-out") view=SignOut />
            </Routes>
        </Router>
    }
}

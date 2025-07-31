use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Account {
    pub hash: String,
    pub account_address: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AccountStore {
    pub accounts: Vec<Account>,
}

impl Default for AccountStore {
    fn default() -> Self {
        Self {
            accounts: Vec::new(),
        }
    }
}

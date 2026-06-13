// THIS IS A PRE-RELEASE STILL. DO NOT USE THIS IN PRODUCTION! -w-

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: String,
}

impl Entry {
    pub fn empty() -> Self {
        Self {
            title: String::new(),
            username: String::new(),
            password: String::new(),
            notes: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Vault {
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    pub key_bundle_path: String,
    pub vault_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserIndex {
    pub users: Vec<UserRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    pub username: String,
    pub kem_private_seed_b64: String,
    pub kem_public_b64: String,
    pub dsa_private_seed_b64: String,
    pub dsa_public_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEnvelope {
    pub username: String,
    pub version: u32,
    pub kem_ciphertext_b64: String,
    pub wrapped_key_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub signature_b64: String,
}

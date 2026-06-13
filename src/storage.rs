// THIS IS A PRE-RELEASE STILL. DO NOT USE THIS IN PRODUCTION! -w-

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::fs;
use std::path::{Path, PathBuf};

use crate::models::{UserIndex, UserRecord, VaultEnvelope};
use crate::util::{ensure_dir_secure, write_private_file};

pub fn app_root() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pqvault")
}

pub fn index_path() -> PathBuf {
    app_root().join("users.json")
}

pub fn load_index() -> Result<UserIndex> {
    let path = index_path();
    if !path.exists() {
        return Ok(UserIndex::default());
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn save_index(index: &UserIndex) -> Result<()> {
    ensure_dir_secure(&app_root())?;
    let bytes = serde_json::to_vec_pretty(index)?;
    write_private_file(&index_path(), &bytes)
}

pub fn vault_path_for(username: &str) -> PathBuf {
    app_root().join("vaults").join(username).join("vault.pqv")
}

pub fn key_path_from_input(dir: &str, filename: &str) -> PathBuf {
    Path::new(dir).join(filename)
}

pub fn create_user_dirs(username: &str) -> Result<PathBuf> {
    let base = app_root().join("vaults").join(username);
    ensure_dir_secure(&base)?;
    Ok(base)
}

pub fn register_user(index: &mut UserIndex, username: &str, key_bundle_path: &Path) -> UserRecord {
    let record = UserRecord {
        username: username.to_string(),
        key_bundle_path: key_bundle_path.display().to_string(),
        vault_path: vault_path_for(username).display().to_string(),
    };
    index.users.retain(|u| u.username != username);
    index.users.push(record.clone());
    record
}

pub fn save_vault_envelope(path: &Path, env: &VaultEnvelope) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir_secure(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(env)?;
    write_private_file(path, &bytes)
}

pub fn load_vault_envelope(path: &Path) -> Result<VaultEnvelope> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EncKeyBundleFile {
    version: u32,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

pub fn save_key_bundle(path: &Path, salt: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<()> {
    let file = EncKeyBundleFile {
        version: 1,
        salt_b64: STANDARD.encode(salt),
        nonce_b64: STANDARD.encode(nonce),
        ciphertext_b64: STANDARD.encode(ciphertext),
    };
    let bytes = serde_json::to_vec_pretty(&file)?;
    write_private_file(path, &bytes)
}

pub fn load_key_bundle(path: &Path) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let file: EncKeyBundleFile = serde_json::from_slice(&bytes)?;
    Ok((
        STANDARD.decode(file.salt_b64)?,
        STANDARD.decode(file.nonce_b64)?,
        STANDARD.decode(file.ciphertext_b64)?,
    ))
}

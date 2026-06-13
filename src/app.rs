// IMPORTANT!!!

// This one is very scawwy. OwO'
//    Upon closer inspection I was able to find
//    an issue regarding how users authenticate
//    when deleting a user's vault.

// I was able to successfully exploit this issue
// and delete a user's vault named "ATTACK_TEST"
// completely bypassing authentication by replacing
// the key bundle that the "legitimate" user used
// with an attacker's own key, which allowed me to
// authenticate with a different password.

// FIX (TODO):
//    Implement an "authenticate_user" function
//    that is more ironclad and robust.
//    e.g., checking vault sig against signing keys
//    (after key bundle decryption)

// SIDENOTE (equally scawwy):
//    There is currently no check to see if
//    a user already exists, so if someone
//    makes a user with an identical name to
//    another, they can overwrite a vault
//    with minimal effort.

// THIS IS A PRE-RELEASE STILL. DO NOT USE THIS IN PRODUCTION! -w-

use anyhow::{anyhow, Context, Result};
use std::path::Path;

use crate::crypto::{decrypt_key_bundle, decrypt_vault, encrypt_key_bundle, encrypt_vault, UserKeys};
use crate::models::{UserIndex, UserRecord, Vault};
use crate::storage::{
    create_user_dirs, key_path_from_input, load_index, load_key_bundle,
    load_vault_envelope, register_user, save_index, save_key_bundle, save_vault_envelope,
};
use crate::tui::{tui_login_select, tui_run_vault, LoginSelection};

pub fn run_app() -> Result<()> {
    let mut index = load_index().unwrap_or_default();

    let choice = tui_login_select(&index)?;
    let record = match choice {
        LoginSelection::DeleteUser => {
            delete_user_flow(&mut index)?;
            save_index(&index)?;
            return Ok(());
        }

        LoginSelection::Existing(i) => index
            .users
            .get(i)
            .cloned()
            .ok_or_else(|| anyhow!("invalid user selection"))?,

        LoginSelection::CreateNew => create_new_user(&mut index)?,
    };

    save_index(&index)?;

    let passphrase = crate::tui::tui_password_modal("Unlock key bundle")?;

    let (salt, nonce, ciphertext) =
        load_key_bundle(Path::new(&record.key_bundle_path))?;

    let bundle = decrypt_key_bundle(&salt, &nonce, &ciphertext, &passphrase)
        .context("unlock private key bundle")?;

    let keys = UserKeys::from_bundle(&bundle)?;

    let mut vault = load_or_create_vault(&record, &keys)?;

    tui_run_vault(&record, &mut vault, &keys)?;

    let env = encrypt_vault(&vault, &keys, &record.username)?;
    save_vault_envelope(Path::new(&record.vault_path), &env)?;

    crate::tui::tui_message("Vault saved.")?;
    Ok(())
}

fn create_new_user(index: &mut UserIndex) -> Result<UserRecord> {
    // TODO: Very important, very simple.
    //       Add checks to make sure the
    //       user being created doesn't exist.

    let username = crate::tui::tui_text_modal("New username (41 chars max)")?;
    if username.trim().is_empty() {
        return Err(anyhow!("username cannot be empty"));
    }

    let dir = crate::tui::tui_text_modal("Key directory")?;
    let filename = crate::tui::tui_text_modal("Key filename")?;
    let key_bundle_path = key_path_from_input(&dir, &filename);

    let passphrase = crate::tui::tui_password_modal("Create passphrase (41 chars max)")?;

    let user_dir = create_user_dirs(&username)?;
    let keys = UserKeys::generate();

    let bundle = keys.to_bundle(&username);
    let (salt, nonce, ciphertext) = encrypt_key_bundle(&bundle, &passphrase)?;

    save_key_bundle(&key_bundle_path, &salt, &nonce, &ciphertext)?;

    let record = register_user(index, &username, &key_bundle_path);

    let vault = Vault::default();
    let env = encrypt_vault(&vault, &keys, &username)?;
    save_vault_envelope(Path::new(&record.vault_path), &env)?;

    let public_card = user_dir.join("public.json");
    std::fs::write(&public_card, serde_json::to_vec_pretty(&serde_json::json!({
        "username": username,
        "kem_public_b64": bundle.kem_public_b64,
        "dsa_public_b64": bundle.dsa_public_b64,
    }))?)?;

    crate::tui::tui_message("User created.")?;
    Ok(record)
}

fn delete_user_flow(index: &mut UserIndex) -> Result<()> {
    let selection = tui_login_select(index)?;

    let user = match selection {
        LoginSelection::Existing(i) => index
            .users
            .get(i)
            .cloned()
            .ok_or_else(|| anyhow!("invalid selection"))?,

        _ => return Err(anyhow!("must select existing user")),
    };

     // TODO: VERY IMPORTANT!!!!! OwO'
     //    The authentication currently revolves
     //    around being able to decrypt the key bundle,
     //    but this is unreliable and dangerous since
     //    key bundles can be replaced. Instead,

     //    I propose that the key bundle should be
     //    capable of decrypting the VAULT with the
     //    signature bytes being required to match
     //    in order to delete.

    let passphrase =
        crate::tui::tui_password_modal("Authenticate to delete account")?;

    let (salt, nonce, ciphertext) =
        load_key_bundle(Path::new(&user.key_bundle_path))?;

    decrypt_key_bundle(&salt, &nonce, &ciphertext, &passphrase)
        .context("authentication failed")?;

    let confirm =
        crate::tui::tui_text_modal("Type DELETE to permanently remove user")?;

    if confirm.trim() != "DELETE" {
        return Err(anyhow!("deletion cancelled"));
    }

    if Path::new(&user.vault_path).exists() {
        std::fs::remove_file(&user.vault_path)?;
    }

    if Path::new(&user.key_bundle_path).exists() {
        std::fs::remove_file(&user.key_bundle_path)?;
    }

    let user_dir = Path::new("users").join(&user.username);

    if user_dir.exists() {
        std::fs::remove_dir_all(&user_dir)?;
    }

    index.users.retain(|u| u.username != user.username);

    crate::tui::tui_message("User deleted.")?;

    Ok(())
}

fn load_or_create_vault(record: &UserRecord, keys: &UserKeys) -> Result<Vault> {
    let path = std::path::Path::new(&record.vault_path);

    if !path.exists() {
        return Ok(Vault::default());
    }

    let env = load_vault_envelope(path)?;
    if env.username != record.username {
        return Err(anyhow!("vault owner mismatch"));
    }

    decrypt_vault(&env, keys)
}
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use ml_dsa::{
    signature::{Signer, Verifier},
    Generate, KeyExport, KeyInit as DsaKeyInit, MlDsa65, SigningKey, VerifyingKey,
    Keypair, SignatureEncoding,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    ml_kem_768::{DecapsulationKey as KemDecapsulationKey, EncapsulationKey as KemEncapsulationKey},
    MlKem768,
    SharedKey,
    TryKeyInit,
};

use sha2::Sha256;
use zeroize::Zeroize;

use crate::models::{KeyBundle, Vault, VaultEnvelope};
use crate::util::{random_bytes};

const KDF_CONTEXT_KEY_BUNDLE: &[u8] = b"pqvault-keybundle-v1";
const KDF_CONTEXT_VAULT: &[u8] = b"pqvault-vault-v1";

pub struct UserKeys {
    pub kem_private: KemDecapsulationKey,
    pub kem_public: KemEncapsulationKey,
    pub dsa_signing: SigningKey<MlDsa65>,
    pub dsa_verifying: VerifyingKey<MlDsa65>,
}

impl UserKeys {
    pub fn generate() -> Self {
        let (kem_private, kem_public) = MlKem768::generate_keypair();
        let dsa_signing = SigningKey::<MlDsa65>::generate();
        let dsa_verifying = dsa_signing.verifying_key();

        Self {
            kem_private,
            kem_public,
            dsa_signing,
            dsa_verifying,
        }
    }

    pub fn to_bundle(&self, username: &str) -> KeyBundle {
        KeyBundle {
            username: username.to_string(),
            kem_private_seed_b64: STANDARD.encode(self.kem_private.to_bytes()),
            kem_public_b64: STANDARD.encode(self.kem_public.to_bytes()),
            dsa_private_seed_b64: STANDARD.encode(self.dsa_signing.to_bytes()),
            dsa_public_b64: STANDARD.encode(self.dsa_verifying.to_bytes()),
        }
    }

    pub fn from_bundle(bundle: &KeyBundle) -> Result<Self> {
        let kem_private_bytes = STANDARD.decode(&bundle.kem_private_seed_b64)?;
        let kem_public_bytes = STANDARD.decode(&bundle.kem_public_b64)?;
        let dsa_private_bytes = STANDARD.decode(&bundle.dsa_private_seed_b64)?;
        let dsa_public_bytes = STANDARD.decode(&bundle.dsa_public_b64)?;

        let kem_private = KemDecapsulationKey::new_from_slice(&kem_private_bytes)
            .map_err(|_| anyhow!("invalid ML-KEM private seed"))?;
        let kem_public = KemEncapsulationKey::new_from_slice(&kem_public_bytes)
            .map_err(|_| anyhow!("invalid ML-KEM public key"))?;
        let dsa_signing = SigningKey::<MlDsa65>::new_from_slice(&dsa_private_bytes)
            .map_err(|_| anyhow!("invalid ML-DSA private seed"))?;
        let dsa_verifying = VerifyingKey::<MlDsa65>::new_from_slice(&dsa_public_bytes)
            .map_err(|_| anyhow!("invalid ML-DSA public key"))?;

        Ok(Self {
            kem_private,
            kem_public,
            dsa_signing,
            dsa_verifying,
        })
    }
}

pub fn encrypt_key_bundle(
    bundle: &KeyBundle,
    passphrase: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let plaintext = serde_json::to_vec(bundle)?;
    let salt = random_bytes(16);

    let key = derive_passphrase_key(passphrase, &salt, KDF_CONTEXT_KEY_BUNDLE)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("bad key"))?;

    let nonce = random_bytes(24);
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())?;

    Ok((salt, nonce, ciphertext))
}

pub fn decrypt_key_bundle(
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    passphrase: &str,
) -> Result<KeyBundle> {
    let key = derive_passphrase_key(passphrase, salt, KDF_CONTEXT_KEY_BUNDLE)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("bad key"))?;

    let plaintext = cipher.decrypt(XNonce::from_slice(nonce), ciphertext.as_ref())?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8],
    context: &[u8],
) -> Result<[u8; 32]> {
    use argon2::Argon2;

    let mut input = Vec::with_capacity(passphrase.len() + context.len());
    input.extend_from_slice(passphrase.as_bytes());
    input.extend_from_slice(context);

    let mut out = [0u8; 32];

    Argon2::default()
        .hash_password_into(&input, salt, &mut out)
        .map_err(|_| anyhow!("argon2 derivation failed"))?;

    input.zeroize();
    Ok(out)
}

pub fn encrypt_vault(
    vault: &Vault,
    keys: &UserKeys,
    username: &str,
) -> Result<VaultEnvelope> {
    let vault_plain = serde_json::to_vec(vault)?;

    let mut data_key = random_bytes(32);
    let data_cipher = XChaCha20Poly1305::new_from_slice(&data_key)
        .map_err(|_| anyhow!("bad key"))?;

    let nonce = random_bytes(24);
    let ciphertext = data_cipher.encrypt(XNonce::from_slice(&nonce), vault_plain.as_ref())?;

    let (kem_ciphertext, shared) = keys.kem_public.encapsulate();

    let wrap_key = derive_shared_key(&shared, KDF_CONTEXT_VAULT)?;
    let wrap_cipher = XChaCha20Poly1305::new_from_slice(&wrap_key)
        .map_err(|_| anyhow!("bad key"))?;

    let wrap_nonce = random_bytes(24);
    let wrapped_key = wrap_cipher.encrypt(XNonce::from_slice(&wrap_nonce), data_key.as_ref())?;

    let mut signed = Vec::new();
    signed.extend_from_slice(username.as_bytes());
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&wrap_nonce);
    signed.extend_from_slice(kem_ciphertext.as_ref());
    signed.extend_from_slice(&wrapped_key);
    signed.extend_from_slice(&ciphertext);

    let signature = keys.dsa_signing.sign(&signed);
    data_key.zeroize();

    Ok(VaultEnvelope {
        username: username.to_string(),
        version: 1,
        kem_ciphertext_b64: STANDARD.encode(kem_ciphertext.as_ref() as &[u8]),
        wrapped_key_b64: STANDARD.encode([wrap_nonce, wrapped_key].concat()),
        nonce_b64: STANDARD.encode(nonce),
        ciphertext_b64: STANDARD.encode(ciphertext),
        signature_b64: STANDARD.encode(signature.to_bytes()),
    })
}

pub fn decrypt_vault(envelope: &VaultEnvelope, keys: &UserKeys) -> Result<Vault> {
    if envelope.version != 1 {
        return Err(anyhow!("unsupported vault version"));
    }

    let kem_ciphertext = STANDARD.decode(&envelope.kem_ciphertext_b64)?;
    let wrapped_blob = STANDARD.decode(&envelope.wrapped_key_b64)?;
    let nonce = STANDARD.decode(&envelope.nonce_b64)?;
    let ciphertext = STANDARD.decode(&envelope.ciphertext_b64)?;
    let signature_bytes = STANDARD.decode(&envelope.signature_b64)?;

    let signature = ml_dsa::Signature::<MlDsa65>::try_from(signature_bytes.as_slice())
        .map_err(|_| anyhow!("invalid signature bytes"))?;

    let wrap_nonce = wrapped_blob.get(..24)
        .ok_or_else(|| anyhow!("wrapped key missing nonce"))?;
    let wrapped_key = wrapped_blob.get(24..)
        .ok_or_else(|| anyhow!("wrapped key missing ciphertext"))?;

    let mut signed = Vec::new();
    signed.extend_from_slice(envelope.username.as_bytes());
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(wrap_nonce);
    signed.extend_from_slice(&kem_ciphertext);
    signed.extend_from_slice(wrapped_key);
    signed.extend_from_slice(&ciphertext);

    keys.dsa_verifying.verify(&signed, &signature)?;

    let ct = ml_kem::ml_kem_768::Ciphertext::try_from(kem_ciphertext.as_slice())
        .map_err(|_| anyhow!("invalid ML-KEM ciphertext"))?;

    let shared = keys.kem_private.decapsulate(&ct);
    let wrap_key = derive_shared_key(&shared, KDF_CONTEXT_VAULT)?;

    let wrap_cipher = XChaCha20Poly1305::new_from_slice(&wrap_key)
        .map_err(|_| anyhow!("bad key"))?;

    let data_key = wrap_cipher.decrypt(XNonce::from_slice(wrap_nonce), wrapped_key)?;
    let data_cipher = XChaCha20Poly1305::new_from_slice(&data_key)
        .map_err(|_| anyhow!("bad key"))?;

    let plain = data_cipher.decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())?;
    Ok(serde_json::from_slice(&plain)?)
}

fn derive_shared_key(shared: &SharedKey, context: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(context), shared.as_ref());
    let mut okm = [0u8; 32];

    hk.expand(b"vault-wrap-key", &mut okm)
        .map_err(|_| anyhow!("hkdf expand failed"))?;

    Ok(okm)
}

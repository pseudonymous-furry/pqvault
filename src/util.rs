// THIS IS A PRE-RELEASE STILL. DO NOT USE THIS IN PRODUCTION! -w-

use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn printable_password(len: usize) -> String {
    let len = len.max(16);
    let charset: Vec<u8> = (33u8..=126u8).collect();
    let mut out = Vec::with_capacity(len);
    let mut rng = OsRng;

    for _ in 0..len {
        let idx = (rng.next_u32() as usize) % charset.len();
        out.push(charset[idx]);
    }

    String::from_utf8(out).expect("ASCII only")
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn ensure_dir_secure(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", path.display()))?;
    }
    Ok(())
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir_secure(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", path.display()))?;
    }

    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all().ok();
    Ok(())
}

#[cfg(unix)]
pub fn disable_core_dumps() {
    use libc::{rlimit, setrlimit, RLIMIT_CORE};
    let lim = rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        let _ = setrlimit(RLIMIT_CORE, &lim);
    }
}

#[cfg(not(unix))]
pub fn disable_core_dumps() {}

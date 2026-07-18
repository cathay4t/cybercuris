// SPDX-License-Identifier: Apache-2.0
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};
use anyhow::Context as _;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;

type AesNonce = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;

use crate::memory_guard::MemoryGuard;

pub(crate) struct Keystore {
    data_dir: PathBuf,
}

impl Keystore {
    pub(crate) fn new() -> anyhow::Result<Self> {
        let data_dir = dirs::data_local_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot find XDG_DATA_HOME"))?
            .join("cybercuris");

        fs::create_dir_all(data_dir.join("passwords"))
            .context("creating password store directory")?;

        Ok(Keystore { data_dir })
    }

    pub(crate) fn main_key_path(&self) -> PathBuf {
        self.data_dir.join("main.key.encrypted")
    }

    pub(crate) fn is_initialized(&self) -> bool {
        self.main_key_path().exists()
    }

    pub(crate) fn init_main_key(&self, password: &str) -> anyhow::Result<()> {
        let mut main_key = vec![0u8; 4096];
        rand::rng().fill_bytes(&mut main_key);

        let aes_key = derive_key_from_password(password);
        let cipher = Aes256Gcm::new(&aes_key);
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce: AesNonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, main_key.as_slice())
            .context("encrypting main key")?;

        let path = self.main_key_path();
        write_with_nonce(&nonce, &ciphertext, &path)?;

        main_key.fill(0);

        Ok(())
    }

    pub(crate) fn load_main_key(
        &self,
        password: &str,
    ) -> anyhow::Result<MemoryGuard> {
        let data = fs::read(self.main_key_path())
            .context("reading encrypted main key")?;

        let aes_key = derive_key_from_password(password);
        let mut plain = decrypt_data(&aes_key, &data)
            .context("decrypting main key (wrong password?)")?;

        let mut guard = MemoryGuard::new(plain.len())
            .context("allocating MemoryGuard for main key")?;
        guard.as_mut_slice().copy_from_slice(&plain);
        // Use write_volatile to prevent compiler dead-store elimination.
        for i in 0..plain.len() {
            unsafe { std::ptr::write_volatile(plain.as_mut_ptr().add(i), 0) };
        }

        Ok(guard)
    }

    pub(crate) fn store_password(
        &self,
        name: &str,
        password: &[u8],
        main_key: &[u8],
    ) -> anyhow::Result<()> {
        let aes_key = derive_key_from_main_key(main_key);
        let cipher = Aes256Gcm::new(&aes_key);
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce: AesNonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, password)
            .context("encrypting password")?;

        let path = self.password_path(name);
        write_with_nonce(&nonce, &ciphertext, &path)
    }

    pub(crate) fn read_password_ciphertext(
        &self,
        name: &str,
    ) -> anyhow::Result<Vec<u8>> {
        fs::read(self.password_path(name)).context("reading encrypted password")
    }

    pub(crate) fn has_password(&self, name: &str) -> bool {
        self.password_path(name).exists()
    }

    pub(crate) fn remove_password(&self, name: &str) -> anyhow::Result<()> {
        fs::remove_file(self.password_path(name))
            .with_context(|| format!("removing password for {name}"))
    }

    pub(crate) fn rename_password(
        &self,
        old_name: &str,
        new_name: &str,
    ) -> anyhow::Result<()> {
        fs::rename(self.password_path(old_name), self.password_path(new_name))
            .with_context(|| {
                format!("renaming password {old_name} to {new_name}")
            })
    }

    pub(crate) fn list_passwords(&self) -> anyhow::Result<Vec<String>> {
        let dir = self.data_dir.join("passwords");
        let mut names = vec![];
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(names);
            }
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "key")
                && let Some(name) = path.file_stem().and_then(|s| s.to_str())
            {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    fn password_path(&self, name: &str) -> PathBuf {
        self.data_dir
            .join("passwords")
            .join(format!("{}.key", sanitize_filename(name)))
    }
}

pub(crate) fn decrypt_with_main_key(
    main_key: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<MemoryGuard> {
    let mut plain = decrypt_with_main_key_into_vec(main_key, ciphertext)?;
    let mut guard = MemoryGuard::new(plain.len())
        .context("allocating MemoryGuard for password")?;
    guard.as_mut_slice().copy_from_slice(&plain);
    plain.fill(0);
    Ok(guard)
}

pub(crate) fn password_aes_key_from_main_key(main_key: &[u8]) -> [u8; 32] {
    let key: Key<Aes256Gcm> = derive_key_from_main_key(main_key);
    key.into()
}

pub(crate) fn decrypt_with_aes_key_into_writer(
    raw_key: &[u8; 32],
    ciphertext: &[u8],
    writer: &mut (impl io::Write + ?Sized),
) -> anyhow::Result<()> {
    let aes_key: Key<Aes256Gcm> = (*raw_key).into();
    let mut plain = decrypt_data(&aes_key, ciphertext)?;
    writer.write_all(&plain)?;
    // Use write_volatile to prevent compiler dead-store elimination.
    for i in 0..plain.len() {
        unsafe { std::ptr::write_volatile(plain.as_mut_ptr().add(i), 0) };
    }
    Ok(())
}

fn decrypt_with_main_key_into_vec(
    main_key: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let aes_key = derive_key_from_main_key(main_key);
    decrypt_data(&aes_key, ciphertext)
}

fn decrypt_data(
    aes_key: &Key<Aes256Gcm>,
    data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if data.len() < 12 + 16 {
        anyhow::bail!("Ciphertext too short");
    }

    let cipher = Aes256Gcm::new(aes_key);
    let nonce = AesNonce::try_from(&data[..12])
        .map_err(|_| anyhow::anyhow!("Invalid nonce"))?;
    let plain = cipher
        .decrypt(&nonce, &data[12..])
        .context("decrypting data (wrong key or corrupted data)")?;

    Ok(plain)
}

fn write_with_nonce(
    nonce: &AesNonce,
    ciphertext: &[u8],
    path: &Path,
) -> anyhow::Result<()> {
    let mut data = Vec::with_capacity(12 + ciphertext.len());
    data.extend_from_slice(nonce.as_slice());
    data.extend_from_slice(ciphertext);
    fs::write(path, &data)?;
    Ok(())
}

fn derive_key_from_password(password: &str) -> Key<Aes256Gcm> {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        b"cybercuris-main-key-v1",
        100_000,
        &mut key,
    );
    key.into()
}

fn derive_key_from_main_key(main_key: &[u8]) -> Key<Aes256Gcm> {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(main_key, b"cybercuris-password-key-v1", 1, &mut key);
    key.into()
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// SPDX-License-Identifier: Apache-2.0
use std::{
    fs,
    io::{self, Read, Write},
};

use anyhow::Context as _;
use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    keystore::Keystore, memory_guard::clear_memory, settings::Settings,
};

#[derive(Serialize, Deserialize)]
struct BackupFile {
    version: u32,
    main_key_encrypted: String,
    passwords: Vec<PasswordEntry>,
    #[serde(default)]
    settings: SettingsData,
}

#[derive(Serialize, Deserialize)]
struct PasswordEntry {
    name: String,
    pass_encrypted: String,
}

#[derive(Serialize, Deserialize)]
struct SettingsData {
    unlock_timeout_secs: u64,
    quit_key: String,
    hide_key: String,
}

impl Default for SettingsData {
    fn default() -> Self {
        SettingsData {
            unlock_timeout_secs: 14400,
            quit_key: "x".to_string(),
            hide_key: "h".to_string(),
        }
    }
}

impl From<&Settings> for SettingsData {
    fn from(s: &Settings) -> Self {
        SettingsData {
            unlock_timeout_secs: s.unlock_timeout_secs,
            quit_key: s.quit_key.clone(),
            hide_key: s.hide_key.clone(),
        }
    }
}

pub(crate) fn backup(
    keystore: &Keystore,
    settings: &Settings,
) -> anyhow::Result<()> {
    let yaml = backup_to_string(keystore, settings)?;
    io::stdout()
        .write_all(yaml.as_bytes())
        .context("writing backup to stdout")?;
    Ok(())
}

pub(crate) fn backup_to_string(
    keystore: &Keystore,
    settings: &Settings,
) -> anyhow::Result<String> {
    let main_key_bytes = fs::read(keystore.main_key_path())
        .context("reading encrypted main key")?;
    let main_key_b64 = BASE64_STANDARD.encode(&main_key_bytes);

    let names = keystore.list_passwords()?;
    let mut passwords = Vec::with_capacity(names.len());
    for name in &names {
        let ciphertext = keystore
            .read_password_ciphertext(name)
            .with_context(|| format!("reading password {name}"))?;
        let pass_b64 = BASE64_STANDARD.encode(&ciphertext);
        passwords.push(PasswordEntry {
            name: name.clone(),
            pass_encrypted: pass_b64,
        });
    }

    let backup = BackupFile {
        version: 1,
        main_key_encrypted: main_key_b64,
        passwords,
        settings: SettingsData::from(settings),
    };

    serde_yaml::to_string(&backup).context("serializing backup YAML")
}

pub(crate) fn restore(keystore: &Keystore, force: bool) -> anyhow::Result<()> {
    let mut yaml_str = String::new();
    io::stdin()
        .read_to_string(&mut yaml_str)
        .context("reading backup YAML from stdin")?;
    restore_from_str(keystore, &yaml_str, force)
}

pub(crate) fn restore_from_str(
    keystore: &Keystore,
    yaml_str: &str,
    force: bool,
) -> anyhow::Result<()> {
    if !force {
        if keystore.is_initialized() {
            anyhow::bail!(
                "Password store already initialized. Use --force to overwrite \
                 existing data."
            );
        }
        let existing = keystore.list_passwords()?;
        if !existing.is_empty() {
            anyhow::bail!(
                "Password store contains {} existing password(s). Use --force \
                 to overwrite existing data.",
                existing.len()
            );
        }
    }

    let backup: BackupFile =
        serde_yaml::from_str(yaml_str).context("parsing backup YAML")?;

    if backup.version != 1 {
        anyhow::bail!(
            "Unsupported backup version: {}. This tool supports version 1.",
            backup.version
        );
    }

    // Decode and write the main key file.
    let mut main_key_bytes = BASE64_STANDARD
        .decode(&backup.main_key_encrypted)
        .context("decoding main_key_encrypted base64")?;

    let main_key_path = keystore.main_key_path();
    if let Some(parent) = main_key_path.parent() {
        fs::create_dir_all(parent).context("creating data directory")?;
    }
    fs::write(&main_key_path, &main_key_bytes)
        .context("writing encrypted main key")?;
    unsafe { clear_memory(&mut main_key_bytes) };

    // Write each password file.
    for entry in &backup.passwords {
        let mut ciphertext =
            BASE64_STANDARD.decode(&entry.pass_encrypted).with_context(
                || format!("decoding pass_encrypted for {}", entry.name),
            )?;

        let path = keystore.password_path(&entry.name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context("creating passwords directory")?;
        }
        fs::write(&path, &ciphertext)
            .with_context(|| format!("writing password {}", entry.name))?;
        unsafe { clear_memory(&mut ciphertext) };
    }

    // Save restored settings.
    let restored_settings = Settings {
        unlock_timeout_secs: backup.settings.unlock_timeout_secs,
        quit_key: backup.settings.quit_key,
        hide_key: backup.settings.hide_key,
    };
    restored_settings
        .save()
        .context("saving restored settings")?;

    eprintln!(
        "Restored main key, {} password(s), and settings.",
        backup.passwords.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::keystore::Keystore;

    #[test]
    fn test_backup_restore_roundtrip() {
        // Create a temp store, init, add passwords, back up.
        let src_dir = tempfile::TempDir::new().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", src_dir.path()) };
        let src_keystore = Keystore::new().unwrap();
        src_keystore.init_main_key("master-password").unwrap();

        // Load main key and store some passwords.
        let main_key = src_keystore.load_main_key("master-password").unwrap();
        src_keystore
            .store_password("example.com", b"secret123", main_key.as_slice())
            .unwrap();
        src_keystore
            .store_password("github", b"gh_p4ss!", main_key.as_slice())
            .unwrap();
        drop(main_key);

        let settings = Settings::default();
        // Backup.
        let yaml = backup_to_string(&src_keystore, &settings).unwrap();
        assert!(yaml.contains("version: 1"));
        assert!(yaml.contains("main_key_encrypted:"));
        assert!(yaml.contains("example.com"));
        assert!(yaml.contains("github"));
        assert!(yaml.contains("unlock_timeout_secs"));
        assert!(yaml.contains("quit_key"));
        assert!(yaml.contains("hide_key"));

        // Restore into a fresh store.
        let dst_dir = tempfile::TempDir::new().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", dst_dir.path()) };
        let dst_keystore = Keystore::new().unwrap();
        restore_from_str(&dst_keystore, &yaml, false).unwrap();

        // Verify we can decrypt passwords with the original master password.
        let main_key = dst_keystore.load_main_key("master-password").unwrap();
        let pw1_ct = dst_keystore
            .read_password_ciphertext("example.com")
            .unwrap();
        let pw1 = crate::keystore::decrypt_with_main_key(
            main_key.as_slice(),
            &pw1_ct,
        )
        .unwrap();
        assert_eq!(pw1.as_slice(), b"secret123");
        drop(pw1);

        let pw2_ct = dst_keystore.read_password_ciphertext("github").unwrap();
        let pw2 = crate::keystore::decrypt_with_main_key(
            main_key.as_slice(),
            &pw2_ct,
        )
        .unwrap();
        assert_eq!(pw2.as_slice(), b"gh_p4ss!");
        drop(pw2);
        drop(main_key);

        // Verify listing.
        let names = dst_keystore.list_passwords().unwrap();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"example.com".to_string()));
        assert!(names.contains(&"github".to_string()));

        // Verify settings were restored.
        let restored = Settings::load();
        assert_eq!(restored.unlock_timeout_secs, 14400);
        assert_eq!(restored.quit_key, "x");
        assert_eq!(restored.hide_key, "h");
    }

    #[test]
    fn test_restore_refuses_initialized_store() {
        let dir = tempfile::TempDir::new().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", dir.path()) };
        let keystore = Keystore::new().unwrap();
        keystore.init_main_key("some-password").unwrap();

        let yaml = "version: 1\nmain_key_encrypted: dGVzdA==\npasswords: []\n";
        let result = restore_from_str(&keystore, yaml, false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("already initialized"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_restore_force_overwrites() {
        // First, create a real backup.
        let src_dir = tempfile::TempDir::new().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", src_dir.path()) };
        let src_keystore = Keystore::new().unwrap();
        src_keystore.init_main_key("pw").unwrap();
        let mk = src_keystore.load_main_key("pw").unwrap();
        src_keystore
            .store_password("site1", b"pass1", mk.as_slice())
            .unwrap();
        drop(mk);
        let settings = Settings::default();
        let yaml = backup_to_string(&src_keystore, &settings).unwrap();

        // Now restore into a store that already has data (via force).
        let dst_dir = tempfile::TempDir::new().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", dst_dir.path()) };
        let dst_keystore = Keystore::new().unwrap();
        dst_keystore.init_main_key("old-pw").unwrap();
        let mk = dst_keystore.load_main_key("old-pw").unwrap();
        dst_keystore
            .store_password("old-entry", b"old", mk.as_slice())
            .unwrap();
        drop(mk);

        // Without force, should fail.
        assert!(restore_from_str(&dst_keystore, &yaml, false).is_err());

        // With force, should succeed.
        restore_from_str(&dst_keystore, &yaml, true).unwrap();

        // Now verify the restored data.
        let mk = dst_keystore.load_main_key("pw").unwrap();
        let ct = dst_keystore.read_password_ciphertext("site1").unwrap();
        let pw =
            crate::keystore::decrypt_with_main_key(mk.as_slice(), &ct).unwrap();
        assert_eq!(pw.as_slice(), b"pass1");
    }

    #[test]
    fn test_restore_rejects_wrong_version() {
        let dir = tempfile::TempDir::new().unwrap();
        unsafe { env::set_var("XDG_DATA_HOME", dir.path()) };
        let keystore = Keystore::new().unwrap();

        let yaml = "version: 99\nmain_key_encrypted: dGVzdA==\npasswords: []\n";
        let result = restore_from_str(&keystore, yaml, false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Unsupported backup version"),
            "unexpected error: {err}"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
use std::{fs, path::PathBuf, time::Duration};

use anyhow::Context as _;

pub(crate) struct Settings {
    pub(crate) unlock_timeout_secs: u64,
    pub(crate) quit_key: String,
    pub(crate) hide_key: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            unlock_timeout_secs: 14400,
            quit_key: "x".to_string(),
            hide_key: "h".to_string(),
        }
    }
}

impl Settings {
    fn path() -> Option<PathBuf> {
        dirs::data_local_dir()
            .map(|d| d.join("cybercuris").join("settings.conf"))
    }

    pub(crate) fn load() -> Self {
        let mut settings = Settings::default();
        let Some(path) = Self::path() else {
            return settings;
        };
        let Ok(content) = fs::read_to_string(path) else {
            return settings;
        };
        for line in content.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "unlock_timeout_secs" => {
                    if let Ok(n) = value.parse::<u64>()
                        && n > 0
                    {
                        settings.unlock_timeout_secs = n;
                    }
                }
                "quit_key" if value.chars().count() == 1 => {
                    settings.quit_key = value.to_string();
                }
                "hide_key" if value.chars().count() == 1 => {
                    settings.hide_key = value.to_string();
                }
                _ => {}
            }
        }
        settings
    }

    pub(crate) fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()
            .ok_or_else(|| anyhow::anyhow!("Cannot find XDG_DATA_HOME"))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context("creating settings directory")?;
        }
        fs::write(
            &path,
            format!(
                "unlock_timeout_secs={}\nquit_key={}\nhide_key={}\n",
                self.unlock_timeout_secs, self.quit_key, self.hide_key
            ),
        )
        .context("writing settings file")?;
        Ok(())
    }

    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_secs(self.unlock_timeout_secs)
    }
}

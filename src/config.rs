use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Gmail,
    Icloud,
}

impl Provider {
    pub fn default_host(self) -> &'static str {
        match self {
            Provider::Gmail => "imap.gmail.com",
            Provider::Icloud => "imap.mail.me.com",
        }
    }

    /// Fallback name for the drafts mailbox if the server doesn't advertise
    /// a `\Drafts` SPECIAL-USE attribute.
    pub fn fallback_drafts(self) -> &'static str {
        match self {
            Provider::Gmail => "[Gmail]/Drafts",
            Provider::Icloud => "Drafts",
        }
    }

    pub fn fallback_trash(self) -> &'static str {
        match self {
            Provider::Gmail => "[Gmail]/Trash",
            Provider::Icloud => "Deleted Messages",
        }
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Provider::Gmail => "gmail",
            Provider::Icloud => "icloud",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// LOGIN with an app password (Gmail app password / iCloud app-specific password).
    #[default]
    Password,
    /// SASL XOAUTH2 with an access token printed by `oauth_token_command` (Gmail only).
    Oauth2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub provider: Provider,
    pub email: String,
    /// Display name used in the From header of drafts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// IMAP login name. Defaults to `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub auth: AuthMethod,
    /// Shell command whose stdout is the password (e.g. `op read op://...`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_command: Option<String>,
    /// Shell command whose stdout is an OAuth2 access token (auth = "oauth2").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_token_command: Option<String>,
    /// Override the drafts mailbox instead of discovering it via SPECIAL-USE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drafts_mailbox: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trash_mailbox: Option<String>,
    /// Testing only: connect without TLS. Honored only for localhost.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub insecure_plaintext: bool,
}

impl Account {
    pub fn host(&self) -> &str {
        self.host.as_deref().unwrap_or(self.provider.default_host())
    }
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(993)
    }
    pub fn username(&self) -> &str {
        self.username.as_deref().unwrap_or(&self.email)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_account: Option<String>,
    #[serde(default)]
    pub accounts: BTreeMap<String, Account>,
}

pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("AGENT_MAIL_CONFIG") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("agent-mail").join("config.toml")
}

impl Config {
    pub fn load() -> Result<Config> {
        let path = config_path();
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, toml::to_string_pretty(self)?)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Resolve which account to use: explicit name, else default, else the only one.
    pub fn account(&self, name: Option<&str>) -> Result<(String, Account)> {
        let name = match name.or(self.default_account.as_deref()) {
            Some(n) => n.to_string(),
            None => match self.accounts.len() {
                0 => bail!("no accounts configured; run `agent-mail account add`"),
                1 => self.accounts.keys().next().unwrap().clone(),
                _ => bail!("multiple accounts configured; pass --account or set a default"),
            },
        };
        let acct = self
            .accounts
            .get(&name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown account `{name}`"))?;
        Ok((name, acct))
    }
}

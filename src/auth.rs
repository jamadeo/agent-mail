use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::Account;

const KEYRING_SERVICE: &str = "agent-mail";

fn env_var_name(account_name: &str) -> String {
    let slug: String = account_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("AGENT_MAIL_{slug}_PASSWORD")
}

fn run_secret_command(cmd: &str) -> Result<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .with_context(|| format!("running `{cmd}`"))?;
    if !out.status.success() {
        bail!(
            "`{cmd}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

/// App passwords are shown with spaces (Gmail) for readability; they are not part of it.
fn normalize(pw: String) -> String {
    pw.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Password lookup order: env var, `password_command`, OS keychain.
pub fn password(account_name: &str, account: &Account) -> Result<String> {
    if let Ok(pw) = std::env::var(env_var_name(account_name)) {
        return Ok(normalize(pw));
    }
    if let Some(cmd) = &account.password_command {
        return run_secret_command(cmd).map(normalize);
    }
    let entry = keyring::Entry::new(KEYRING_SERVICE, &account.email)?;
    match entry.get_password() {
        Ok(pw) => Ok(normalize(pw)),
        Err(keyring::Error::NoEntry) => bail!(
            "no password for `{}`; set {} , configure password_command, or run `agent-mail account add` again",
            account.email,
            env_var_name(account_name)
        ),
        Err(e) => Err(e.into()),
    }
}

pub fn oauth_token(account: &Account) -> Result<String> {
    match &account.oauth_token_command {
        Some(cmd) => run_secret_command(cmd),
        None => bail!("auth = \"oauth2\" requires oauth_token_command in the account config"),
    }
}

pub fn store_password(account: &Account, pw: &str) -> Result<()> {
    keyring::Entry::new(KEYRING_SERVICE, &account.email)?
        .set_password(&normalize(pw.to_string()))?;
    Ok(())
}

pub fn delete_password(account: &Account) -> Result<()> {
    match keyring::Entry::new(KEYRING_SERVICE, &account.email)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

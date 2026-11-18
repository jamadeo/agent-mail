//! `account` subcommands: interactive terminal setup, the local web form
//! (see `web.rs`), and the shared logic both use to validate, verify and
//! persist an account.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Result, anyhow, bail};
use clap::{Args, Subcommand, ValueEnum};

use crate::config::{Account, AuthMethod, Config, OAuthClient, Provider};
use crate::mail::{Client, Credential};
use crate::{auth, config, oauth, print_json, web};

pub const GMAIL_APP_PASSWORDS: &str = "https://myaccount.google.com/apppasswords";
pub const APPLE_APP_PASSWORDS: &str = "https://account.apple.com/account/manage/section/security";
pub const GOOGLE_CREDENTIALS: &str = "https://console.cloud.google.com/apis/credentials";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuthChoice {
    /// Sign in with Google in the browser (Gmail only).
    Oauth,
    /// App password (Gmail) / app-specific password (iCloud).
    Password,
}

#[derive(Args)]
pub struct LoginOpts {
    /// Don't launch a browser; just print the URL.
    #[arg(long)]
    no_browser: bool,
    /// Read the app password from stdin instead of prompting.
    #[arg(long)]
    password_stdin: bool,
    /// Google OAuth client ID (saved to the config for all Gmail accounts).
    #[arg(long, requires = "client_secret")]
    client_id: Option<String>,
    #[arg(long, requires = "client_id")]
    client_secret: Option<String>,
    /// Skip the test login.
    #[arg(long)]
    no_verify: bool,
}

#[derive(Subcommand)]
pub enum AccountCmd {
    /// Add an account. Prompts for anything not given on the command line.
    ///
    /// Gmail defaults to signing in with Google in your browser. iCloud only
    /// supports app-specific passwords, so the browser opens Apple's page for
    /// creating one and you paste it back here.
    Add {
        name: Option<String>,
        #[arg(long, value_enum)]
        provider: Option<Provider>,
        #[arg(long)]
        email: Option<String>,
        /// Display name for the From header.
        #[arg(long)]
        display_name: Option<String>,
        /// IMAP username if different from the email address.
        #[arg(long)]
        username: Option<String>,
        /// How to authenticate (default: oauth for Gmail, password for iCloud).
        #[arg(long, value_enum)]
        auth: Option<AuthChoice>,
        /// Don't store a password; get it from this shell command instead.
        #[arg(long, conflicts_with = "password_stdin")]
        password_command: Option<String>,
        /// Use XOAUTH2 with a token printed by this shell command (Gmail).
        #[arg(long, conflicts_with_all = ["password_stdin", "password_command"])]
        oauth_token_command: Option<String>,
        /// Make this the default account.
        #[arg(long)]
        default: bool,
        /// Fill in the account details in a form in your web browser instead of the terminal.
        /// Any other flags given are used to pre-fill the form.
        #[arg(long, conflicts_with_all = ["password_stdin", "no_verify"])]
        web: bool,
        #[command(flatten)]
        login: LoginOpts,
    },
    /// Re-authorize an existing account (browser sign-in or new app password).
    Login {
        /// Account name (defaults to the default account).
        name: Option<String>,
        #[command(flatten)]
        login: LoginOpts,
    },
    /// List configured accounts.
    List,
    /// Remove an account and its stored credentials.
    Remove { name: String },
    /// Set the default account.
    Default { name: String },
}

// ------------------------------------------------------------ shared core

/// Raw account inputs, as typed on the command line or submitted in the web form.
#[derive(Debug, Clone, Default)]
pub struct Fields {
    pub name: Option<String>,
    pub provider: Option<Provider>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub auth: Option<AuthChoice>,
    pub password_command: Option<String>,
    pub oauth_token_command: Option<String>,
    pub make_default: bool,
}

fn nonempty(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

pub fn guess_provider(email: &str) -> Option<Provider> {
    let domain = email.rsplit('@').next()?.to_ascii_lowercase();
    match domain.as_str() {
        "gmail.com" | "googlemail.com" => Some(Provider::Gmail),
        "icloud.com" | "me.com" | "mac.com" => Some(Provider::Icloud),
        _ => None,
    }
}

pub fn default_name(email: &str) -> String {
    email.split('@').next().unwrap_or("mail").to_string()
}

/// Validate inputs and turn them into a (name, Account). Nothing is stored.
pub fn build_account(cfg: &Config, f: &Fields) -> Result<(String, Account)> {
    let email = nonempty(&f.email).ok_or_else(|| anyhow!("email address is required"))?;
    if !email.contains('@') || email.contains(char::is_whitespace) {
        bail!("`{email}` doesn't look like an email address");
    }
    let provider = f
        .provider
        .or_else(|| guess_provider(&email))
        .ok_or_else(|| anyhow!("can't tell the provider from `{email}`; choose Gmail or iCloud"))?;
    let name = nonempty(&f.name).unwrap_or_else(|| default_name(&email));
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("account name `{name}` may only contain letters, digits, '-', '_' and '.'");
    }
    if cfg.accounts.contains_key(&name) {
        bail!("account `{name}` already exists (use `account login {name}` to re-authorize)");
    }
    let password_command = nonempty(&f.password_command);
    let oauth_token_command = nonempty(&f.oauth_token_command);
    let auth = if oauth_token_command.is_some() {
        AuthMethod::Oauth2
    } else if password_command.is_some() {
        AuthMethod::Password
    } else {
        match f.auth.unwrap_or(match provider {
            Provider::Gmail => AuthChoice::Oauth,
            Provider::Icloud => AuthChoice::Password,
        }) {
            AuthChoice::Oauth => AuthMethod::Oauth2,
            AuthChoice::Password => AuthMethod::Password,
        }
    };
    if provider == Provider::Icloud && auth == AuthMethod::Oauth2 {
        bail!("iCloud doesn't support OAuth for mail; it only accepts app-specific passwords");
    }
    Ok((
        name,
        Account {
            provider,
            email,
            name: nonempty(&f.display_name),
            username: nonempty(&f.username),
            host: None,
            port: None,
            auth,
            password_command,
            oauth_token_command,
            drafts_mailbox: None,
            trash_mailbox: None,
            insecure_plaintext: false,
        },
    ))
}

/// The credential obtained for an account, not yet stored.
pub enum Secret {
    Password(String),
    OAuth(oauth::Tokens),
    /// Comes from password_command / oauth_token_command at runtime.
    External,
}

/// Verify the credential by logging in, and only then store it and save the
/// account to the config. Returns the discovered drafts mailbox when verified.
pub fn commit(
    cfg: &mut Config,
    name: &str,
    acct: &Account,
    secret: Secret,
    verify: bool,
    make_default: bool,
) -> Result<Option<String>> {
    let drafts = if verify {
        let mut c = match &secret {
            Secret::Password(pw) => Client::connect_with(acct, Credential::Password(pw.clone()))?,
            Secret::OAuth(t) => {
                Client::connect_with(acct, Credential::AccessToken(t.access.clone()))?
            }
            Secret::External => Client::connect(name, acct, cfg.google_client().as_ref())?,
        };
        let d = c.drafts_mailbox()?;
        c.logout();
        Some(d)
    } else {
        None
    };
    match &secret {
        Secret::Password(pw) => auth::store_password(acct, pw)?,
        Secret::OAuth(t) => auth::store_refresh_token(acct, &t.refresh)?,
        Secret::External => {}
    }
    cfg.accounts.insert(name.to_string(), acct.clone());
    if make_default || cfg.default_account.is_none() {
        cfg.default_account = Some(name.to_string());
    }
    cfg.save()?;
    Ok(drafts)
}

// ------------------------------------------------------------ terminal flow

fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    if !interactive() {
        bail!("missing {label} (not running interactively; pass it as a flag)");
    }
    match default {
        Some(d) => eprint!("{label} [{d}]: "),
        None => eprint!("{label}: "),
    }
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    let s = s.trim();
    match (s.is_empty(), default) {
        (true, Some(d)) => Ok(d.to_string()),
        (true, None) => prompt(label, default),
        _ => Ok(s.to_string()),
    }
}

/// Make sure we have a Google OAuth client, from flags, env, config, or by asking.
fn google_client(cfg: &mut Config, opts: &LoginOpts) -> Result<OAuthClient> {
    if let (Some(id), Some(secret)) = (&opts.client_id, &opts.client_secret) {
        let c = OAuthClient {
            client_id: id.clone(),
            client_secret: secret.clone(),
        };
        cfg.google_oauth = Some(c.clone());
        return Ok(c);
    }
    if let Some(c) = cfg.google_client() {
        return Ok(c);
    }
    if !interactive() {
        bail!(
            "no Google OAuth client configured; pass --client-id/--client-secret or set \
             AGENT_MAIL_GOOGLE_CLIENT_ID/AGENT_MAIL_GOOGLE_CLIENT_SECRET (see README)"
        );
    }
    eprintln!(
        "\nSigning in with Google needs an OAuth client that you create once (free):\n\
         \x20 1. In Google Cloud Console, create a project and enable the Gmail API.\n\
         \x20 2. Configure the OAuth consent screen (External; add yourself as a test user).\n\
         \x20 3. Credentials → Create credentials → OAuth client ID → Application type \"Desktop app\".\n\
         \x20 4. Paste the client ID and secret below.\n\
         \x20 {GOOGLE_CREDENTIALS}\n"
    );
    let c = OAuthClient {
        client_id: prompt("Client ID", None)?,
        client_secret: prompt("Client secret", None)?,
    };
    cfg.google_oauth = Some(c.clone());
    Ok(c)
}

/// Obtain a credential in the terminal (prompts / browser), without storing it.
fn obtain_secret(cfg: &mut Config, acct: &Account, opts: &LoginOpts) -> Result<Secret> {
    Ok(match acct.auth {
        AuthMethod::Oauth2 if acct.oauth_token_command.is_some() => Secret::External,
        AuthMethod::Oauth2 => {
            let client = google_client(cfg, opts)?;
            let tokens = oauth::authorize(&client, &acct.email, !opts.no_browser)?;
            eprintln!("Authorized.");
            Secret::OAuth(tokens)
        }
        AuthMethod::Password if acct.password_command.is_some() => Secret::External,
        AuthMethod::Password => {
            let pw = if opts.password_stdin {
                let mut s = String::new();
                std::io::stdin().read_line(&mut s)?;
                s
            } else {
                if !interactive() {
                    bail!(
                        "no password: run interactively, or use --password-stdin / --password-command / --web"
                    );
                }
                let (what, page) = match acct.provider {
                    Provider::Gmail => ("Gmail app password", GMAIL_APP_PASSWORDS),
                    Provider::Icloud => ("iCloud app-specific password", APPLE_APP_PASSWORDS),
                };
                if opts.no_browser {
                    eprintln!("Create a {what} at {page}");
                } else {
                    eprintln!("Opening {page} so you can create a {what}…");
                    oauth::open_browser(page);
                }
                rpassword::prompt_password(format!("{what} for {}: ", acct.email))?
            };
            let pw = pw.trim().to_string();
            if pw.is_empty() {
                bail!("empty password");
            }
            Secret::Password(pw)
        }
    })
}

fn report_drafts(drafts: &Option<String>) {
    if let Some(d) = drafts {
        eprintln!("Logged in OK; drafts mailbox is `{d}`");
    }
}

pub fn run(cmd: &AccountCmd, cfg: &mut Config, json: bool) -> Result<()> {
    match cmd {
        AccountCmd::Add {
            name,
            provider,
            email,
            display_name,
            username,
            auth: auth_choice,
            password_command,
            oauth_token_command,
            default,
            web: use_web,
            login,
        } => {
            let mut f = Fields {
                name: name.clone(),
                provider: *provider,
                email: email.clone(),
                display_name: display_name.clone(),
                username: username.clone(),
                auth: *auth_choice,
                password_command: password_command.clone(),
                oauth_token_command: oauth_token_command.clone(),
                make_default: *default,
            };
            if *use_web {
                if let (Some(id), Some(secret)) = (&login.client_id, &login.client_secret) {
                    cfg.google_oauth = Some(OAuthClient {
                        client_id: id.clone(),
                        client_secret: secret.clone(),
                    });
                }
                let added = web::serve(cfg, f, !login.no_browser)?;
                if json {
                    print_json(&serde_json::json!({ "added": added }))?;
                } else if added.is_empty() {
                    println!("No accounts added.");
                }
                return Ok(());
            }

            // Terminal: prompt for whatever is missing.
            if nonempty(&f.email).is_none() {
                f.email = Some(prompt("Email address", None)?);
            }
            let email = f.email.clone().unwrap();
            if f.provider.is_none() && guess_provider(&email).is_none() {
                f.provider = Some(
                    match prompt("Provider (gmail/icloud)", None)?
                        .to_ascii_lowercase()
                        .as_str()
                    {
                        "gmail" | "g" => Provider::Gmail,
                        "icloud" | "i" => Provider::Icloud,
                        other => bail!("unknown provider `{other}`"),
                    },
                );
            }
            if f.name.is_none() && interactive() {
                f.name = Some(prompt("Account name", Some(&default_name(&email)))?);
            }
            if f.display_name.is_none() && interactive() {
                f.display_name = Some(prompt("Display name (blank for none)", Some(""))?);
            }

            let (name, acct) = build_account(cfg, &f)?;
            let secret = obtain_secret(cfg, &acct, login)?;
            let drafts = commit(cfg, &name, &acct, secret, !login.no_verify, f.make_default)?;
            report_drafts(&drafts);
            if json {
                print_json(&serde_json::json!({ "added": name, "email": acct.email }))?;
            } else {
                println!(
                    "Added account `{name}` ({})",
                    config::config_path().display()
                );
            }
        }
        AccountCmd::Login { name, login } => {
            let (name, acct) = cfg.account(name.as_deref())?;
            let secret = obtain_secret(cfg, &acct, login)?;
            let drafts = commit(cfg, &name, &acct, secret, !login.no_verify, false)?;
            report_drafts(&drafts);
            if json {
                print_json(&serde_json::json!({ "authorized": name }))?;
            } else {
                println!("Account `{name}` is authorized");
            }
        }
        AccountCmd::List => {
            if json {
                return print_json(&cfg.accounts);
            }
            if cfg.accounts.is_empty() {
                println!("(no accounts; run `agent-mail account add`)");
            }
            for (n, a) in &cfg.accounts {
                let star = if cfg.default_account.as_deref() == Some(n) {
                    "*"
                } else {
                    " "
                };
                let how = match a.auth {
                    AuthMethod::Oauth2 => "oauth",
                    AuthMethod::Password => "password",
                };
                println!(
                    "{star} {n:15} {:7} {:9} {}",
                    a.provider.to_string(),
                    how,
                    a.email
                );
            }
        }
        AccountCmd::Remove { name } => {
            let acct = cfg
                .accounts
                .remove(name)
                .ok_or_else(|| anyhow!("unknown account `{name}`"))?;
            auth::delete_password(&acct)?;
            if cfg.default_account.as_deref() == Some(name) {
                cfg.default_account = cfg.accounts.keys().next().cloned();
            }
            cfg.save()?;
            println!("Removed account `{name}`");
        }
        AccountCmd::Default { name } => {
            if !cfg.accounts.contains_key(name) {
                bail!("unknown account `{name}`");
            }
            cfg.default_account = Some(name.clone());
            cfg.save()?;
            println!("Default account is now `{name}`");
        }
    }
    Ok(())
}

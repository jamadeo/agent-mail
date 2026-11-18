//! Google OAuth 2.0 for installed apps: browser consent + loopback redirect + PKCE.
//! https://developers.google.com/identity/protocols/oauth2/native-app

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::{Account, OAuthClient};

/// Full IMAP access. This is the only scope Gmail accepts for XOAUTH2 over IMAP.
const SCOPE: &str = "https://mail.google.com/";

fn auth_url() -> String {
    std::env::var("AGENT_MAIL_GOOGLE_AUTH_URL")
        .unwrap_or_else(|_| "https://accounts.google.com/o/oauth2/v2/auth".into())
}
fn token_url() -> String {
    std::env::var("AGENT_MAIL_GOOGLE_TOKEN_URL")
        .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".into())
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn post_token(form: &[(&str, &str)]) -> Result<TokenResponse> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let mut resp = agent
        .post(token_url())
        .send_form(form.iter().copied())
        .context("contacting Google token endpoint")?;
    let tr: TokenResponse = resp
        .body_mut()
        .read_json()
        .context("reading token response")?;
    if let Some(e) = &tr.error {
        bail!(
            "Google returned `{e}`{}",
            tr.error_description
                .as_deref()
                .map(|d| format!(": {d}"))
                .unwrap_or_default()
        );
    }
    Ok(tr)
}

pub fn open_browser(url: &str) {
    let cmd = std::env::var("BROWSER").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "open".into()
        } else if cfg!(windows) {
            "explorer".into()
        } else {
            "xdg-open".into()
        }
    });
    let ok = std::process::Command::new(&cmd)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("(could not launch a browser with `{cmd}`; open the URL above manually)");
    }
}

fn random_token() -> String {
    // 2 × v4 UUIDs = 244 random bits; hex is valid for PKCE verifiers and state.
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// A started authorization: send the user to `url`, then call [`Pending::exchange`]
/// with the `code` delivered to `redirect` alongside a matching `state`.
pub struct Pending {
    pub url: String,
    pub state: String,
    redirect: String,
    verifier: String,
}

pub struct Tokens {
    pub refresh: String,
    pub access: String,
}

pub fn begin(client: &OAuthClient, email: &str, redirect: &str) -> Result<Pending> {
    let verifier = random_token();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_token();
    let url = url::Url::parse_with_params(
        &auth_url(),
        &[
            ("client_id", client.client_id.as_str()),
            ("redirect_uri", redirect),
            ("response_type", "code"),
            ("scope", SCOPE),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", state.as_str()),
            // offline + consent guarantees we get a refresh token back.
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("login_hint", email),
        ],
    )?;
    Ok(Pending {
        url: url.into(),
        state,
        redirect: redirect.to_string(),
        verifier,
    })
}

impl Pending {
    pub fn exchange(&self, client: &OAuthClient, code: &str) -> Result<Tokens> {
        let tr = post_token(&[
            ("code", code),
            ("client_id", client.client_id.as_str()),
            ("client_secret", client.client_secret.as_str()),
            ("redirect_uri", self.redirect.as_str()),
            ("grant_type", "authorization_code"),
            ("code_verifier", self.verifier.as_str()),
        ])?;
        Ok(Tokens {
            refresh: tr
                .refresh_token
                .ok_or_else(|| anyhow!("Google did not return a refresh token"))?,
            access: tr
                .access_token
                .ok_or_else(|| anyhow!("Google did not return an access token"))?,
        })
    }
}

/// Terminal flow: open the browser, wait on a one-shot loopback listener.
pub fn authorize(client: &OAuthClient, email: &str, launch_browser: bool) -> Result<Tokens> {
    let listener = TcpListener::bind("127.0.0.1:0").context("starting local callback server")?;
    let redirect = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let pending = begin(client, email, &redirect)?;
    let url = &pending.url;
    if launch_browser {
        eprintln!(
            "Opening your browser to authorize {email}. If it doesn't open, visit:\n\n  {url}\n"
        );
        open_browser(url);
    } else {
        eprintln!("Visit this URL in a browser on this machine to authorize {email}:\n\n  {url}\n");
    }
    eprintln!("Waiting for authorization (Ctrl-C to cancel)…");
    let code = wait_for_code(&listener, &pending.state)?;
    pending.exchange(client, &code)
}

/// Accept connections on the loopback listener until one carries our `state`.
fn wait_for_code(listener: &TcpListener, state: &str) -> Result<String> {
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line)?;
        // "GET /?state=..&code=.. HTTP/1.1"
        let path = line.split_whitespace().nth(1).unwrap_or("/");
        let parsed = url::Url::parse(&format!("http://localhost{path}"))?;
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();

        let (status, msg, result) = if q.get("state").map(String::as_str) != Some(state) {
            // Favicon requests, stray hits etc. Keep waiting.
            ("404 Not Found", "Not found.", None)
        } else if let Some(err) = q.get("error") {
            (
                "400 Bad Request",
                "Authorization was denied. You can close this tab.",
                Some(Err(anyhow!("authorization denied: {err}"))),
            )
        } else if let Some(code) = q.get("code") {
            (
                "200 OK",
                "agent-mail is authorized. You can close this tab and return to the terminal.",
                Some(Ok(code.clone())),
            )
        } else {
            ("400 Bad Request", "Missing code.", None)
        };
        let body = format!("<!doctype html><title>agent-mail</title><p>{msg}</p>");
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        if let Some(r) = result {
            return r;
        }
    }
    bail!("callback server closed unexpectedly")
}

/// Exchange the stored refresh token for a short-lived access token.
pub fn access_token(client: &OAuthClient, account_name: &str, account: &Account) -> Result<String> {
    let refresh = crate::auth::refresh_token(account)?.ok_or_else(|| {
        anyhow!("no stored Google authorization; run `agent-mail account login {account_name}`")
    })?;
    let tr = post_token(&[
        ("client_id", client.client_id.as_str()),
        ("client_secret", client.client_secret.as_str()),
        ("refresh_token", refresh.as_str()),
        ("grant_type", "refresh_token"),
    ])
    .map_err(|e| {
        anyhow!("{e:#}\nThe authorization may have been revoked or expired; run `agent-mail account login {account_name}`")
    })?;
    tr.access_token
        .ok_or_else(|| anyhow!("Google did not return an access token"))
}

//! `account add --web`: a tiny local web form for adding accounts.
//!
//! Listens on 127.0.0.1 at a random port. Every page lives under a random
//! per-run token path, the Host header must be our loopback address (blocks
//! DNS rebinding), and POSTs must not carry a foreign Origin (blocks other
//! sites submitting the form). Google's OAuth redirect comes back to `/` and
//! is matched by its unguessable `state` value instead.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::accounts::{self, AuthChoice, Fields, Secret};
use crate::config::{Account, AuthMethod, Config, OAuthClient, Provider};
use crate::oauth;

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &TcpStream) -> Result<Request> {
    let mut r = BufReader::new(stream);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if len > 1 << 20 {
        bail!("request body too large");
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body)?;
    let url = url::Url::parse(&format!("http://localhost{target}"))?;
    Ok(Request {
        method,
        path: url.path().to_string(),
        query: url.query_pairs().into_owned().collect(),
        headers,
        body,
    })
}

fn respond(mut stream: &TcpStream, status: &str, extra_headers: &str, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\n\
         Connection: close\r\n{extra_headers}\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Form values as strings, so a failed submit can be re-rendered as typed.
/// The password is deliberately never echoed back.
#[derive(Clone, Default)]
struct Form {
    email: String,
    provider: String, // auto | gmail | icloud
    name: String,
    display_name: String,
    username: String,
    auth: String, // password | oauth | password_command | oauth_token_command
    password: String,
    password_command: String,
    oauth_token_command: String,
    client_id: String,
    client_secret: String,
    make_default: bool,
}

impl Form {
    fn from_fields(f: &Fields) -> Form {
        let auth = if f.oauth_token_command.is_some() {
            "oauth_token_command"
        } else if f.password_command.is_some() {
            "password_command"
        } else {
            match f.auth {
                Some(AuthChoice::Oauth) => "oauth",
                Some(AuthChoice::Password) => "password",
                None => "",
            }
        };
        Form {
            email: f.email.clone().unwrap_or_default(),
            provider: match f.provider {
                Some(Provider::Gmail) => "gmail",
                Some(Provider::Icloud) => "icloud",
                None => "auto",
            }
            .into(),
            name: f.name.clone().unwrap_or_default(),
            display_name: f.display_name.clone().unwrap_or_default(),
            username: f.username.clone().unwrap_or_default(),
            auth: auth.into(),
            password_command: f.password_command.clone().unwrap_or_default(),
            oauth_token_command: f.oauth_token_command.clone().unwrap_or_default(),
            make_default: f.make_default,
            ..Default::default()
        }
    }

    fn parse(body: &[u8]) -> Form {
        let m: HashMap<String, String> = url::form_urlencoded::parse(body).into_owned().collect();
        let g = |k: &str| m.get(k).cloned().unwrap_or_default();
        Form {
            email: g("email"),
            provider: g("provider"),
            name: g("name"),
            display_name: g("display_name"),
            username: g("username"),
            auth: g("auth"),
            password: g("password"),
            password_command: g("password_command"),
            oauth_token_command: g("oauth_token_command"),
            client_id: g("client_id"),
            client_secret: g("client_secret"),
            make_default: m.contains_key("make_default"),
        }
    }

    fn to_fields(&self) -> Fields {
        let opt = |s: &str| Some(s.to_string()).filter(|s| !s.trim().is_empty());
        Fields {
            name: opt(&self.name),
            provider: match self.provider.as_str() {
                "gmail" => Some(Provider::Gmail),
                "icloud" => Some(Provider::Icloud),
                _ => None,
            },
            email: opt(&self.email),
            display_name: opt(&self.display_name),
            username: opt(&self.username),
            auth: match self.auth.as_str() {
                "oauth" => Some(AuthChoice::Oauth),
                "password" => Some(AuthChoice::Password),
                _ => None,
            },
            // Only honor the command field that matches the chosen method.
            password_command: opt(&self.password_command)
                .filter(|_| self.auth == "password_command"),
            oauth_token_command: opt(&self.oauth_token_command)
                .filter(|_| self.auth == "oauth_token_command"),
            make_default: self.make_default,
        }
    }
}

const STYLE: &str = "body{font:15px/1.45 system-ui,sans-serif;max-width:640px;margin:24px auto;padding:0 16px;\
color:#1a1a1a;background:#fff}label{display:block;margin:10px 0 2px;font-weight:600}\
input[type=text],input[type=email],input[type=password],select{width:100%;padding:6px;box-sizing:border-box}\
fieldset{border:1px solid #ccc;margin:14px 0;padding:8px 12px}.hint{color:#555;font-size:13px;font-weight:400}\
.err{background:#fde8e8;border:1px solid #e0a0a0;padding:8px 12px}.ok{background:#e6f6e6;border:1px solid #9c9;padding:8px 12px}\
button{padding:8px 16px;margin-top:14px}code{background:#f2f2f2;padding:1px 4px}\
@media (prefers-color-scheme:dark){body{background:#161616;color:#e8e8e8}.hint{color:#aaa}\
.err{background:#4a1f1f;border-color:#844}.ok{background:#1f3a1f;border-color:#484}code{background:#2a2a2a}}";

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'>\
         <title>{}</title><style>{STYLE}</style></head><body><h1>{}</h1>{body}</body></html>",
        esc(title),
        esc(title)
    )
}

fn render_form(base: &str, f: &Form, error: Option<&str>, google_configured: bool) -> String {
    let sel = |v: &str, cur: &str| if v == cur { " selected" } else { "" };
    let chk = |v: &str| if f.auth == v { " checked" } else { "" };
    let auth_default = if f.auth.is_empty() {
        "data-default=1"
    } else {
        ""
    };
    let err = error
        .map(|e| format!("<p class=err>{}</p>", esc(e).replace('\n', "<br>")))
        .unwrap_or_default();
    let google_note = if google_configured {
        "A Google OAuth client is already configured. Leave these blank to use it."
    } else {
        "Required once for Google sign-in. Create a <b>Desktop app</b> OAuth client \
         (see the README for the steps). It's saved to the config and shared by all Gmail accounts."
    };
    format!(
        r#"{err}
<form method=post action="{base}add" autocomplete=off>
<label>Email address<input type=email name=email required value="{email}"></label>

<label>Provider
<select name=provider id=provider>
<option value=auto{p_auto}>Detect from address</option>
<option value=gmail{p_gmail}>Gmail</option>
<option value=icloud{p_icloud}>iCloud</option>
</select></label>

<label>Account name <span class=hint>(used with <code>--account</code>; defaults to the part before @)</span>
<input type=text name=name value="{name}"></label>

<label>Display name <span class=hint>(shown in From on your drafts)</span>
<input type=text name=display_name value="{display_name}"></label>

<fieldset><legend>Sign-in method</legend>
<label><input type=radio name=auth value=password{a_pw} {auth_default}> App password</label>
<label><input type=radio name=auth value=oauth{a_oauth}> Sign in with Google (OAuth) <span class=hint>Gmail only</span></label>
<label><input type=radio name=auth value=password_command{a_pwc}> Password from a shell command</label>
<label><input type=radio name=auth value=oauth_token_command{a_otc}> OAuth token from a shell command <span class=hint>Gmail only</span></label>
</fieldset>

<div data-auth=password>
<label>App password
<input type=password name=password autocomplete=new-password></label>
<p class=hint>Gmail: create one at <a href="{gmail_pw}" target=_blank rel=noreferrer>myaccount.google.com/apppasswords</a> (needs 2-Step Verification and IMAP enabled).<br>
iCloud: create an app-specific password at <a href="{apple_pw}" target=_blank rel=noreferrer>account.apple.com</a> → Sign-In and Security.<br>
It is checked against the server before being saved to the macOS Keychain.</p>
</div>

<div data-auth=oauth>
<p class=hint>{google_note}</p>
<label>Google client ID<input type=text name=client_id value="{client_id}"></label>
<label>Google client secret<input type=password name=client_secret autocomplete=off></label>
<p class=hint>After you submit, you'll be sent to Google to approve access, then back here.</p>
</div>

<div data-auth=password_command>
<label>Password command <span class=hint>e.g. <code>op read op://Private/gmail/app-pw</code></span>
<input type=text name=password_command value="{password_command}"></label>
</div>

<div data-auth=oauth_token_command>
<label>OAuth token command <span class=hint>prints an access token</span>
<input type=text name=oauth_token_command value="{oauth_token_command}"></label>
</div>

<details{adv_open}><summary>Advanced</summary>
<label>IMAP username <span class=hint>(only if different from the email address)</span>
<input type=text name=username value="{username}"></label>
</details>

<label><input type=checkbox name=make_default{default_chk}> Make this the default account</label>

<button type=submit>Add account</button>
</form>
<form method=post action="{base}done"><button type=submit>Done, close this server</button></form>
<script>
(function(){{
  var prov=document.getElementById('provider'), email=document.querySelector('[name=email]');
  function provider(){{
    if(prov.value!=='auto')return prov.value;
    var d=(email.value.split('@')[1]||'').toLowerCase();
    if(d==='gmail.com'||d==='googlemail.com')return 'gmail';
    if(d==='icloud.com'||d==='me.com'||d==='mac.com')return 'icloud';
    return '';
  }}
  function update(){{
    var p=provider(), radios=document.querySelectorAll('[name=auth]'), cur=null;
    radios.forEach(function(r){{
      var gmailOnly=r.value==='oauth'||r.value==='oauth_token_command';
      r.disabled=(p==='icloud'&&gmailOnly);
      if(r.disabled&&r.checked)r.checked=false;
      if(r.checked)cur=r.value;
    }});
    if(!cur){{cur=(p==='gmail')?'oauth':'password';document.querySelector('[name=auth][value='+cur+']').checked=true;}}
    document.querySelectorAll('[data-auth]').forEach(function(d){{d.style.display=d.dataset.auth===cur?'':'none';}});
  }}
  prov.addEventListener('change',update); email.addEventListener('input',update);
  document.querySelectorAll('[name=auth]').forEach(function(r){{r.addEventListener('change',update);}});
  update();
}})();
</script>"#,
        email = esc(&f.email),
        p_auto = sel("auto", &f.provider),
        p_gmail = sel("gmail", &f.provider),
        p_icloud = sel("icloud", &f.provider),
        name = esc(&f.name),
        display_name = esc(&f.display_name),
        a_pw = chk("password"),
        a_oauth = chk("oauth"),
        a_pwc = chk("password_command"),
        a_otc = chk("oauth_token_command"),
        gmail_pw = accounts::GMAIL_APP_PASSWORDS,
        apple_pw = accounts::APPLE_APP_PASSWORDS,
        client_id = esc(&f.client_id),
        password_command = esc(&f.password_command),
        oauth_token_command = esc(&f.oauth_token_command),
        username = esc(&f.username),
        adv_open = if f.username.is_empty() { "" } else { " open" },
        default_chk = if f.make_default { " checked" } else { "" },
    )
}

fn success_page(base: &str, name: &str, acct: &Account, drafts: Option<&str>) -> String {
    let drafts = drafts
        .map(|d| format!(" Drafts will be saved to <code>{}</code>.", esc(d)))
        .unwrap_or_default();
    page(
        "Account added",
        &format!(
            "<p class=ok>Added <b>{}</b> ({}, {}). Logged in successfully.{drafts}</p>\
             <p><a href=\"{base}\">Add another account</a></p>\
             <form method=post action=\"{base}done\"><button type=submit>Done, close this server</button></form>",
            esc(name),
            esc(&acct.email),
            acct.provider
        ),
    )
}

/// An OAuth sign-in waiting for Google to redirect back.
struct PendingOAuth {
    flow: oauth::Pending,
    client: OAuthClient,
    name: String,
    acct: Account,
    form: Form,
}

enum Outcome {
    Html(String),
    Redirect(String),
}

struct Server<'a> {
    cfg: &'a mut Config,
    base: String,
    origin: String,
    pending: Option<PendingOAuth>,
    added: Vec<String>,
}

impl Server<'_> {
    fn form_page(&self, f: &Form, error: Option<&str>) -> String {
        page(
            "Add a mail account",
            &render_form(&self.base, f, error, self.cfg.google_client().is_some()),
        )
    }

    fn add(&mut self, form: Form) -> Outcome {
        match self.try_add(&form) {
            Ok(o) => o,
            Err(e) => Outcome::Html(self.form_page(&form, Some(&format!("{e:#}")))),
        }
    }

    fn try_add(&mut self, form: &Form) -> Result<Outcome> {
        let fields = form.to_fields();
        let (name, acct) = accounts::build_account(self.cfg, &fields)?;
        let acct = test_override(acct);
        let secret = match acct.auth {
            AuthMethod::Password if acct.password_command.is_some() => Secret::External,
            AuthMethod::Oauth2 if acct.oauth_token_command.is_some() => Secret::External,
            AuthMethod::Password => {
                let pw = form.password.trim();
                if pw.is_empty() {
                    bail!("enter the app password");
                }
                Secret::Password(pw.to_string())
            }
            AuthMethod::Oauth2 => {
                let client = match (form.client_id.trim(), form.client_secret.trim()) {
                    ("", "") => self.cfg.google_client().ok_or_else(|| {
                        anyhow!("enter a Google OAuth client ID and secret (see the README for how to create one)")
                    })?,
                    (id, secret) if !id.is_empty() && !secret.is_empty() => OAuthClient {
                        client_id: id.to_string(),
                        client_secret: secret.to_string(),
                    },
                    _ => bail!("enter both the Google client ID and the client secret"),
                };
                let redirect = self.origin.clone();
                let flow = oauth::begin(&client, &acct.email, &redirect)?;
                let url = flow.url.clone();
                eprintln!("Sending browser to Google to authorize {}…", acct.email);
                self.pending = Some(PendingOAuth {
                    flow,
                    client,
                    name,
                    acct,
                    form: Form {
                        password: String::new(),
                        client_secret: String::new(),
                        ..form.clone()
                    },
                });
                return Ok(Outcome::Redirect(url));
            }
        };
        let drafts = accounts::commit(self.cfg, &name, &acct, secret, true, fields.make_default)?;
        Ok(self.added_ok(name, acct, drafts))
    }

    fn added_ok(&mut self, name: String, acct: Account, drafts: Option<String>) -> Outcome {
        eprintln!("Added account `{name}` ({})", acct.email);
        let html = success_page(&self.base, &name, &acct, drafts.as_deref());
        self.added.push(name);
        Outcome::Html(html)
    }

    fn oauth_callback(&mut self, q: &HashMap<String, String>) -> Outcome {
        let matches = self
            .pending
            .as_ref()
            .is_some_and(|p| q.get("state") == Some(&p.flow.state));
        if !matches {
            return Outcome::Html(page(
                "Sign-in expired",
                &format!(
                    "<p class=err>This sign-in link doesn't match a pending request. <a href=\"{}\">Start over</a>.</p>",
                    self.base
                ),
            ));
        }
        let p = self.pending.take().unwrap();
        if let Some(err) = q.get("error") {
            return Outcome::Html(self.form_page(
                &p.form,
                Some(&format!("Google sign-in did not complete: {err}")),
            ));
        }
        let result = (|| -> Result<Option<String>> {
            let code = q
                .get("code")
                .ok_or_else(|| anyhow!("Google returned no code"))?;
            let tokens = p.flow.exchange(&p.client, code)?;
            self.cfg.google_oauth = Some(p.client.clone());
            accounts::commit(
                self.cfg,
                &p.name,
                &p.acct,
                Secret::OAuth(tokens),
                true,
                p.form.make_default,
            )
        })();
        match result {
            Ok(drafts) => self.added_ok(p.name, p.acct, drafts),
            Err(e) => Outcome::Html(self.form_page(&p.form, Some(&format!("{e:#}")))),
        }
    }
}

/// Testing hook: point new accounts at a local fake IMAP server.
fn test_override(mut acct: Account) -> Account {
    if let Ok(addr) = std::env::var("AGENT_MAIL_TEST_IMAP_ADDR")
        && let Some((h, p)) = addr.rsplit_once(':')
    {
        acct.host = Some(h.to_string());
        acct.port = p.parse().ok();
        acct.insecure_plaintext = true;
    }
    acct
}

/// Serve the form until the user clicks Done. Returns the names of added accounts.
pub fn serve(cfg: &mut Config, prefill: Fields, launch_browser: bool) -> Result<Vec<String>> {
    let listener = TcpListener::bind("127.0.0.1:0").context("starting local web server")?;
    let port = listener.local_addr()?.port();
    let origin = format!("http://127.0.0.1:{port}");
    let token = format!("{}", uuid::Uuid::new_v4().simple());
    let base = format!("/{token}/");
    let url = format!("{origin}{base}");
    let host = format!("127.0.0.1:{port}");

    if launch_browser {
        eprintln!(
            "Opening the account form in your browser. If it doesn't open, visit:\n\n  {url}\n"
        );
        oauth::open_browser(&url);
    } else {
        eprintln!("Open this URL in a browser on this machine:\n\n  {url}\n");
    }
    eprintln!("Waiting for the form (Ctrl-C to stop)…");

    let mut s = Server {
        cfg,
        base: base.clone(),
        origin: origin.clone(),
        pending: None,
        added: vec![],
    };
    let first_form = Form::from_fields(&prefill);

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let Ok(req) = read_request(&stream) else {
            continue;
        };
        if req.headers.get("host") != Some(&host) {
            respond(&stream, "400 Bad Request", "", "bad host");
            continue;
        }
        if req.method == "POST"
            && let Some(o) = req.headers.get("origin")
            && o != &origin
        {
            respond(&stream, "403 Forbidden", "", "cross-origin request refused");
            continue;
        }
        let outcome = match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") if req.query.contains_key("state") => s.oauth_callback(&req.query),
            ("GET", p) if p == base => Outcome::Html(if s.added.is_empty() {
                s.form_page(&first_form, None)
            } else {
                s.form_page(&Form::default(), None)
            }),
            ("POST", p) if p == format!("{base}add") => s.add(Form::parse(&req.body)),
            ("POST", p) if p == format!("{base}done") => {
                let list = if s.added.is_empty() {
                    "No accounts were added.".to_string()
                } else {
                    format!("Added: {}.", esc(&s.added.join(", ")))
                };
                respond(
                    &stream,
                    "200 OK",
                    "",
                    &page(
                        "All set",
                        &format!("<p>{list}</p><p>You can close this tab.</p>"),
                    ),
                );
                break;
            }
            _ => {
                respond(&stream, "404 Not Found", "", "not found");
                continue;
            }
        };
        match outcome {
            Outcome::Html(h) => respond(&stream, "200 OK", "", &h),
            Outcome::Redirect(to) => {
                respond(&stream, "303 See Other", &format!("Location: {to}\r\n"), "")
            }
        }
    }
    Ok(s.added)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(
            esc(r#"<a href="x">'&'"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;"
        );
    }

    #[test]
    fn form_roundtrip_only_honors_matching_command() {
        let f = Form::parse(
            b"email=a%40gmail.com&provider=auto&auth=password&password=x&password_command=evil&make_default=on",
        );
        let fields = f.to_fields();
        assert_eq!(fields.email.as_deref(), Some("a@gmail.com"));
        assert!(fields.password_command.is_none());
        assert!(fields.make_default);
        assert_eq!(fields.auth, Some(AuthChoice::Password));
    }
}

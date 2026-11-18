//! Thin IMAP layer over the `imap` crate with the provider quirks we care about.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, FixedOffset};
use imap::types::Flag;
use imap_proto::{NameAttribute, UidSetMember};
use serde::Serialize;

use crate::auth;
use crate::config::{Account, AuthMethod, OAuthClient, Provider};

pub type Session = imap::Session<imap::Connection>;

pub struct Client {
    pub account: Account,
    pub session: Session,
    mailboxes: Option<Vec<MailboxInfo>>,
    selected: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MailboxInfo {
    pub name: String,
    /// RFC 6154 special-use role, if any (drafts, sent, trash, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip)]
    pub selectable: bool,
}

/// A message summary built from the header block plus IMAP metadata.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub uid: u32,
    pub date: Option<String>,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Stable draft id (X-Universally-Unique-Identifier), when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<String>,
}

struct XOAuth2 {
    user: String,
    token: String,
}

impl imap::Authenticator for XOAuth2 {
    type Response = String;
    fn process(&self, _challenge: &[u8]) -> Self::Response {
        format!("user={}\x01auth=Bearer {}\x01\x01", self.user, self.token)
    }
}

/// Quote a string for use as an IMAP `astring`/search key.
pub fn imap_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn flag_name(f: &Flag<'_>) -> String {
    match f {
        Flag::Seen => "seen".into(),
        Flag::Answered => "answered".into(),
        Flag::Flagged => "flagged".into(),
        Flag::Deleted => "deleted".into(),
        Flag::Draft => "draft".into(),
        Flag::Recent => "recent".into(),
        Flag::MayCreate => "maycreate".into(),
        Flag::Custom(c) => c.to_string(),
        other => format!("{other:?}").to_lowercase(),
    }
}

/// Per-message data merged across possibly-split FETCH responses (iCloud
/// sometimes returns UID/FLAGS and the body section in separate untagged
/// FETCH lines for the same message).
#[derive(Default)]
struct Merged {
    uid: Option<u32>,
    flags: Vec<String>,
    header: Option<Vec<u8>>,
    body: Option<Vec<u8>>,
    internal_date: Option<DateTime<FixedOffset>>,
}

fn merge_fetches(fetches: &imap::types::Fetches) -> BTreeMap<u32, Merged> {
    let mut out: BTreeMap<u32, Merged> = BTreeMap::new();
    for f in fetches.iter() {
        let m = out.entry(f.message).or_default();
        if f.uid.is_some() {
            m.uid = f.uid;
        }
        if !f.flags().is_empty() {
            m.flags = f.flags().iter().map(flag_name).collect();
        }
        if let Some(h) = f.header() {
            m.header = Some(h.to_vec());
        }
        if let Some(b) = f.body() {
            m.body = Some(b.to_vec());
        }
        if let Some(d) = f.internal_date() {
            m.internal_date = Some(d);
        }
    }
    out
}

fn summarize(uid: u32, m: &Merged) -> Summary {
    let parsed = m
        .header
        .as_deref()
        .or(m.body.as_deref())
        .and_then(|h| mail_parser::MessageParser::default().parse_headers(h));
    let draft_id = parsed
        .as_ref()
        .and_then(|p| p.header_raw(crate::draft::UUID_HEADER))
        .map(|s| s.trim().to_string());
    let (from, to, subject, date, message_id) = match &parsed {
        Some(p) => (
            crate::draft::addrs_to_string(p.from()),
            crate::draft::addrs_to_string(p.to()),
            p.subject().unwrap_or("").to_string(),
            p.date().map(|d| d.to_rfc3339()),
            p.message_id().map(|s| s.to_string()),
        ),
        None => Default::default(),
    };
    Summary {
        uid,
        date: date.or_else(|| m.internal_date.map(|d| d.to_rfc3339())),
        from,
        to,
        subject,
        flags: m.flags.clone(),
        message_id,
        draft_id,
    }
}

/// A resolved secret to log in with.
pub enum Credential {
    Password(String),
    AccessToken(String),
}

impl Client {
    /// Connect using the account's stored credentials (env, command, keychain, OAuth refresh).
    pub fn connect(
        account_name: &str,
        account: &Account,
        google: Option<&OAuthClient>,
    ) -> Result<Client> {
        let cred = match account.auth {
            AuthMethod::Password => Credential::Password(auth::password(account_name, account)?),
            AuthMethod::Oauth2 => {
                Credential::AccessToken(auth::oauth_token(account_name, account, google)?)
            }
        };
        Self::connect_with(account, cred).map_err(|e| match account.auth {
            AuthMethod::Oauth2 => {
                anyhow!("{e:#}\nRun `agent-mail account login {account_name}` to re-authorize.")
            }
            AuthMethod::Password => e,
        })
    }

    /// Connect with an explicit credential (used to verify before storing anything).
    pub fn connect_with(account: &Account, cred: Credential) -> Result<Client> {
        let mut builder = imap::ClientBuilder::new(account.host(), account.port());
        if account.insecure_plaintext {
            if !matches!(account.host(), "localhost" | "127.0.0.1" | "::1") {
                bail!("insecure_plaintext is only allowed for localhost");
            }
            builder = builder.mode(imap::ConnectionMode::Plaintext);
        }
        let client = builder
            .connect()
            .with_context(|| format!("connecting to {}:{}", account.host(), account.port()))?;
        let session = match cred {
            Credential::Password(pw) => {
                client.login(account.username(), pw).map_err(|(e, _)| {
                    anyhow!(
                        "login failed for {}: {e}\n{}",
                        account.username(),
                        login_hint(account.provider)
                    )
                })?
            }
            Credential::AccessToken(token) => {
                let a = XOAuth2 {
                    user: account.username().to_string(),
                    token,
                };
                client.authenticate("XOAUTH2", &a).map_err(|(e, _)| {
                    anyhow!(
                        "XOAUTH2 authentication failed for {}: {e}",
                        account.username()
                    )
                })?
            }
        };
        Ok(Client {
            account: account.clone(),
            session,
            mailboxes: None,
            selected: None,
        })
    }

    pub fn logout(mut self) {
        let _ = self.session.logout();
    }

    pub fn has_capability(&mut self, cap: &str) -> bool {
        self.session
            .capabilities()
            .map(|c| c.has_str(cap))
            .unwrap_or(false)
    }

    pub fn mailboxes(&mut self) -> Result<&[MailboxInfo]> {
        if self.mailboxes.is_none() {
            let names = self.session.list(Some(""), Some("*"))?;
            let list = names
                .iter()
                .map(|n| {
                    let mut role = None;
                    let mut selectable = true;
                    for a in n.attributes() {
                        match a {
                            NameAttribute::NoSelect => selectable = false,
                            NameAttribute::All => role = Some("all"),
                            NameAttribute::Archive => role = Some("archive"),
                            NameAttribute::Drafts => role = Some("drafts"),
                            NameAttribute::Flagged => role = Some("flagged"),
                            NameAttribute::Junk => role = Some("junk"),
                            NameAttribute::Sent => role = Some("sent"),
                            NameAttribute::Trash => role = Some("trash"),
                            NameAttribute::Extension(e)
                                if e.eq_ignore_ascii_case("\\NonExistent") =>
                            {
                                selectable = false
                            }
                            _ => {}
                        }
                    }
                    MailboxInfo {
                        name: n.name().to_string(),
                        role: role.map(String::from),
                        selectable,
                    }
                })
                .collect();
            self.mailboxes = Some(list);
        }
        Ok(self.mailboxes.as_deref().unwrap())
    }

    fn mailbox_by_role(&mut self, role: &str) -> Result<Option<String>> {
        Ok(self
            .mailboxes()?
            .iter()
            .find(|m| m.role.as_deref() == Some(role))
            .map(|m| m.name.clone()))
    }

    fn mailbox_exists(&mut self, name: &str) -> Result<bool> {
        Ok(self.mailboxes()?.iter().any(|m| m.name == name))
    }

    /// The drafts mailbox: config override, then SPECIAL-USE `\Drafts`
    /// (handles localized Gmail names like `[Google Mail]/Entwürfe`), then the
    /// provider's well-known name.
    pub fn drafts_mailbox(&mut self) -> Result<String> {
        if let Some(m) = self.account.drafts_mailbox.clone() {
            return Ok(m);
        }
        if let Some(m) = self.mailbox_by_role("drafts")? {
            return Ok(m);
        }
        let fallback = self.account.provider.fallback_drafts();
        if self.mailbox_exists(fallback)? {
            return Ok(fallback.to_string());
        }
        bail!("could not find a drafts mailbox; set drafts_mailbox in the account config")
    }

    pub fn trash_mailbox(&mut self) -> Result<String> {
        if let Some(m) = self.account.trash_mailbox.clone() {
            return Ok(m);
        }
        if let Some(m) = self.mailbox_by_role("trash")? {
            return Ok(m);
        }
        let fallback = self.account.provider.fallback_trash();
        if self.mailbox_exists(fallback)? {
            return Ok(fallback.to_string());
        }
        bail!("could not find a trash mailbox; set trash_mailbox in the account config")
    }

    /// Resolve user-facing mailbox aliases ("drafts", "sent", "trash", ...) to real names.
    pub fn resolve_mailbox(&mut self, name: &str) -> Result<String> {
        if name.eq_ignore_ascii_case("inbox") {
            return Ok("INBOX".into());
        }
        if self.mailbox_exists(name)? {
            return Ok(name.to_string());
        }
        let lower = name.to_ascii_lowercase();
        if lower == "drafts" {
            return self.drafts_mailbox();
        }
        if lower == "trash" {
            return self.trash_mailbox();
        }
        if let Some(m) = self.mailbox_by_role(&lower)? {
            return Ok(m);
        }
        bail!("no mailbox named `{name}` (see `agent-mail mailboxes`)")
    }

    pub fn select(&mut self, mailbox: &str) -> Result<u32> {
        let mb = self
            .session
            .select(mailbox)
            .with_context(|| format!("selecting {mailbox}"))?;
        self.selected = Some(mailbox.to_string());
        Ok(mb.exists)
    }

    /// Most recent `limit` messages in the selected mailbox, newest first.
    pub fn recent(&mut self, mailbox: &str, limit: u32) -> Result<Vec<Summary>> {
        let exists = self.select(mailbox)?;
        if exists == 0 {
            return Ok(vec![]);
        }
        let start = exists.saturating_sub(limit.saturating_sub(1)).max(1);
        let fetches = self.session.fetch(
            format!("{start}:{exists}"),
            "(UID FLAGS INTERNALDATE BODY.PEEK[HEADER])",
        )?;
        let mut out: Vec<Summary> = merge_fetches(&fetches)
            .values()
            .filter_map(|m| m.uid.map(|u| summarize(u, m)))
            .collect();
        out.sort_by(|a, b| b.uid.cmp(&a.uid));
        Ok(out)
    }

    /// Run a UID SEARCH in `mailbox` and return summaries, newest first.
    pub fn search(&mut self, mailbox: &str, query: &str, limit: usize) -> Result<Vec<Summary>> {
        self.select(mailbox)?;
        let mut uids: Vec<u32> = self.session.uid_search(query)?.into_iter().collect();
        uids.sort_unstable_by(|a, b| b.cmp(a));
        uids.truncate(limit);
        self.summaries(&uids)
    }

    /// Summaries for UIDs in the currently selected mailbox, newest first.
    pub fn summaries(&mut self, uids: &[u32]) -> Result<Vec<Summary>> {
        if uids.is_empty() {
            return Ok(vec![]);
        }
        let set = uids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let fetches = self
            .session
            .uid_fetch(set, "(UID FLAGS INTERNALDATE BODY.PEEK[HEADER])")?;
        let mut out: Vec<Summary> = merge_fetches(&fetches)
            .values()
            .filter_map(|m| m.uid.map(|u| summarize(u, m)))
            .collect();
        out.sort_by(|a, b| b.uid.cmp(&a.uid));
        Ok(out)
    }

    /// Fetch the full raw RFC 822 message for `uid` in `mailbox`.
    pub fn fetch_raw(
        &mut self,
        mailbox: &str,
        uid: u32,
        mark_seen: bool,
    ) -> Result<(Vec<u8>, Vec<String>)> {
        self.select(mailbox)?;
        let item = if mark_seen {
            "(UID FLAGS BODY[])"
        } else {
            "(UID FLAGS BODY.PEEK[])"
        };
        let fetches = self.session.uid_fetch(uid.to_string(), item)?;
        let merged = merge_fetches(&fetches);
        let m = merged
            .values()
            .find(|m| m.uid == Some(uid) && m.body.is_some())
            .or_else(|| merged.values().find(|m| m.body.is_some()))
            .ok_or_else(|| anyhow!("message UID {uid} not found in {mailbox}"))?;
        Ok((m.body.clone().unwrap(), m.flags.clone()))
    }

    pub fn uid_exists(&mut self, mailbox: &str, uid: u32) -> Result<bool> {
        self.select(mailbox)?;
        Ok(self
            .session
            .uid_search(format!("UID {uid}"))?
            .contains(&uid))
    }

    pub fn find_by_header(&mut self, mailbox: &str, header: &str, value: &str) -> Result<Vec<u32>> {
        self.select(mailbox)?;
        let mut v: Vec<u32> = self
            .session
            .uid_search(format!("HEADER {} {}", header, imap_quote(value)))?
            .into_iter()
            .collect();
        v.sort_unstable();
        Ok(v)
    }

    /// APPEND a message and return its UID (from APPENDUID when the server
    /// supports UIDPLUS, otherwise by searching for its Message-ID).
    pub fn append(
        &mut self,
        mailbox: &str,
        raw: &[u8],
        flags: &[Flag<'static>],
        message_id: &str,
    ) -> Result<Option<u32>> {
        let appended = self
            .session
            .append(mailbox, raw)
            .flags(flags.iter().cloned())
            .internal_date(chrono::Local::now().fixed_offset())
            .finish()
            .with_context(|| format!("appending to {mailbox}"))?;
        if let Some(UidSetMember::Uid(u)) = appended.uids.as_ref().and_then(|v| v.first().cloned())
        {
            return Ok(Some(u));
        }
        Ok(self
            .find_by_header(mailbox, "Message-ID", message_id)?
            .last()
            .copied())
    }

    /// Permanently remove a message, using the strategy that actually works for the provider.
    ///
    /// * Gmail: a `\Deleted` + EXPUNGE in a label folder only removes the label
    ///   (the message falls into All Mail). We MOVE it to Trash and expunge it
    ///   there, which deletes it for real.
    /// * iCloud (and generic IMAP): flag `\Deleted` and UID EXPUNGE just that UID.
    pub fn delete_message(
        &mut self,
        mailbox: &str,
        uid: u32,
        message_id: Option<&str>,
    ) -> Result<()> {
        self.select(mailbox)?;
        match self.account.provider {
            Provider::Gmail => {
                let trash = self.trash_mailbox()?;
                self.session
                    .uid_mv(uid.to_string(), &trash)
                    .context("moving old draft to Trash")?;
                if let Some(mid) = message_id {
                    let in_trash = self.find_by_header(&trash, "Message-ID", mid)?;
                    if !in_trash.is_empty() {
                        let set = in_trash
                            .iter()
                            .map(u32::to_string)
                            .collect::<Vec<_>>()
                            .join(",");
                        self.expunge_uids(&set)?;
                    }
                }
            }
            Provider::Icloud => {
                self.expunge_uids(&uid.to_string())?;
            }
        }
        Ok(())
    }

    /// Flag `\Deleted` and expunge only the given UIDs in the selected mailbox.
    fn expunge_uids(&mut self, set: &str) -> Result<()> {
        self.session.uid_store(set, "+FLAGS.SILENT (\\Deleted)")?;
        if self.has_capability("UIDPLUS") {
            self.session.uid_expunge(set)?;
        } else {
            self.session.expunge()?;
        }
        Ok(())
    }
}

fn login_hint(p: Provider) -> &'static str {
    match p {
        Provider::Gmail => {
            "Gmail requires an app password (Google Account → Security → 2-Step Verification → App passwords) and IMAP enabled in Gmail settings."
        }
        Provider::Icloud => {
            "iCloud requires an app-specific password (account.apple.com → Sign-In and Security → App-Specific Passwords)."
        }
    }
}

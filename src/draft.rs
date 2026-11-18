//! Draft model: building RFC 5322 messages, parsing them back, and the
//! plain-text editor format.

use anyhow::{Result, bail};
use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address as BAddress;
use mail_builder::headers::message_id::MessageId;
use mail_builder::headers::raw::Raw;
use mail_parser::{MessageParser, MimeHeaders};
use serde::Serialize;

use crate::config::{Account, Provider};

/// Stable identity for a draft across revisions. IMAP messages are immutable,
/// so every save is a new message with a new UID; this header lets us (and
/// Apple Mail, which uses the same header) recognize revisions of one draft.
pub const UUID_HEADER: &str = "X-Universally-Unique-Identifier";
/// Apple Mail's marker that a message is an editable draft.
pub const APPLE_DRAFT_HEADER: &str = "X-Uniform-Type-Identifier";
pub const APPLE_DRAFT_VALUE: &str = "com.apple.mail-draft";

#[derive(Debug, Clone, Serialize)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    #[serde(skip)]
    pub data: Vec<u8>,
    pub size: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Draft {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// Stable draft id (see [`UUID_HEADER`]).
    pub id: String,
    pub attachments: Vec<Attachment>,
    /// Original HTML body of a draft created elsewhere; kept only while the
    /// plain-text body is unchanged so we don't silently clobber formatting.
    #[serde(skip)]
    pub html: Option<String>,
    #[serde(skip)]
    pub original_text: Option<String>,
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string().to_uppercase()
}

pub fn from_header(account: &Account) -> String {
    match &account.name {
        Some(n) => format!("{n} <{}>", account.email),
        None => account.email.clone(),
    }
}

fn strip_brackets(s: &str) -> String {
    s.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

pub fn addrs_to_string(a: Option<&mail_parser::Address<'_>>) -> String {
    addr_list(a).join(", ")
}

fn fmt_addr(a: &mail_parser::Addr<'_>) -> Option<String> {
    let email = a.address()?;
    Some(match a.name() {
        Some(n) if !n.is_empty() && n != email => {
            if n.contains([',', '"', '<', '>', '@', ';', ':']) {
                format!("\"{}\" <{email}>", n.replace('"', "'"))
            } else {
                format!("{n} <{email}>")
            }
        }
        _ => email.to_string(),
    })
}

fn addr_list(a: Option<&mail_parser::Address<'_>>) -> Vec<String> {
    a.map(|a| a.iter().filter_map(fmt_addr).collect())
        .unwrap_or_default()
}

/// Parse a comma-separated address list ("Ann <a@x>, b@y") using a real
/// RFC 5322 parser, so quoted display names with commas work.
pub fn parse_addresses(s: &str) -> Result<Vec<String>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(vec![]);
    }
    let hdr = format!("To: {s}\r\n\r\n");
    let parsed = MessageParser::default().parse_headers(hdr.as_bytes());
    let list = addr_list(parsed.as_ref().and_then(|p| p.to()));
    if list.is_empty() {
        bail!("could not parse address list: {s}");
    }
    for a in &list {
        let email = a.rsplit('<').next().unwrap_or(a).trim_end_matches('>');
        if !email.contains('@') {
            bail!("invalid address: {a}");
        }
    }
    Ok(list)
}

fn to_builder_addrs(list: &[String]) -> Vec<BAddress<'static>> {
    list.iter()
        .map(|s| {
            let hdr = format!("To: {s}\r\n\r\n");
            let parsed = MessageParser::default().parse_headers(hdr.as_bytes());
            match parsed.as_ref().and_then(|p| p.to()).and_then(|a| a.first()) {
                Some(a) => BAddress::new_address(
                    a.name().map(|n| n.to_string()),
                    a.address().unwrap_or(s).to_string(),
                ),
                None => BAddress::new_address(None::<String>, s.clone()),
            }
        })
        .collect()
}

impl Draft {
    pub fn new(account: &Account) -> Draft {
        Draft {
            from: from_header(account),
            id: new_id(),
            ..Default::default()
        }
    }

    /// Serialize to RFC 5322 bytes. Returns (bytes, message_id-without-brackets).
    /// Every revision gets a fresh Message-ID: Gmail de-duplicates messages
    /// that share a Message-ID, which would make a replaced draft vanish.
    pub fn to_rfc822(&self, account: &Account) -> Result<(Vec<u8>, String)> {
        let domain = account.email.rsplit('@').next().unwrap_or("localhost");
        let message_id = format!("{}@{}", uuid::Uuid::new_v4().simple(), domain);

        let from = to_builder_addrs(std::slice::from_ref(&self.from));
        let mut b = MessageBuilder::new()
            .from(from.into_iter().next().unwrap())
            .subject(self.subject.clone())
            .date(chrono::Utc::now().timestamp())
            .message_id(MessageId::new(message_id.clone()));
        if !self.to.is_empty() {
            b = b.to(BAddress::new_list(to_builder_addrs(&self.to)));
        }
        if !self.cc.is_empty() {
            b = b.cc(BAddress::new_list(to_builder_addrs(&self.cc)));
        }
        if !self.bcc.is_empty() {
            // Drafts keep Bcc so it survives a round-trip; it's stripped at send time.
            b = b.bcc(BAddress::new_list(to_builder_addrs(&self.bcc)));
        }
        if let Some(irt) = &self.in_reply_to {
            b = b.in_reply_to(MessageId::new(irt.clone()));
        }
        if !self.references.is_empty() {
            b = b.references(MessageId::new_list(self.references.iter().cloned()));
        }
        b = b.header(UUID_HEADER, Raw::new(self.id.clone()));
        if account.provider == Provider::Icloud {
            b = b.header(APPLE_DRAFT_HEADER, Raw::new(APPLE_DRAFT_VALUE));
        }
        b = b.text_body(self.body.clone());
        if let Some(html) = &self.html
            && self.original_text.as_deref() == Some(self.body.as_str())
        {
            b = b.html_body(html.clone());
        }
        for a in &self.attachments {
            b = b.attachment(a.content_type.clone(), a.filename.clone(), a.data.clone());
        }
        Ok((b.write_to_vec()?, message_id))
    }

    pub fn from_rfc822(raw: &[u8]) -> Result<Draft> {
        let Some(m) = MessageParser::default().parse(raw) else {
            bail!("could not parse draft");
        };
        let body = m
            .body_text(0)
            .map(|s| s.replace("\r\n", "\n"))
            .unwrap_or_default();
        let html = if m.html_body_count() > 0 && m.html_part(0).is_some_and(|p| p.is_text_html()) {
            m.body_html(0).map(|s| s.into_owned())
        } else {
            None
        };
        let attachments = m
            .attachments()
            .map(|p| {
                let ct = p
                    .content_type()
                    .map(|c| match c.subtype() {
                        Some(s) => format!("{}/{}", c.ctype(), s),
                        None => c.ctype().to_string(),
                    })
                    .unwrap_or_else(|| "application/octet-stream".into());
                let data = p.contents().to_vec();
                Attachment {
                    filename: p.attachment_name().unwrap_or("attachment").to_string(),
                    content_type: ct,
                    size: data.len(),
                    data,
                }
            })
            .collect();
        let refs = m
            .references()
            .as_text_list()
            .map(|l| l.iter().map(|s| strip_brackets(s)).collect())
            .or_else(|| m.references().as_text().map(|s| vec![strip_brackets(s)]))
            .unwrap_or_default();
        Ok(Draft {
            from: addrs_to_string(m.from()),
            to: addr_list(m.to()),
            cc: addr_list(m.cc()),
            bcc: addr_list(m.bcc()),
            subject: m.subject().unwrap_or("").to_string(),
            in_reply_to: m.in_reply_to().as_text().map(strip_brackets),
            references: refs,
            id: m
                .header_raw(UUID_HEADER)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(new_id),
            attachments,
            original_text: Some(body.clone()),
            html,
            body,
        })
    }

    /// Plain-text representation for $EDITOR: headers, blank line, body.
    pub fn to_editor_text(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("From: {}\n", self.from));
        s.push_str(&format!("To: {}\n", self.to.join(", ")));
        s.push_str(&format!("Cc: {}\n", self.cc.join(", ")));
        s.push_str(&format!("Bcc: {}\n", self.bcc.join(", ")));
        s.push_str(&format!("Subject: {}\n", self.subject));
        if !self.attachments.is_empty() {
            s.push_str("# Attachments (kept as-is): ");
            s.push_str(
                &self
                    .attachments
                    .iter()
                    .map(|a| a.filename.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            s.push('\n');
        }
        s.push_str("# Lines starting with '#' in the header block are ignored. Body follows the blank line.\n");
        s.push('\n');
        s.push_str(&self.body);
        s
    }

    pub fn apply_editor_text(&mut self, text: &str) -> Result<()> {
        let text = text.replace("\r\n", "\n");
        let (head, body) = match text.split_once("\n\n") {
            Some((h, b)) => (h.to_string(), b.to_string()),
            None => (text.clone(), String::new()),
        };
        for line in head.lines() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once(':') else {
                bail!("malformed header line: {line}");
            };
            let v = v.trim();
            match k.trim().to_ascii_lowercase().as_str() {
                "from" => self.from = v.to_string(),
                "to" => self.to = parse_addresses(v)?,
                "cc" => self.cc = parse_addresses(v)?,
                "bcc" => self.bcc = parse_addresses(v)?,
                "subject" => self.subject = v.to_string(),
                other => bail!("unknown header `{other}` (allowed: From, To, Cc, Bcc, Subject)"),
            }
        }
        self.body = body;
        Ok(())
    }
}

fn quote_body(text: &str) -> String {
    text.lines()
        .map(|l| {
            if l.is_empty() {
                ">".to_string()
            } else {
                format!("> {l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn prefixed(subject: &str, prefix: &str) -> String {
    let lower = subject.to_ascii_lowercase();
    if lower.starts_with(&format!("{}:", prefix.to_ascii_lowercase())) {
        subject.to_string()
    } else {
        format!("{prefix}: {subject}")
    }
}

/// Build a reply draft. Threading (Gmail conversations, Apple Mail threads)
/// relies on In-Reply-To/References plus a matching subject.
pub fn reply(account: &Account, raw: &[u8], all: bool) -> Result<Draft> {
    let Some(m) = MessageParser::default().parse(raw) else {
        bail!("could not parse original message");
    };
    let mut d = Draft::new(account);
    let me = account.email.to_ascii_lowercase();
    let is_me = |a: &String| a.to_ascii_lowercase().contains(&me);

    let reply_to = addr_list(m.reply_to());
    let from = addr_list(m.from());
    let orig_from_me = from.iter().any(is_me);
    d.to = if !reply_to.is_empty() {
        reply_to
    } else if orig_from_me {
        // Replying to our own sent message: address the original recipients.
        addr_list(m.to())
    } else {
        from.clone()
    };
    if all {
        let mut cc: Vec<String> = addr_list(m.to());
        cc.extend(addr_list(m.cc()));
        cc.retain(|a| !is_me(a) && !d.to.iter().any(|t| t.eq_ignore_ascii_case(a)));
        cc.dedup();
        d.cc = cc;
    }
    d.subject = prefixed(m.subject().unwrap_or(""), "Re");
    if let Some(mid) = m.message_id() {
        let mid = strip_brackets(mid);
        let mut refs: Vec<String> = m
            .references()
            .as_text_list()
            .map(|l| l.iter().map(|s| strip_brackets(s)).collect())
            .or_else(|| m.references().as_text().map(|s| vec![strip_brackets(s)]))
            .unwrap_or_default();
        if refs.is_empty()
            && let Some(irt) = m.in_reply_to().as_text()
        {
            refs.push(strip_brackets(irt));
        }
        refs.push(mid.clone());
        d.in_reply_to = Some(mid);
        d.references = refs;
    }
    let date = m.date().map(|d| d.to_rfc822()).unwrap_or_default();
    let who = from.first().cloned().unwrap_or_default();
    let orig = m.body_text(0).map(|s| s.into_owned()).unwrap_or_default();
    d.body = format!("\n\nOn {date}, {who} wrote:\n{}\n", quote_body(&orig));
    Ok(d)
}

pub fn forward(account: &Account, raw: &[u8]) -> Result<Draft> {
    let orig = Draft::from_rfc822(raw)?;
    let Some(m) = MessageParser::default().parse(raw) else {
        bail!("could not parse original message");
    };
    let mut d = Draft::new(account);
    d.subject = prefixed(&orig.subject, "Fwd");
    let date = m.date().map(|d| d.to_rfc822()).unwrap_or_default();
    d.body = format!(
        "\n\n---------- Forwarded message ----------\nFrom: {}\nDate: {}\nSubject: {}\nTo: {}\n\n{}\n",
        orig.from,
        date,
        orig.subject,
        orig.to.join(", "),
        orig.body
    );
    d.attachments = orig.attachments;
    Ok(d)
}

pub fn attachment_from_path(path: &std::path::Path) -> Result<Attachment> {
    let data = std::fs::read(path)?;
    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "attachment".into());
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let content_type = match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "txt" | "md" => "text/plain",
        "html" | "htm" => "text/html",
        "csv" => "text/csv",
        "json" => "application/json",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string();
    Ok(Attachment {
        filename,
        content_type,
        size: data.len(),
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;

    fn acct(p: Provider) -> Account {
        Account {
            provider: p,
            email: "me@example.com".into(),
            name: Some("Me Myself".into()),
            username: None,
            host: None,
            port: None,
            auth: AuthMethod::Password,
            password_command: None,
            oauth_token_command: None,
            drafts_mailbox: None,
            trash_mailbox: None,
            insecure_plaintext: false,
        }
    }

    #[test]
    fn roundtrip_preserves_fields_and_id() {
        let a = acct(Provider::Icloud);
        let mut d = Draft::new(&a);
        d.to = parse_addresses("\"Doe, Jane\" <jane@x.com>, bob@y.org").unwrap();
        d.bcc = vec!["secret@z.com".into()];
        d.subject = "Héllo wörld".into();
        d.body = "line one\nline two ünïcode\n".into();
        d.in_reply_to = Some("abc@x.com".into());
        d.references = vec!["root@x.com".into(), "abc@x.com".into()];
        let (raw, mid) = d.to_rfc822(&a).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("X-Uniform-Type-Identifier: com.apple.mail-draft"));
        assert!(text.contains(&format!("<{mid}>")));
        let back = Draft::from_rfc822(&raw).unwrap();
        assert_eq!(back.id, d.id);
        assert_eq!(back.to.len(), 2);
        assert!(back.to[0].contains("jane@x.com"));
        assert_eq!(back.bcc, vec!["secret@z.com".to_string()]);
        assert_eq!(back.subject, d.subject);
        assert_eq!(back.body.trim_end(), d.body.trim_end());
        assert_eq!(back.in_reply_to.as_deref(), Some("abc@x.com"));
        assert_eq!(back.references, d.references);
    }

    #[test]
    fn gmail_has_no_apple_header_and_fresh_message_ids() {
        let a = acct(Provider::Gmail);
        let d = Draft::new(&a);
        let (raw1, m1) = d.to_rfc822(&a).unwrap();
        let (_, m2) = d.to_rfc822(&a).unwrap();
        assert_ne!(m1, m2);
        assert!(!String::from_utf8_lossy(&raw1).contains("com.apple.mail-draft"));
    }

    #[test]
    fn editor_roundtrip() {
        let a = acct(Provider::Gmail);
        let mut d = Draft::new(&a);
        d.apply_editor_text("From: Me <me@example.com>\nTo: a@b.com, C <c@d.com>\nCc:\nBcc:\nSubject: Hi there\n# comment\n\nBody\n\nmore\n").unwrap();
        assert_eq!(d.to.len(), 2);
        assert_eq!(d.subject, "Hi there");
        assert_eq!(d.body, "Body\n\nmore\n");
        let mut d2 = Draft::new(&a);
        d2.apply_editor_text(&d.to_editor_text()).unwrap();
        assert_eq!(d2.to, d.to);
        assert_eq!(d2.body, d.body);
    }

    #[test]
    fn reply_threads() {
        let a = acct(Provider::Gmail);
        let orig = b"From: Ann <ann@x.com>\r\nTo: me@example.com, zed@x.com\r\nSubject: Plans\r\nMessage-ID: <m2@x.com>\r\nReferences: <m1@x.com>\r\nDate: Mon, 16 Nov 2026 10:00:00 +0000\r\n\r\nSee you\r\n";
        let r = reply(&a, orig, true).unwrap();
        assert_eq!(r.subject, "Re: Plans");
        assert_eq!(r.to, vec!["Ann <ann@x.com>".to_string()]);
        assert_eq!(r.cc, vec!["zed@x.com".to_string()]);
        assert_eq!(r.in_reply_to.as_deref(), Some("m2@x.com"));
        assert_eq!(
            r.references,
            vec!["m1@x.com".to_string(), "m2@x.com".to_string()]
        );
        assert!(r.body.contains("> See you"));
    }
}

mod auth;
mod config;
mod draft;
mod mail;

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use imap::types::Flag;
use serde::Serialize;

use config::{Account, AuthMethod, Config, Provider};
use draft::Draft;
use mail::{Client, Summary};

/// A command-line email client for Gmail and iCloud Mail.
///
/// Reads mail and manages drafts over IMAP. It never sends mail: drafts are
/// saved to the account's Drafts mailbox where they sync to the web UI and
/// other clients (Gmail web/app, Apple Mail on Mac/iPhone).
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Account name from the config (defaults to `default_account`).
    #[arg(short, long, global = true, env = "AGENT_MAIL_ACCOUNT")]
    account: Option<String>,
    /// Emit JSON instead of human-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Manage configured accounts.
    #[command(subcommand)]
    Account(AccountCmd),
    /// List mailboxes (folders/labels) and their special-use roles.
    Mailboxes,
    /// List the most recent messages in a mailbox.
    List {
        #[arg(short, long, default_value = "INBOX")]
        mailbox: String,
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: u32,
    },
    /// Search a mailbox. Uses Gmail search syntax on Gmail, full-text search elsewhere.
    Search {
        query: String,
        #[arg(short, long, default_value = "INBOX")]
        mailbox: String,
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: usize,
        /// Treat QUERY as a raw IMAP SEARCH criteria string (e.g. 'UNSEEN FROM "bob"').
        #[arg(long)]
        imap: bool,
    },
    /// Show a message.
    Read {
        uid: u32,
        #[arg(short, long, default_value = "INBOX")]
        mailbox: String,
        /// Print the raw RFC 822 source.
        #[arg(long)]
        raw: bool,
        /// Mark the message as read (default: leave flags untouched).
        #[arg(long)]
        mark_read: bool,
    },
    /// Create, edit and manage drafts (synced to the server's Drafts mailbox).
    #[command(subcommand)]
    Draft(DraftCmd),
}

#[derive(Subcommand)]
enum AccountCmd {
    /// Add an account. Prompts for the app password and stores it in the OS keychain.
    Add {
        name: String,
        #[arg(long, value_enum)]
        provider: Provider,
        #[arg(long)]
        email: String,
        /// Display name for the From header.
        #[arg(long)]
        display_name: Option<String>,
        /// IMAP username if different from the email address.
        #[arg(long)]
        username: Option<String>,
        /// Read the password from stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
        /// Don't store a password; get it from this shell command instead.
        #[arg(long)]
        password_command: Option<String>,
        /// Use XOAUTH2 with a token from this shell command (Gmail).
        #[arg(long, conflicts_with_all = ["password_stdin", "password_command"])]
        oauth_token_command: Option<String>,
        /// Make this the default account.
        #[arg(long)]
        default: bool,
        /// Skip the test login.
        #[arg(long)]
        no_verify: bool,
    },
    /// List configured accounts.
    List,
    /// Remove an account and its stored password.
    Remove { name: String },
    /// Set the default account.
    Default { name: String },
}

#[derive(Args, Default)]
struct Compose {
    /// Recipients (comma-separated, may be repeated).
    #[arg(long)]
    to: Vec<String>,
    #[arg(long)]
    cc: Vec<String>,
    #[arg(long)]
    bcc: Vec<String>,
    #[arg(short, long)]
    subject: Option<String>,
    /// Body text. Use `-` to read from stdin.
    #[arg(short, long, conflicts_with = "body_file")]
    body: Option<String>,
    /// Read the body from a file.
    #[arg(long)]
    body_file: Option<PathBuf>,
    /// Attach a file (may be repeated).
    #[arg(long)]
    attach: Vec<PathBuf>,
    /// Open $EDITOR on the draft before saving.
    #[arg(short, long)]
    edit: bool,
}

impl Compose {
    fn has_content(&self) -> bool {
        !self.to.is_empty()
            || !self.cc.is_empty()
            || !self.bcc.is_empty()
            || self.subject.is_some()
            || self.body.is_some()
            || self.body_file.is_some()
            || !self.attach.is_empty()
    }

    fn body_text(&self) -> Result<Option<String>> {
        if let Some(path) = &self.body_file {
            return Ok(Some(std::fs::read_to_string(path)?));
        }
        match self.body.as_deref() {
            Some("-") => {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                Ok(Some(s))
            }
            Some(b) => Ok(Some(b.to_string())),
            None => Ok(None),
        }
    }

    /// Apply flags onto a draft. For replies the body flag is prepended above the quote.
    fn apply(&self, d: &mut Draft, prepend_body: bool) -> Result<()> {
        let list = |v: &[String]| -> Result<Vec<String>> {
            let mut out = vec![];
            for s in v {
                out.extend(draft::parse_addresses(s)?);
            }
            Ok(out)
        };
        if !self.to.is_empty() {
            d.to = list(&self.to)?;
        }
        if !self.cc.is_empty() {
            d.cc = list(&self.cc)?;
        }
        if !self.bcc.is_empty() {
            d.bcc = list(&self.bcc)?;
        }
        if let Some(s) = &self.subject {
            d.subject = s.clone();
        }
        if let Some(b) = self.body_text()? {
            d.body = if prepend_body {
                format!("{}{}", b.trim_end_matches('\n'), d.body)
            } else {
                b
            };
        }
        for p in &self.attach {
            d.attachments.push(
                draft::attachment_from_path(p)
                    .with_context(|| format!("attaching {}", p.display()))?,
            );
        }
        Ok(())
    }

    /// Open the editor if asked, or if nothing was supplied and we're interactive.
    fn wants_editor(&self) -> bool {
        self.edit
            || (!self.has_content()
                && std::io::stdin().is_terminal()
                && std::io::stdout().is_terminal())
    }
}

#[derive(Subcommand)]
enum DraftCmd {
    /// List drafts.
    List {
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: u32,
    },
    /// Show a draft. ID is a UID or the stable draft id.
    Show { id: String },
    /// Create a new draft.
    New(Compose),
    /// Create a reply draft to a message (threaded via In-Reply-To/References).
    Reply {
        uid: u32,
        #[arg(short, long, default_value = "INBOX")]
        mailbox: String,
        /// Reply to all recipients.
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        compose: Compose,
    },
    /// Create a forward draft of a message (keeps attachments).
    Forward {
        uid: u32,
        #[arg(short, long, default_value = "INBOX")]
        mailbox: String,
        #[command(flatten)]
        compose: Compose,
    },
    /// Edit a draft. Replaces it on the server, keeping its stable draft id.
    Edit {
        id: String,
        #[command(flatten)]
        compose: Compose,
        /// Remove an attachment by filename (may be repeated).
        #[arg(long)]
        remove_attachment: Vec<String>,
        /// Save even if the draft was changed on the server since it was loaded.
        #[arg(long)]
        force: bool,
    },
    /// Delete a draft.
    Delete { id: String },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn print_json<T: Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let mut cfg = Config::load()?;

    if let Cmd::Account(cmd) = &cli.cmd {
        return account_cmd(cmd, &mut cfg, cli.json);
    }

    let (name, account) = cfg.account(cli.account.as_deref())?;
    let mut c = Client::connect(&name, &account)?;
    let res = dispatch(&cli, &mut c);
    c.logout();
    res
}

fn dispatch(cli: &Cli, c: &mut Client) -> Result<()> {
    let json = cli.json;
    match &cli.cmd {
        Cmd::Account(_) => unreachable!(),
        Cmd::Mailboxes => {
            let list = c.mailboxes()?.to_vec();
            if json {
                return print_json(&list);
            }
            for m in list.iter().filter(|m| m.selectable) {
                match &m.role {
                    Some(r) => println!("{}  ({r})", m.name),
                    None => println!("{}", m.name),
                }
            }
        }
        Cmd::List { mailbox, limit } => {
            let mb = c.resolve_mailbox(mailbox)?;
            let msgs = c.recent(&mb, *limit)?;
            print_summaries(&msgs, json)?;
        }
        Cmd::Search {
            query,
            mailbox,
            limit,
            imap,
        } => {
            let mb = c.resolve_mailbox(mailbox)?;
            let criteria = if *imap {
                query.clone()
            } else if c.account.provider == Provider::Gmail {
                format!("X-GM-RAW {}", mail::imap_quote(query))
            } else {
                format!("TEXT {}", mail::imap_quote(query))
            };
            let msgs = c.search(&mb, &criteria, *limit)?;
            print_summaries(&msgs, json)?;
        }
        Cmd::Read {
            uid,
            mailbox,
            raw,
            mark_read,
        } => {
            let mb = c.resolve_mailbox(mailbox)?;
            let (bytes, flags) = c.fetch_raw(&mb, *uid, *mark_read)?;
            if *raw {
                std::io::stdout().write_all(&bytes)?;
                return Ok(());
            }
            print_message(*uid, &bytes, &flags, json)?;
        }
        Cmd::Draft(cmd) => draft_cmd(cmd, c, json)?,
    }
    Ok(())
}

fn print_summaries(msgs: &[Summary], json: bool) -> Result<()> {
    if json {
        return print_json(&msgs);
    }
    if msgs.is_empty() {
        println!("(no messages)");
    }
    for m in msgs {
        let unread = if m.flags.iter().any(|f| f == "seen") {
            ' '
        } else {
            '*'
        };
        let date = m
            .date
            .as_deref()
            .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
            .map(|d| {
                d.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M")
                    .to_string()
            })
            .unwrap_or_default();
        println!(
            "{:>7} {unread} {:16}  {:30}  {}",
            m.uid,
            date,
            truncate(&m.from, 30),
            m.subject
        );
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

#[derive(Serialize)]
struct MessageView {
    uid: u32,
    flags: Vec<String>,
    from: String,
    to: String,
    cc: String,
    date: Option<String>,
    subject: String,
    message_id: Option<String>,
    body: String,
    attachments: Vec<draft::Attachment>,
}

fn print_message(uid: u32, raw: &[u8], flags: &[String], json: bool) -> Result<()> {
    let m = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| anyhow!("could not parse message"))?;
    let d = Draft::from_rfc822(raw)?;
    let view = MessageView {
        uid,
        flags: flags.to_vec(),
        from: d.from.clone(),
        to: d.to.join(", "),
        cc: d.cc.join(", "),
        date: m.date().map(|d| d.to_rfc3339()),
        subject: d.subject.clone(),
        message_id: m.message_id().map(String::from),
        body: d.body.clone(),
        attachments: d.attachments.clone(),
    };
    if json {
        return print_json(&view);
    }
    println!("From:    {}", view.from);
    println!("To:      {}", view.to);
    if !view.cc.is_empty() {
        println!("Cc:      {}", view.cc);
    }
    if let Some(dt) = &view.date {
        println!("Date:    {dt}");
    }
    println!("Subject: {}", view.subject);
    for a in &view.attachments {
        println!(
            "Attach:  {} ({}, {} bytes)",
            a.filename, a.content_type, a.size
        );
    }
    println!();
    println!("{}", view.body);
    Ok(())
}

// ---------------------------------------------------------------- drafts

#[derive(Serialize)]
struct Saved {
    uid: Option<u32>,
    draft_id: String,
    mailbox: String,
    replaced: Vec<u32>,
}

/// Find a draft by UID or stable draft id; returns (uid, raw bytes).
fn load_draft(c: &mut Client, id: &str) -> Result<(String, u32, Vec<u8>)> {
    let mb = c.drafts_mailbox()?;
    let uid = match id.parse::<u32>() {
        Ok(uid) => {
            if !c.uid_exists(&mb, uid)? {
                bail!(
                    "no draft with UID {uid} in {mb}. Drafts get a new UID every time they are saved \
                     (here or in another client); run `draft list` or use the stable draft id."
                );
            }
            uid
        }
        Err(_) => {
            let revisions = draft_revisions(c, &mb, id)?;
            *revisions
                .last()
                .ok_or_else(|| anyhow!("no draft with id {id}"))?
        }
    };
    let (raw, _) = c.fetch_raw(&mb, uid, false)?;
    Ok((mb, uid, raw))
}

/// All UIDs in the drafts mailbox carrying this draft id, ascending.
/// We scan headers client-side rather than `SEARCH HEADER X-...` because
/// Gmail doesn't reliably index arbitrary X- headers.
fn draft_revisions(c: &mut Client, mb: &str, draft_id: &str) -> Result<Vec<u32>> {
    let mut v: Vec<u32> = c
        .recent(mb, u32::MAX)?
        .into_iter()
        .filter(|s| {
            s.draft_id
                .as_deref()
                .is_some_and(|d| d.eq_ignore_ascii_case(draft_id))
        })
        .map(|s| s.uid)
        .collect();
    v.sort_unstable();
    Ok(v)
}

/// Save a draft the way Gmail and iCloud expect:
///
/// 1. APPEND the new revision to the special-use Drafts mailbox with the
///    `\Draft` and `\Seen` flags (Gmail turns this into a real draft in the
///    web UI; Apple Mail additionally keys off `X-Uniform-Type-Identifier`).
/// 2. Only after the append succeeds, remove the previous revision(s) using the
///    provider's real-delete strategy, so a failure never loses the draft.
fn save_draft(c: &mut Client, d: &Draft, replacing: Option<u32>, force: bool) -> Result<Saved> {
    let mb = c.drafts_mailbox()?;
    if let Some(old) = replacing
        && !c.uid_exists(&mb, old)?
        && !force
    {
        bail!(
            "draft UID {old} no longer exists on the server (edited or sent from another client?). \
                 Re-run `draft edit {}` to edit the latest version, or pass --force to save as a new draft.",
            d.id
        );
    }
    let (raw, mid) = d.to_rfc822(&c.account)?;
    let uid = c.append(&mb, &raw, &[Flag::Draft, Flag::Seen], &mid)?;

    let mut stale: Vec<u32> = draft_revisions(c, &mb, &d.id)?;
    if let Some(old) = replacing {
        stale.push(old);
    }
    stale.sort_unstable();
    stale.dedup();
    stale.retain(|u| Some(*u) != uid);
    let mut replaced = vec![];
    for old in stale {
        if !c.uid_exists(&mb, old)? {
            continue;
        }
        let (old_raw, _) = c.fetch_raw(&mb, old, false)?;
        let old_mid = mail_parser::MessageParser::default()
            .parse_headers(&old_raw)
            .and_then(|m| m.message_id().map(String::from));
        c.delete_message(&mb, old, old_mid.as_deref())
            .with_context(|| format!("removing previous revision UID {old}"))?;
        replaced.push(old);
    }
    Ok(Saved {
        uid,
        draft_id: d.id.clone(),
        mailbox: mb,
        replaced,
    })
}

fn edit_in_editor(d: &mut Draft) -> Result<()> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".into());
    let mut tmp = tempfile::Builder::new().suffix(".eml.txt").tempfile()?;
    tmp.write_all(d.to_editor_text().as_bytes())?;
    tmp.flush()?;
    let path = tmp.path().to_owned();
    loop {
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$1\""))
            .arg("sh")
            .arg(&path)
            .status()
            .with_context(|| format!("launching editor `{editor}`"))?;
        if !status.success() {
            bail!("editor exited with {status}; draft not saved");
        }
        let text = std::fs::read_to_string(&path)?;
        match d.apply_editor_text(&text) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("error: {e:#}");
                eprint!("Re-open editor? [Y/n] ");
                let mut ans = String::new();
                std::io::stdin().read_line(&mut ans)?;
                if ans.trim().eq_ignore_ascii_case("n") {
                    bail!("draft not saved");
                }
            }
        }
    }
}

fn report_saved(s: &Saved, verb: &str, json: bool) -> Result<()> {
    if json {
        return print_json(s);
    }
    let uid = s.uid.map(|u| u.to_string()).unwrap_or_else(|| "?".into());
    println!(
        "{verb} draft in {} (uid {uid}, id {})",
        s.mailbox, s.draft_id
    );
    Ok(())
}

fn draft_cmd(cmd: &DraftCmd, c: &mut Client, json: bool) -> Result<()> {
    match cmd {
        DraftCmd::List { limit } => {
            let mb = c.drafts_mailbox()?;
            let msgs = c.recent(&mb, *limit)?;
            if json {
                return print_json(&msgs);
            }
            if msgs.is_empty() {
                println!("(no drafts)");
            }
            for m in &msgs {
                let to = if m.to.is_empty() {
                    "(no recipients)"
                } else {
                    &m.to
                };
                let subject = if m.subject.is_empty() {
                    "(no subject)"
                } else {
                    &m.subject
                };
                println!("{:>7}  {:30}  {}", m.uid, truncate(to, 30), subject);
            }
        }
        DraftCmd::Show { id } => {
            let (_, uid, raw) = load_draft(c, id)?;
            let d = Draft::from_rfc822(&raw)?;
            if json {
                #[derive(Serialize)]
                struct V<'a> {
                    uid: u32,
                    #[serde(flatten)]
                    draft: &'a Draft,
                }
                return print_json(&V { uid, draft: &d });
            }
            println!("# uid {uid}, id {}", d.id);
            print!("{}", d.to_editor_text());
            println!();
        }
        DraftCmd::New(compose) => {
            let mut d = Draft::new(&c.account);
            compose.apply(&mut d, false)?;
            if compose.wants_editor() {
                edit_in_editor(&mut d)?;
            }
            let s = save_draft(c, &d, None, false)?;
            report_saved(&s, "Saved", json)?;
        }
        DraftCmd::Reply {
            uid,
            mailbox,
            all,
            compose,
        } => {
            let mb = c.resolve_mailbox(mailbox)?;
            let (raw, _) = c.fetch_raw(&mb, *uid, false)?;
            let mut d = draft::reply(&c.account, &raw, *all)?;
            compose.apply(&mut d, true)?;
            if compose.wants_editor() {
                edit_in_editor(&mut d)?;
            }
            let s = save_draft(c, &d, None, false)?;
            report_saved(&s, "Saved reply", json)?;
        }
        DraftCmd::Forward {
            uid,
            mailbox,
            compose,
        } => {
            let mb = c.resolve_mailbox(mailbox)?;
            let (raw, _) = c.fetch_raw(&mb, *uid, false)?;
            let mut d = draft::forward(&c.account, &raw)?;
            compose.apply(&mut d, true)?;
            if compose.wants_editor() {
                edit_in_editor(&mut d)?;
            }
            let s = save_draft(c, &d, None, false)?;
            report_saved(&s, "Saved forward", json)?;
        }
        DraftCmd::Edit {
            id,
            compose,
            remove_attachment,
            force,
        } => {
            let (_, uid, raw) = load_draft(c, id)?;
            let mut d = Draft::from_rfc822(&raw)?;
            compose.apply(&mut d, false)?;
            for name in remove_attachment {
                let before = d.attachments.len();
                d.attachments.retain(|a| &a.filename != name);
                if d.attachments.len() == before {
                    bail!("draft has no attachment named `{name}`");
                }
            }
            if compose.wants_editor() || (!compose.has_content() && remove_attachment.is_empty()) {
                if !std::io::stdin().is_terminal() && !compose.edit {
                    bail!("nothing to change: pass --to/--subject/--body/... or --edit");
                }
                edit_in_editor(&mut d)?;
            }
            if d.html.is_some() && d.original_text.as_deref() != Some(d.body.as_str()) {
                eprintln!("note: this draft had an HTML body; it was saved as plain text.");
            }
            let s = save_draft(c, &d, Some(uid), *force)?;
            report_saved(&s, "Updated", json)?;
        }
        DraftCmd::Delete { id } => {
            let (mb, uid, raw) = load_draft(c, id)?;
            let d = Draft::from_rfc822(&raw)?;
            let mut uids = if raw_has_uuid(&raw) {
                draft_revisions(c, &mb, &d.id)?
            } else {
                vec![]
            };
            uids.push(uid);
            uids.sort_unstable();
            uids.dedup();
            for u in &uids {
                let (r, _) = c.fetch_raw(&mb, *u, false)?;
                let mid = mail_parser::MessageParser::default()
                    .parse_headers(&r)
                    .and_then(|m| m.message_id().map(String::from));
                c.delete_message(&mb, *u, mid.as_deref())?;
            }
            if json {
                return print_json(&serde_json::json!({ "deleted": uids, "draft_id": d.id }));
            }
            println!("Deleted draft {} (uid {})", d.id, uid);
        }
    }
    Ok(())
}

fn raw_has_uuid(raw: &[u8]) -> bool {
    mail_parser::MessageParser::default()
        .parse_headers(raw)
        .is_some_and(|m| m.header_raw(draft::UUID_HEADER).is_some())
}

// ---------------------------------------------------------------- accounts

fn account_cmd(cmd: &AccountCmd, cfg: &mut Config, json: bool) -> Result<()> {
    match cmd {
        AccountCmd::Add {
            name,
            provider,
            email,
            display_name,
            username,
            password_stdin,
            password_command,
            oauth_token_command,
            default,
            no_verify,
        } => {
            if *provider == Provider::Icloud && oauth_token_command.is_some() {
                bail!("iCloud does not support OAuth for IMAP; use an app-specific password");
            }
            let acct = Account {
                provider: *provider,
                email: email.clone(),
                name: display_name.clone(),
                username: username.clone(),
                host: None,
                port: None,
                auth: if oauth_token_command.is_some() {
                    AuthMethod::Oauth2
                } else {
                    AuthMethod::Password
                },
                password_command: password_command.clone(),
                oauth_token_command: oauth_token_command.clone(),
                drafts_mailbox: None,
                trash_mailbox: None,
                insecure_plaintext: false,
            };
            if acct.auth == AuthMethod::Password && acct.password_command.is_none() {
                let pw = if *password_stdin {
                    let mut s = String::new();
                    std::io::stdin().read_line(&mut s)?;
                    s
                } else {
                    let what = match provider {
                        Provider::Gmail => "Gmail app password",
                        Provider::Icloud => "iCloud app-specific password",
                    };
                    rpassword::prompt_password(format!("{what} for {email}: "))?
                };
                if pw.trim().is_empty() {
                    bail!("empty password");
                }
                auth::store_password(&acct, pw.trim())?;
            }
            if !no_verify {
                let mut c = Client::connect(name, &acct)?;
                let drafts = c.drafts_mailbox()?;
                c.logout();
                if !json {
                    println!("Logged in OK; drafts mailbox is `{drafts}`");
                }
            }
            cfg.accounts.insert(name.clone(), acct);
            if *default || cfg.default_account.is_none() {
                cfg.default_account = Some(name.clone());
            }
            cfg.save()?;
            if json {
                print_json(&serde_json::json!({ "added": name }))?;
            } else {
                println!(
                    "Added account `{name}` ({})",
                    config::config_path().display()
                );
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
                println!("{star} {n:15} {:7} {}", a.provider.to_string(), a.email);
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

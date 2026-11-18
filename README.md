# agent-mail

A command-line email client for **Gmail** and **iCloud Mail**, written in Rust.

It reads mail and manages drafts over IMAP. **It cannot send mail.** There is no SMTP
code in it. Drafts are saved to the account's Drafts mailbox, where they show up in
Gmail on the web and phone, and in Apple Mail on Mac and iPhone. You review and send
them from there.

Every command takes `--json`, so scripts and agents can use it as easily as people can.

## Install

```sh
cargo install --path .
```

## Setup

Both providers need an app password. Your normal account password won't work over IMAP.

- **Gmail:** turn on 2-Step Verification, then create a password at
  <https://myaccount.google.com/apppasswords>. Also check that IMAP is on in
  Gmail Settings → Forwarding and POP/IMAP.
- **iCloud:** create an app-specific password at <https://account.apple.com> →
  Sign-In and Security → App-Specific Passwords.

```sh
agent-mail account add personal --provider gmail  --email you@gmail.com  --display-name "You"
agent-mail account add apple    --provider icloud --email you@icloud.com --display-name "You"
agent-mail account default personal
```

`account add` prompts for the password, saves it in the macOS Keychain (service
`agent-mail`), test-logs in, and finds your Drafts mailbox.

The tool looks for a password in this order:

1. The `AGENT_MAIL_<ACCOUNT>_PASSWORD` environment variable.
2. `password_command` in the config, for example `op read op://Private/gmail/app-pw`.
3. The OS keychain.

Gmail Workspace accounts that block app passwords can use XOAUTH2 instead:
`--oauth-token-command "<command that prints an access token>"`.

The config lives in `~/.config/agent-mail/config.toml`. You can point to a different
file with `AGENT_MAIL_CONFIG`. Each account can override `host`, `port`, `username`,
`drafts_mailbox` and `trash_mailbox`.

## Usage

```sh
agent-mail mailboxes                     # folders/labels with their roles (drafts, sent, trash…)
agent-mail list -m INBOX -n 20           # recent messages (UID, date, from, subject; * = unread)
agent-mail search "from:bob has:attachment"   # Gmail search syntax on Gmail; full-text on iCloud
agent-mail search --imap 'UNSEEN FROM "bob"'  # raw IMAP SEARCH
agent-mail read 4211                     # doesn't mark as read unless you pass --mark-read
agent-mail read 4211 --raw               # RFC 822 source

agent-mail draft list
agent-mail draft new --to "Ann <ann@x.com>" --subject "Hi" --body "Hello!" --attach notes.pdf
agent-mail draft new                     # no flags in a terminal → opens $EDITOR
echo "text" | agent-mail draft new --to a@b.com --subject S --body -
agent-mail draft reply 4211 --all --body "Sounds good."   # threaded reply, original quoted below
agent-mail draft forward 4211 --to c@d.com                # keeps the original's attachments
agent-mail draft show <ID>
agent-mail draft edit <ID> --subject "New subject"       # or --edit for $EDITOR
agent-mail draft edit <ID> --remove-attachment old.pdf
agent-mail draft delete <ID>
```

`<ID>` can be a UID from `draft list`, or the draft's **stable id** (a UUID). A draft
gets a new UID every time it is saved, but its stable id never changes, so scripts
should use the stable id.

In the editor, the draft looks like this:

```
From: You <you@gmail.com>
To: Ann <ann@x.com>
Cc:
Bcc:
Subject: Hi

Body goes here.
```

## How draft sync works

IMAP messages can't be changed after they're stored, so "editing" a draft really means
saving a new copy and deleting the old one. The two providers need different handling
for this:

| | Gmail | iCloud |
|---|---|---|
| Drafts mailbox | found by its `\Drafts` role (works with localized names like `[Google Mail]/Entwürfe`), else `[Gmail]/Drafts` | found by its `\Drafts` role, else `Drafts` |
| Saving | `APPEND` with `\Draft \Seen` | `APPEND` with `\Draft \Seen`, plus `X-Uniform-Type-Identifier: com.apple.mail-draft` so Apple Mail can open it as an editable draft |
| Removing an old copy | `UID MOVE` to Trash, then mark it `\Deleted` and expunge it **from Trash**. (In Gmail, deleting and expunging in Drafts only archives the message to All Mail, which leaves junk behind.) | mark `\Deleted`, then `UID EXPUNGE` (or plain `EXPUNGE` if the server lacks UIDPLUS) |

Other rules that apply to both:

- **The new copy is saved before the old one is deleted.** If something fails partway,
  you might briefly have two copies, but you never lose the draft.
- **Stable identity:** each draft carries `X-Universally-Unique-Identifier`, the same
  header Apple Mail uses. When you save, any other copies with the same id are cleaned up.
- **Fresh Message-ID on every save**, so Gmail never mistakes a new copy for a duplicate
  of the old one.
- **Conflict check:** if the copy you're editing was changed or deleted on the server
  since you loaded it (say, you edited it on your phone), the edit stops instead of
  overwriting. `--force` saves it as a new draft instead.
- **Replies** set `In-Reply-To` and `References` and use a `Re:` subject, so Gmail
  conversations and Apple Mail threads group them correctly.
- **Bcc** is kept in the draft, as Gmail and Apple Mail do themselves.
- **Drafts written in other apps:** editing keeps their attachments. An HTML body is
  kept as long as you don't change the text; if you do, the draft is saved as plain text
  and you get a warning.
- **Finding drafts by id:** the tool scans draft headers itself, because Gmail search
  doesn't reliably match custom `X-` headers.

## Development

```sh
cargo test
```

The unit tests cover building and parsing messages, the editor format and reply
threading. The full IMAP flows were checked by hand against a fake server that
mimics Gmail's expunge-only-archives behavior and iCloud's split FETCH responses and
lack of UIDPLUS. For that kind of testing only, an account can set
`insecure_plaintext = true`, which is allowed only for `localhost`.

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

Run this and answer the prompts:

```sh
agent-mail account add
```

It asks for your email address, works out the provider from the domain (or asks), and
then signs you in:

- **Gmail** opens a Google sign-in page in your browser. After you approve access, the
  browser sends you back to a temporary local web server, and the tool stores the
  resulting refresh token in the macOS Keychain. No password is involved.
- **iCloud** has no browser sign-in for mail; Apple only accepts app-specific
  passwords. The tool opens Apple's page for creating one and asks you to paste it.

When the token expires or is revoked, run `agent-mail account login <name>` to sign in again.

Every login is checked against the server **before** anything is saved, so a mistyped
password never replaces a working one.

### Adding accounts in a web form

```sh
agent-mail account add --web
```

This opens a form in your browser with the same inputs as the command line: email,
provider, account name, display name, IMAP username, and the sign-in method (app
password, Google sign-in, password command, or token command). Any flags you pass,
such as `--email`, pre-fill the form. Wrong passwords or other errors show up on the
form so you can fix them. After an account is added you can add another one, or click
**Done** to shut the form down. Add `--no-browser` to print the URL instead of opening
it.

The form is served only to this computer (127.0.0.1) on a random port. Its URL
contains a secret token, and the server rejects requests that come from other websites.

### One-time Google setup (Gmail browser sign-in)

Google only allows browser sign-in through an OAuth client registered to you. Creating
one takes about five minutes and is free:

1. In <https://console.cloud.google.com>, create a project and enable the **Gmail API**.
2. Set up the **OAuth consent screen**: choose External and add your own Gmail address
   as a **test user**.
3. Go to **Credentials → Create credentials → OAuth client ID** and pick application
   type **Desktop app**.
4. Run `agent-mail account add`. It asks for the client ID and secret the first time
   and saves them in the config file, where all your Gmail accounts share them. You can
   also pass `--client-id/--client-secret`, or set `AGENT_MAIL_GOOGLE_CLIENT_ID` and
   `AGENT_MAIL_GOOGLE_CLIENT_SECRET`.

While the app's publishing status is **Testing**, Google expires refresh tokens after
7 days, so you'd need to run `account login` weekly. To avoid that, click **Publish
app** on the consent screen page. Google will show an "unverified app" warning when
you sign in; click through it. You don't need verification for your own use.

### Without a browser

```sh
# Gmail app password instead of OAuth (needs 2-Step Verification)
agent-mail account add personal --email you@gmail.com --auth password
# Scripted: password from stdin or a command
echo "$PW" | agent-mail account add apple --email you@icloud.com --password-stdin
agent-mail account add apple --email you@icloud.com --password-command "op read op://Private/icloud/app-pw"
# Bring your own OAuth token source
agent-mail account add work --email you@company.com --oauth-token-command "my-token-helper"
```

Add `--no-browser` to print URLs instead of opening them.

### Where credentials live

- **macOS Keychain**, service `agent-mail`: app passwords and Google refresh tokens.
  The `AGENT_MAIL_<ACCOUNT>_PASSWORD` environment variable overrides the stored
  password.
- **`~/.config/agent-mail/config.toml`** (mode 0600; change the location with
  `AGENT_MAIL_CONFIG`): account settings and the Google client ID and secret. Google
  says Desktop-app client secrets aren't actually confidential.

`account remove` deletes the account's keychain entries. Each account can also override
`host`, `port`, `username`, `drafts_mailbox` and `trash_mailbox` in the config.

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
lack of UIDPLUS. The browser sign-in was checked the same way, with a fake Google
token endpoint (`AGENT_MAIL_GOOGLE_AUTH_URL` / `AGENT_MAIL_GOOGLE_TOKEN_URL`) and a
`BROWSER` script that approves the consent. The web form was driven with `curl`, using
`AGENT_MAIL_TEST_IMAP_ADDR=127.0.0.1:<port>` to point new accounts at the fake server.
For that kind of testing only, an account can set `insecure_plaintext = true`, which
is allowed only for `localhost`.

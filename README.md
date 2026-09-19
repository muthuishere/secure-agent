# sec — credentials broker for humans and their agents

Agents write `{{NAME}}` placeholders. `sec` fills them, runs the work, and scrubs the values
out of everything that comes back. The model never holds a secret; the audit log says who used
what; `rotate` knows every place a value was put.

```bash
sec init                                                   # age keypair → ~/.config/sec
printf '%s' "$VALUE" | sec set STRIPE_KEY --source https://dashboard.stripe.com/apikeys
sec exec -- curl -H "Authorization: Bearer {{STRIPE_KEY}}" https://api.stripe.com/v1/balance
sec gen --save APP_DB_PW --env infra/vault/dev/.env.dev=DB_PASSWORD
sec place APP_DB_PW --gh muthuishere/app:production --gcp my-project
sec rotate APP_DB_PW --gen --hook hooks/postgres-rotate.sh  # → re-pushed to .env, GitHub, GCP
sec where APP_DB_PW                                        # the compromise-day question
```

## Why

| tool | secrets out of the model | works for argv/config files, not just env | placement ledger → one-verb rotate | no daemon / SaaS |
|---|---|---|---|---|
| Doppler / 1Password `op run` | ✅ | env only | ✗ | SaaS |
| secretctl / agent-secrets | ✅ | env only | ✗ | MCP server / daemon |
| OneCLI / agentsecrets | ✅ | HTTP only (proxy) | rotate in vault only | proxy + dashboard |
| sops + age | ✅ | ✗ | ✗ | ✅ |
| **sec** | ✅ + output redaction | ✅ `exec` / `render` | ✅ | ✅ single binary |

## Install

```bash
task install        # builds, copies to ~/.local/bin, links the agent skill, adds harness deny rules
sec init
```

`sec skill install` symlinks `skills/sec` into `~/.claude/skills/` and `~/.agents/skills/` and merges
`Read(~/.config/sec/**)`, `Read(**/.env*)`, `Bash(sec get:*)`, `Bash(sec export:*)` into
`~/.claude/settings.json` `permissions.deny` — so the harness, not the model, refuses.

## Model

- **Vault**: `~/.config/sec/vault/NAME.age` (age X25519, `filippo.io/age`) + `NAME.json` metadata.
  Ciphertext + names only → commit it to a private repo or `rclone sync` it. Sync is not sec's job.
- **Identity**: pluggable, the same three backends `Bun.secrets` gives JS, plus a file:
  `SEC_IDENTITY` env (CI/containers) > OS keyring (macOS Keychain / Windows Credential Manager /
  Linux Secret Service, via `go-keyring`) > `identity.txt` (0400).

  | situation | default | why |
  |---|---|---|
  | macOS / Windows desktop session | keyring | local API, answers immediately, no prompt |
  | **anything headless** — SSH, container, CI, no `DISPLAY`/DBus | **file** (0400) | every credential store assumes a logged-in desktop; without one it prompts where nobody can answer, and a prompt is a hung agent |
  | Linux desktop | file, opt in with `--backend keyring` | gnome-keyring/KWallet works, but it's DBus, and the same config in cron or CI would block |

  Headless is detected from `SSH_CONNECTION`/`SSH_TTY`, `/.dockerenv` + cgroups, CI env vars,
  and (on unix) a missing `DISPLAY`/`WAYLAND_DISPLAY`/`DBUS_SESSION_BUS_ADDRESS`. Override with
  `SEC_HEADLESS=0|1`. Every keyring call — probe, read, and the write's read-back — is bounded by
  a 3s timeout, so a locked keychain can never wedge the process.

  **Resolution is automatic and never needs a flag.** Reads try `SEC_IDENTITY`, then the keyring
  (if the vault prefers it *and* this session can reach it), then `identity.txt`, and use the first
  that answers — so one home directory works from the desktop that created it and from a cron job
  or SSH session that can't reach the credential store. Falling back prints one line on stderr so
  it's never a silent downgrade. `sec identity adopt key.txt` gives a machine its own file copy
  without changing where the vault prefers to keep the key.

  Two things are refused rather than guessed: `sec init` on a directory that already holds
  encrypted secrets but no key (generating a fresh one would orphan them forever), and adopting a
  key whose public key doesn't match the vault's.
  `sec identity` shows which; `sec identity move --to keyring|file` switches (verifies the new
  location reads back *before* removing the old copy); `sec identity export --out f --confirm`
  makes a backup for a password manager. Teammates: `sec recipients --add age1…`.
  What the keyring buys: no plaintext key on disk, so a disk image, a Time Machine backup or an
  `rclone` of the wrong directory doesn't carry it. It does **not** stop a process running as you
  from asking the keyring — that exposure is identical to a 0600 file.
- **Owner vs agent**: a TTY on stdin or `SEC_OWNER=1` is the owner. `get --print`, `export`,
  `--allow-output-only` need it. Agent harnesses run with a piped stdin, so they never have it.
- **Redaction**: `exec`/`run` scrub each value plus its base64 (with/without trailing newline), hex,
  url-encoded and JSON-escaped forms from stdout/stderr, line-buffered.
- **Placement ledger**: `env write`, `render`, `import`, `gen --env`, `place` record where a value went.
  `rotate` re-applies to all of them and prints what must be done by hand.
- **Audit**: `~/.config/sec/audit.ndjson` — action, names, agent, cwd, template. Never values.

## Threat model, honestly

Defends against sloppiness and logs: secrets in transcripts, guides, commits, test output, chat.
Does **not** defend against a hostile agent with network access (it could `curl` a value to a webhook
through `exec`); neither does any tool in this category. The refusal of output-only commands and the
audit line for every use make the silly attempt visible, not impossible.

## Layout

`cmd/sec` · `internal/{store,tmpl,redact,execx,gen,envfile,cert,place,owner,cli}` · `skills/sec/SKILL.md` ·
`hooks/` (rotation hooks: postgres, aws-iam) · `scripts/smoke.sh`.

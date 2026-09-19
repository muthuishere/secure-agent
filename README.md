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

  | platform | default | why |
  |---|---|---|
  | macOS, Windows | keyring | local API, answers immediately, no prompt |
  | Linux, BSD, containers, CI | **file** | a server has no Secret Service; a desktop one is DBus and can block on an unlock prompt that never comes in cron or an agent session |

  Linux desktop users who want gnome-keyring/KWallet opt in: `sec init --backend keyring`
  (or `sec identity move --to keyring`), which warns about the DBus caveat.
  `sec identity` shows which; `sec identity move --to keyring|file` switches (verifies the new
  location reads back *before* removing the old copy); `sec identity export --out f --confirm`
  makes a backup for a password manager. Teammates: `sec recipients --add age1…`.
  What the keyring buys: no plaintext key on disk, so a disk image, a Time Machine backup or an
  `rclone` of the wrong directory doesn't carry it. It does **not** stop a process running as you
  from asking the keyring — that exposure is identical to a 0600 file.
- **Owner vs agent**: a TTY on stdin or `SEC_OWNER=1` is the owner. `get --print`, `export`,
  `--allow-output-only` need it. Agent harnesses run with a piped stdin, so they never have it.
- **Redaction**: `exec`/`run` scrub each value plus its base64 (with/without trailing newline), hex,
  url-encoded and JSON-escaped forms from stdout/stderr. Matching is newline-tolerant — the stream is
  also searched with `\r`/`\n` removed, because ordinary tools wrap long output (`xxd -p` at 60
  columns, GNU `base64` at 76, `fold`) and a value in three pieces is still the value. The tail is
  held back briefly so a match cannot slip through the seam.
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

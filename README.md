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
- **Identity**: `~/.config/sec/identity.txt` (0600). Back it up. Teammates: `sec recipients --add age1…`.
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

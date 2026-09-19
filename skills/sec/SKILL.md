---
name: sec
description: >
  Use, create, place, or rotate ANY credential — API key, token, password, .env value,
  service-account JSON, TLS cert — through the `sec` CLI, never by hand. You write
  {{NAME}} placeholders; sec fills them, runs the work, and scrubs the values out of
  the output. Trigger on: needs a key / token / secret / credential / password, run
  this with credentials, set up the .env, generate a password, create a certificate,
  which places use this key, a key leaked / was exposed / rotate it, import the
  .env into the vault, write a guide that uses credentials.
---

# sec — the credentials broker

You never hold a secret value. You hold **names**. `sec` holds values, in an
age-encrypted vault at `~/.config/sec/` (owner's machine; `SEC_HOME` overrides).

## The one rule

Anything that needs a credential is written with `{{NAME}}` and handed to `sec`:

```bash
sec ls --json                                             # discover names (never values)
sec exec -- curl -sS https://api.x.com/v1 -H "Authorization: Bearer {{STRIPE_KEY}}"
sec exec -- psql "{{STAGING_DB_URL}}" -c "select 1"
sec exec -f ./scripts/integration.sh -- '{{A_KEY}}'       # script with placeholders inside
sec run STRIPE_KEY,DB_URL -- go test ./...                # env injection, for tools that want env
sec render deploy/gcp-sa.json.tpl --out /tmp/sa.json      # config file with secrets → 0600
sec seal notes.md                                         # the reverse: real values → {{NAME}}
```

Output comes back with every value (and its base64/hex/url-encoded forms)
replaced by `[REDACTED:NAME]`. That is by design — do not try to work around it.

## Verbs you use

| need | command |
|---|---|
| what credentials exist | `sec ls --json` (`--tag test` to filter) |
| run something with a credential | `sec exec -- <cmd with {{NAME}}>` |
| run a script that needs several | `sec exec -f script.sh -- args` |
| tool wants env vars | `sec run NAME[=ENVVAR],NAME2 -- cmd` |
| a config file needs secrets | `sec render template --out file` |
| a doc/config ALREADY has real values in it | `sec seal file [--out file]` — values → `{{NAME}}`, captured as placements |
| is this file safe to commit / send | `sec seal file --check` — names what it found, writes nothing, exits 1 |
| a new password / token | `sec gen --save NAME [--env production=VAR] [--len 32] [--hex]` |
| put an existing secret in an env | `sec env write production NAME[=VAR]` |
| which environments exist here | `sec env list` — environment → file → key count |
| what keys are in one | `sec env ls production` (or a path) |
| record where a secret lives | `sec place NAME --file .env[=VAR] \| --gh owner/repo[:env] \| --gcp project` |
| where has it been placed / used | `sec where NAME` |
| leak suspected | `sec where NAME` + `sec audit --name NAME --since 7d`, then rotate |
| replace a value everywhere | `sec rotate NAME --gen [--hook script]` or ask owner to paste one |
| local TLS | `sec cert ca` once, then `sec cert issue --cn host --san a,b --out dir` |
| user pasted a value in chat | `sec set NAME <<'EOF' … EOF` then recommend `sec rotate NAME` |
| .env already exists in a repo | `sec import production --tag <project>` (file becomes a placement) |

## The two directions

`render` and `seal` are the same door, walked opposite ways:

- **`render`** takes a template of names and writes a file holding real values. That file is
  live credential material: 0600, vault-only, never committed, never forwarded.
- **`seal`** takes that file back to `{{NAME}}` placeholders. Render → seal is byte-exact, so a
  filled copy is disposable — regenerate it per recipient instead of keeping one around.

Anything that leaves the machine goes **sealed**. Before you commit, attach, paste or hand over a
file you did not author, run `sec seal <file> --check`: it names any live secret in it without you
— or the owner — having to read the file to find out.

## Environments — never assume `.env`

A repo usually has several: `.env`, `.env.local`, `infra/vault/production/.env.production`.
Anywhere a file is wanted you may give an **environment name** instead of a path, and `sec`
resolves it against the files actually present (`sec env list` shows them). Writing a production
credential into whatever `.env` happened to be nearby is the failure this prevents, so:

- **Ask which environment** when the task says "the API key" without saying which. Don't default.
- An environment that doesn't exist is an **error listing the ones that do** — don't retry with `.env`.
- Template files (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`) are **refused** as
  write targets; they're committed, and a real value in one is a public leak.
- `sec where NAME` shows the environment of every file placement, so "is this key in prod too?"
  is one command.

## Hard rules

1. **Never read** a `.env*`, `~/.config/sec/**`, or a file `sec render` wrote. Use `sec env ls` for key names. The harness denies these reads anyway.
2. **Never write** `export X=value`, a literal password, or a token into any file, guide, commit, or message. Guides say `sec run NAME -- …` / `sec exec -- … {{NAME}}`.
3. **Never generate** a password yourself. `sec gen` does it and you never see it.
4. `--print`, `--confirm`, `--allow-output-only`, `sec get`, `sec export` are **owner flags**. You do not have them (they need a TTY or `SEC_OWNER=1`). If a task needs one, stop and tell the owner exactly what to run.
5. A placeholder in `echo`/`cat`/`env`/`printf`/`base64` is refused — that's exfiltration, not use.
6. **Missing a value?** Don't go get it (no browser, no clipboard, no dashboard). Tell the owner:
   `sec set NAME --source <url> --place` — they paste once on a masked prompt; you continue.
7. **Never `gh secret set` / `gcloud secrets` by hand.** Use `sec place NAME --gh …` so the vault stays authoritative and rotation still works.
8. After you stored a value that transited chat: say so, and recommend `sec rotate NAME`.

## Rotation: what "replace it" means

`sec rotate NAME` stores a new value (retiring the old one for `--undo`), re-pushes it
to **every recorded placement** (.env files, rendered files, GitHub, GCP), and prints
the steps that must be done by a human (revoke at the source URL, restart readers).
Most SaaS keys cannot be rotated by API — the owner mints one in a dashboard and pastes
it into `sec rotate NAME`; for passwords you own (DB users) use `--gen --hook hooks/postgres-rotate.sh`.
When the old value is revoked upstream: `sec rotate NAME --purge`.

## Reporting back

Say what ran, what passed, and which names were used — e.g. "ran integration tests with
`STAGING_DB_URL`, `STAGING_API_KEY`; 14/14 pass; `STAGING_DB_URL` rotated to v4 and
re-placed in 2 locations; `STAGING_API_KEY` needs the owner to mint a new one at <source>".
Never quote a value, even a redacted-looking fragment.

## Identity (where the key lives)

Where the key lives is resolved automatically (`SEC_IDENTITY` → keyring → file); you never pass a
backend flag. `sec identity` reports which one answered and the public key — never the key.
If it errors with "no usable identity", the key has not reached this machine: report the commands
it prints and stop. Do not retry, do not try to unlock a keychain, and never run
`sec init` to "fix" it — on a synced vault that would orphan every secret. Moving, exporting or importing the identity is **owner-only**; if a machine has no
identity, say so and give the owner the command, don't improvise.

## Sync is not sec's job

`~/.config/sec/vault/` is ciphertext + names: the owner commits it to a private git repo
or `rclone sync`s it. Team fanout to GitHub/GCP/AWS is `sec place` or `vsync sync`.

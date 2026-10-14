---
name: sec
description: >
  Use, create, place, or rotate ANY credential — API key, token, password, .env value,
  service-account JSON, TLS cert — through the `sec` CLI, never by hand. You write
  {{NAME}} placeholders; sec fills them, runs the work, and scrubs the values out of
  the output. Trigger on: needs a key / token / secret / credential / password, run
  this with credentials, set up the .env, generate a password, create a certificate,
  which places use this key, a key leaked / was exposed / rotate it, import the
  .env into the vault, write a guide that uses credentials, put certs / a key folder /
  a .env on a server or in a container or volume, which keys are missing, is everything
  in sync, what happened to this secret.
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
| run an agent with the keyboard filtered | `sec agent claude -- …` — owner's tty, secrets become `{{NAME}}` before I see them |
| a cert / key file / whole folder | `sec set NAME --from ./certs` (files + folders, modes kept; symlinks skipped) |
| put secrets where a program reads them | `sec push NAMES WHERE` — see "Putting secrets where programs read them" |
| which keys does this project need / lack | `sec keys` (reads `.env.example`, `*.tmpl`) or `sec keys FILE…` — exits 1 if any missing |
| what happened to a secret | `sec logs [NAME] [--since 7d] [--json]` — every set, push, rotate, run, and failures (✗) |
| is everything in sync / healthy | `sec ok --dry` — report; `sec ok` re-pushes stale copies only, never guesses |
| saved destinations | `sec target ls` |

## How you were started — `sec agent`

If your process environment carries `SEC_AGENT_WRAPPED=<agent>`, the owner launched you as
`sec agent <agent> …`. That matters to you: **the keyboard went through `sec` first.** A secret
the owner pasted or typed was stored in the vault and replaced with `{{NAME}}` before this line
reached you. So a value you have never seen may already have a name —

```bash
sec ls --json          # a name may exist for a value you were never shown
```

Do not ask the owner to paste a credential into chat to "help me". Ask for a **name**; if the
value is not in the vault yet, `sec seal` on whatever they drop it into, or `sec set NAME`, puts
it there without it passing through the model. Everything after the agent name reaches the agent
untouched (`--dangerously-skip-permissions` and friends still work), and the agent's exit code is
the exit code of `sec agent`.

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

- **Always re-scan, never assume.** Any question about the environment starts with
  `sec env list` — it re-walks the tree on every call. Don't reuse a path from earlier in the
  conversation, from a README, or from another repo: files get added, renamed and moved, and a
  stale path is how a value lands in the wrong environment. Pass the environment *name* and let
  `sec` find the file; if you do pass a path that has gone, `sec` searches for it rather than
  failing, and says so.
- **Ask which environment** when the task says "the API key" without saying which. Don't default.
- An environment that doesn't exist is an **error listing the ones that do** — don't retry with `.env`.
- Template files (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`) are **refused** as
  write targets; they're committed, and a real value in one is a public leak.
- `sec where NAME` shows the environment of every file placement, so "is this key in prod too?"
  is one command.

## Putting secrets where programs read them — `sec push`

Programs never call sec. `push` writes the value where the program already looks, and
**remembers it**, so `sec rotate` / `sec set NAME --place` / `sec ok` keep that copy current.

```bash
sec push DB_PW,API_KEY ./app/.env          # KEY=value lines; other lines untouched
sec push TLS /srv/myapp/certs              # a stored file/folder, written whole (e.g. a docker volume)
sec push TLS ssh://hetzner/etc/myapp/certs # file/folder on a server — needs only sh + tar there
sec push DB_PW ssh://hetzner               # into that server's own sec vault (owner's other sec)
sec push TLS docker://myapp/run/certs      # also podman://, k8s://pod/path
sec push DB_PW prod                        # a saved target (owner: sec target add prod ssh://…)
sec run DB_PW npm start                    # `--` after the names is optional
```

- **Sending to another machine** (`ssh://`, `docker://`, `k8s://`, `export --for`) is **owner-only**:
  you cannot pick a new destination. Re-pushes to destinations the owner already set up happen
  on rotate / `sec ok` whoever runs them — that is the point.
- A path takes **one** file/folder secret; several values go into a `.env` path.
- A `.env` on a *remote* machine can't be edited line by line — push the whole file.
- Another sec with no ssh: owner runs `sec export --only A,B --for <their sec id> --out x.sec`;
  the other machine runs `sec import x.sec`. One-off copy: re-export after a rotate.
- Never `scp`, `docker cp`, `kubectl cp` or `cat > file` a secret by hand — use `push` so the vault
  stays the source of truth and rotation reaches the copy.

## Is everything okay — `sec ok`

Run `sec ok --dry` when asked "is it set up / in sync / healthy". It reports keys the project
needs but the vault lacks, copies holding an old version, files that vanished, and replaced
versions not yet revoked — each with the command to run. `sec ok` (no `--dry`) only re-pushes a
copy that exists and is provably on an older version; it never recreates deleted files, never
touches relative paths, and never pushes where no version is on record. Exit 1 = something needs
the owner: relay the listed commands, don't improvise.

## Hard rules

1. **Never read** a `.env*`, `~/.config/sec/**`, or a file `sec render` wrote. Use `sec env ls` for key names. The harness denies these reads anyway.
2. **Never write** `export X=value`, a literal password, or a token into any file, guide, commit, or message. Guides say `sec run NAME -- …` / `sec exec -- … {{NAME}}`.
3. **Never generate** a password yourself. `sec gen` does it and you never see it.
4. `--print`, `--confirm`, `--allow-output-only`, `sec get`, `sec export`, and `sec push` to another machine are **owner flags**. You do not have them (they need a TTY or `SEC_OWNER=1`). If a task needs one, stop and tell the owner exactly what to run.
5. A placeholder in `echo`/`cat`/`env`/`printf`/`base64` is refused — that's exfiltration, not use.
6. **Missing a value?** Don't go get it (no browser, no clipboard, no dashboard). Tell the owner:
   `sec set NAME --source <url> --place` — they paste once on a masked prompt (`*` per key; a paste
   shows only its last 3 characters so they can check it); you continue.
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
Moving secrets to a machine is `sec push` (ssh) or `sec export --for` / `sec import` (no ssh).

**sec is flat — no app / env / key hierarchy.** Repo- and environment-scoped secrets
(`myapp/prod` vs `myapp/dev`, shared with a team through a bucket) belong in **vsync**. Don't
invent prefixes like `MYAPP_PROD_DB_PW` to fake namespaces in sec; point the owner at vsync.

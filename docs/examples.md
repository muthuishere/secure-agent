# sec — examples

Programs never talk to sec. sec puts secrets where a program already looks —
an env var, a `.env`, a config file, a cert folder, a mounted volume, a server,
a container — and keeps every copy up to date when a value changes.

```
IN                                  OUT (sec remembers each one)
sec set NAME          (prompt)      sec run   NAMES cmd…        env vars, one process
sec set NAME --from FILE|DIR        sec push  NAMES ./app/.env  KEY=value lines
sec import .env                     sec push  NAME  ./certs     a file / folder, whole
sec import x.sec  (sealed export)   sec push  NAME  ssh://host/etc/app/certs
                                    sec push  NAME  docker://ctr/run/secrets
                                    sec render config.tmpl config.yaml
                                    sec push  NAMES ssh://host  another sec, live + kept in sync
                                    sec export --for KEY        another sec, as a sealed file

change it once:  sec set NAME --place   or   sec rotate NAME   → every OUT above is rewritten
```

## 1. A Node / Python / Go app reading env vars

```bash
sec set DB_PW                      # masked prompt; a paste shows ****…xyz
sec run DB_PW,API_KEY npm start    # process.env.DB_PW — nothing written to disk
```

## 2. An app that reads a `.env`

```bash
sec import .env.production         # every KEY=value into the vault
sec push DB_PW,API_KEY ./app/.env  # writes/updates just those lines
sec rotate DB_PW --gen             # new value lands in ./app/.env automatically
```

## 3. Docker with a mounted volume

```bash
sec set TLS --from ./certs         # a whole folder: ca.pem, tls.crt, tls.key …
sec push TLS /srv/myapp/certs
sec push DB_PW,API_KEY /srv/myapp/env/.env

docker run -v /srv/myapp/certs:/certs:ro \
           --env-file /srv/myapp/env/.env myapp
```

The container sees ordinary files. Rotating rewrites them in place (atomic
swap); restart the container if it only reads them at start.

## 4. A server over ssh (no sec needed there)

```bash
sec target add prod ssh://deploy@hetzner/etc/myapp/certs
sec push TLS prod                  # folder written atomically, modes kept
sec push GCP_SA ssh://hetzner/etc/myapp/sa.json --mode 0640
```

## 5. Another sec instance

Two ways, nothing else:

```bash
# a) ssh — live, and kept in sync on every rotate
sec target add hz ssh://deploy@hetzner
sec push DB_PW,TLS hz                    # lands in hetzner's own sec vault
# on hetzner:  sec run DB_PW ./myapp

# b) no ssh — export a sealed file, import it there
# on the other machine:  sec id          → age1…
sec export --only DB_PW,TLS --for age1... --out to-hz.sec
# copy to-hz.sec any way you like; only that vault can open it
# on the other machine:  sec import to-hz.sec
```

Export is a one-off copy: re-export after a rotate.

## 6. Inside a running container / pod

```bash
sec push TLS docker://myapp/run/certs
sec push TLS k8s://api-7f9c/etc/certs
sec push DB_PW -- any command that runs on the other end   # escape hatch
```

## 7. A config file that isn't a .env

```bash
# config.tmpl (committed):   password: {{DB_PW}}
sec render config.tmpl config.yaml   # 0600, re-rendered on rotate
```

## 8. Is everything there? What happened?

```bash
sec ok                   # check everything, re-push stale copies, list what needs you
sec ok --dry             # same, change nothing
sec keys                 # which keys .env.example / templates need, ✓ / ✗ missing
sec where DB_PW          # every place DB_PW was put
sec logs                 # every set, push, rotate, run — and failures (✗)
sec logs DB_PW --since 7d
```

## For agents

Agents never see values. They write `{{NAME}}` and let sec fill it:

```bash
sec exec -- curl -H "Authorization: Bearer {{API_KEY}}" https://api.example.com
sec run DB_PW psql -h db -U app
```

Output is scrubbed. Sending to a new machine (`push` to ssh/docker/k8s,
`export`) is owner-only; re-pushes to places the owner already set up happen
on rotate whoever runs it.

**Repo / environment–scoped secrets** (myapp/prod vs myapp/dev, shared with a
team through a bucket) belong in vsync; sec stays a flat personal vault.

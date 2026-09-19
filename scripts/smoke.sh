#!/bin/sh
# Exercises every verb against a throwaway SEC_HOME. Fails on any leak.
set -eu
: "${SEC_HOME:?}"
# The agent path is what this script checks, so never inherit owner rights
# from whoever invoked it (a `SEC_OWNER=1 task ci` would silently pass).
unset SEC_OWNER
S="$(cd "$(dirname "$0")/.." && pwd)/bin/sec"
W=$(mktemp -d); cd "$W"
$S init --backend file >/dev/null
$S identity | grep -q "backend    : file"
printf 'hunter2-super-secret' | $S set STRIPE_KEY --tag test --source https://example.com/keys >/dev/null
out=$($S exec -- sh -c 'echo "{{STRIPE_KEY}}"; echo "{{STRIPE_KEY}}" | base64')
case "$out" in *hunter2*|*aHVudGVy*) echo "LEAK: $out"; exit 1;; esac
$S exec -- echo '{{STRIPE_KEY}}' 2>/dev/null && { echo "echo must be refused"; exit 1; }
$S get STRIPE_KEY --print </dev/null 2>/dev/null && { echo "get must be owner-only"; exit 1; }
$S gen --save DB_PW --env .env=DB_PASSWORD >/dev/null
printf '{"pw":"{{DB_PW}}"}' > c.tpl; $S render c.tpl --out c.json >/dev/null
$S rotate DB_PW --gen >/dev/null
$S rotate DB_PW --undo >/dev/null
$S rotate DB_PW --purge >/dev/null
$S where DB_PW >/dev/null
$S cert ca >/dev/null && $S cert issue --cn app.local --san localhost --out certs >/dev/null
$S ls --json | grep -q '"name":"DB_PW"'
$S audit --since 1h | grep -q rotate
$S identity export --out id.bak --confirm >/dev/null 2>&1 && { echo "identity export must be owner-only"; exit 1; }
SEC_OWNER=1 $S identity export --out id.bak --confirm >/dev/null
grep -q AGE-SECRET-KEY id.bak
echo "smoke OK"

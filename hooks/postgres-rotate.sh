#!/bin/sh
# sec rotate hook: apply the new password to a Postgres role.
# Runs with SEC_NAME, SEC_NEW_VALUE, SEC_OLD_VALUE in the environment.
# Needs: PGURL_ADMIN (admin connection string) and PGROLE (role to change) in env,
# e.g.  sec run PG_ADMIN_URL=PGURL_ADMIN -- env PGROLE=app sec rotate APP_DB_PW --gen --hook hooks/postgres-rotate.sh
set -eu
: "${PGURL_ADMIN:?set PGURL_ADMIN}" "${PGROLE:?set PGROLE}"
esc=$(printf '%s' "$SEC_NEW_VALUE" | sed "s/'/''/g")
psql "$PGURL_ADMIN" -v ON_ERROR_STOP=1 -q -c "ALTER ROLE \"$PGROLE\" WITH PASSWORD '$esc';"
echo "postgres: password for role $PGROLE updated"

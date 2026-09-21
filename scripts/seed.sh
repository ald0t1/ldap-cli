#!/usr/bin/env bash
#
# Fill the compose dev directory with bulk test data.
#
#   ./scripts/seed.sh              # 100 users, 15 groups
#   ./scripts/seed.sh 500 40       # 500 users, 40 groups
#
# Two steps, one LDAP write: generate the whole batch as a single LDIF, then
# load it with one ldapadd. Nothing is provisioned account-by-account.
#
# uid/gid numbering continues from whatever is already in the directory, so
# running this repeatedly stacks more data instead of colliding. `podman
# compose down -v` wipes everything back to the bootstrap tree.

set -euo pipefail

USERS="${1:-100}"
GROUPS="${2:-15}"
SEED="${3:-1}"

cd "$(dirname "$0")/.."

ADMIN_DN="cn=admin,dc=example,dc=org"
ADMIN_PW="adminpassword"
LDIF="seed.ldif"

# Read the highest uid/gid in use so a re-run continues past it rather than
# tripping over entries from a previous run.
highest() {
  local base="$1" attr="$2" class="$3" fallback="$4"
  local found
  found=$(podman compose exec -T ldap ldapsearch -x -LLL -o ldif-wrap=no \
            -H ldap://localhost:1389 -D "$ADMIN_DN" -w "$ADMIN_PW" \
            -b "$base" "(objectClass=$class)" "$attr" 2>/dev/null \
          | awk -F': ' -v a="$attr" 'tolower($1)==tolower(a) {print $2}' \
          | sort -n | tail -1)
  if [ -n "${found:-}" ]; then echo $((found + 1)); else echo "$fallback"; fi
}

echo "==> checking the directory for ids already in use"
UID_START=$(highest "ou=people,dc=example,dc=org" uidNumber posixAccount 10000)
GID_START=$(highest "ou=groups,dc=example,dc=org" gidNumber posixGroup 20000)
echo "    starting at uid $UID_START, gid $GID_START"

echo "==> generating $USERS accounts and $GROUPS groups into $LDIF"
podman compose run --rm -T --entrypoint "go run ./cmd/seed" go \
  --config /src/examples/config.yaml --profile dev \
  --users "$USERS" --groups "$GROUPS" \
  --uid-start "$UID_START" --gid-start "$GID_START" \
  --seed "$SEED" --out "/src/$LDIF"

echo "==> loading $LDIF in a single ldapadd"
# -c keeps going past an entry that already exists, so a partial re-run tops
# the directory up instead of aborting on the first duplicate name.
podman compose exec -T ldap ldapadd -x -c \
  -H ldap://localhost:1389 -D "$ADMIN_DN" -w "$ADMIN_PW" < "$LDIF" \
  | tail -5 || true

echo "==> done"
podman compose run --rm -T cli group list | tail -5
echo "    (run 'podman compose run --rm cli' for the interactive menu)"

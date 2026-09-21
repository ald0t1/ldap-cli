# ldap-cli

Provisions users and groups on OpenLDAP servers. Point it at a **profile** (one
per server, from a config file) and it derives the username, allocates the
uidNumber, generates the password, and sets that password through the LDAP
password modify operation so the server applies its own hashing policy.

```
$ ldap-cli --profile prod user create \
      --given-name John --surname Doe \
      --primary-group developers --group docker

Bind password for cn=manager,dc=corp,dc=com (profile "prod"):
created    uid=jdoe,ou=people,dc=corp,dc=com
username   jdoe
uidNumber  10042
gidNumber  20001 (developers)
email      jdoe@corp.com
home       /home/jdoe
shell      /bin/bash
groups     docker
password   jCJfKz2%9EZ=xs4d

The password is shown only once — the server stores it hashed.
```

## Two ways to use it

**Interactive menu** — run it with no arguments. Pick a server, authenticate
once, then choose actions from a list. Nothing to memorise, and every group and
account is a type-to-filter picker rather than a name you have to recall:

```
$ podman compose run --rm cli

  Server
  > dev
    prod

  dev — what would you like to do?
  > Create a user
    Show a user
    Add a user to groups
    Remove a user from groups
    Reset a user's password
    List users
    Create a group
    ...
```

**Flags** — the same operations, for scripting and `--json`. Everything below
documents this form.

Both share one implementation: the menu gathers values and calls the same
`internal/directory` code the flags do, so behaviour cannot drift between them.

## What it does

- **Usernames are generated, never duplicated.** `John Doe` becomes `jdoe`; a
  second `Jonathan Doe` becomes `jdoe1`, then `jdoe2`. Accented and ligatured
  names are transliterated (`Jens Straße` → `jstrasse`, `Ærø` → `aero`).
- **uidNumbers and gidNumbers come from a configured range.** The directory is
  always scanned, and an optional counter entry is claimed atomically. See
  [id allocation](#id-allocation).
- **Passwords are generated with `crypto/rand`** and set via RFC 3062, so the
  cleartext never lands in an attribute and the server picks the hash scheme.
  Lookalike characters (`l I O 0 1`) are excluded.
- **Groups are `posixGroup`** with `gidNumber` and `memberUid`. The primary
  group must already exist; it supplies the account's `gidNumber`.
- **Welcome email is sent over SMTP** when `mail.enabled` is set, with an
  optional RFC 2156 `Sensitivity` header. See [Email](#email).

## Everything runs through podman compose

No Go toolchain is needed on the host.

```bash
podman compose run --rm test              # unit tests
podman compose run --rm vet               # go vet
podman compose run --rm build             # binary at ./bin/ldap-cli
podman compose run --rm go mod tidy       # any other toolchain command
podman compose up -d ldap                 # throwaway OpenLDAP for e2e work
podman compose run --rm cli <args>        # the CLI, against the dev server
podman compose up -d ldapadmin            # phpLDAPadmin UI on localhost:8080
podman compose up -d mailhog              # mail sink on localhost:8025
podman compose down -v                    # stop and wipe the dev directory
```

### Browsing the tree

`podman compose up -d ldapadmin` starts [phpLDAPadmin](https://github.com/leenooks/phpLDAPadmin)
on <http://localhost:8080>. It opens straight into the dev directory as a guest,
so you can look around without logging in. To make changes, log in with the full
DN `cn=admin,dc=example,dc=org` and password `adminpassword`.

It is a viewer for the dev server only — nothing in the build or test path
depends on it.

The `cli` service sets `LDAP_CLI_CONFIG=/src/examples/config.yaml` and supplies
the dev server's bind password through `LDAP_CLI_BIND_PASSWORD`, so it runs
non-interactively. Real profiles prompt.

## Configuration

Profiles live in a YAML file, searched in this order when `--config` is absent —
most specific first, so one admin can override a shared file without editing it
for everyone:

1. `$LDAP_CLI_CONFIG`
2. `./ldap-cli.yaml`, `./ldap-cli.yml`
3. `$XDG_CONFIG_HOME/ldap-cli/config.yaml`
4. `~/.config/ldap-cli/config.yaml`
5. `/etc/ldap-cli/config.yaml`

### Where to install it

| Situation | Config | Mode |
|---|---|---|
| One admin's workstation | `~/.config/ldap-cli/config.yaml` | `0600` |
| Shared server, several admins | `/etc/ldap-cli/config.yaml` | `0640`, `root:ldap-admins` |
| Cron, CI, automation | explicit `--config` or `$LDAP_CLI_CONFIG` | `0640` |

```bash
sudo install -m 0755 ./bin/ldap-cli /usr/local/bin/ldap-cli
sudo install -d -m 0750 /etc/ldap-cli
sudo install -m 0640 examples/config.yaml /etc/ldap-cli/config.yaml
sudo vi /etc/ldap-cli/config.yaml
```

The config holds **no LDAP passwords**, so `0640` is enough to keep your bind
DNs and directory layout from being world readable. Three things do need care:

- **`mail.password`**, if you put the SMTP password in the file rather than
  using `mail.password_env`: that makes the config a secret, so `0600` it.
- **A bind password file**, if you use `--bind-password-file`, is the sensitive
  one: `0600`, owned by the account that runs the tool.
- **`backup_dir`** fills with directory dumps containing password hashes. On a
  server point it somewhere deliberate — `backup_dir: /var/backups/ldap-cli`,
  mode `0700` — rather than leaving it under a home directory.

For **automation, always pass `--config` or set `$LDAP_CLI_CONFIG`.** The
working-directory entries are a development convenience, and relying on them
from cron means the config found depends on where the job happens to start.

See [`examples/config.yaml`](examples/config.yaml) for a documented file. The
essentials:

```yaml
default_profile: prod
profiles:
  prod:
    url: ldaps://ldap.corp.com:636
    ca_cert: /etc/ssl/corp-ca.pem
    bind_dn: cn=manager,dc=corp,dc=com
    user_base_dn: ou=people,dc=corp,dc=com
    group_base_dn: ou=groups,dc=corp,dc=com
    default_primary_group: users
    mail_domain: corp.com
    uid: {min: 10000, max: 60000}
    gid: {min: 20000, max: 60000}
```

**No password is ever stored in the config file.** The manager bind password
comes from `$LDAP_CLI_BIND_PASSWORD`, then `--bind-password-file`, then an
interactive no-echo prompt. It is never echoed, logged, or included in `--json`
output.

### Transport security

Set `url` to `ldaps://`, or use `ldap://` with `start_tls: true`. If a profile
would send the bind password over an unencrypted connection, the tool refuses
before connecting:

```
error: profile "strict" would send the bind password over an unencrypted
connection to ldap://ldap:1389; use ldaps://, set start_tls: true, or set
allow_insecure_bind: true to permit it
```

`allow_insecure_bind: true` is the explicit opt-out, intended for throwaway
local servers. `ca_cert` pins a private CA; `insecure_skip_verify` disables
verification entirely and cannot be combined with `ca_cert`.

## Commands

| Command | Purpose |
|---|---|
| `profile list` | Configured servers; prints nothing secret |
| `user create` | Create an account (see flags below) |
| `user show <username>` | Account attributes and group memberships |
| `user add-group <username> <group>...` | Add `memberUid` entries |
| `user remove-group <username> <group>...` | Remove `memberUid` entries |
| `user passwd <username>` | Generate and set a new password |
| `group create <name>` | Create a `posixGroup` |
| `group list` / `group show <name>` | Inspect groups |

Global flags: `--config`, `--profile`, `--bind-password-file`, `--json`.

`user create` prompts for any of `--given-name`, `--surname` and `--email` not
given on the command line, so it is usable interactively and scriptably. Other
flags: `--username` (used verbatim, never silently renamed), `--primary-group`,
`--group` (repeatable), `--password-length`, `--dry-run`, `--no-rollback`.

Membership changes are idempotent — re-running after a partial failure is safe.

## Behaviour worth knowing

**`--dry-run` writes nothing.** It prints the exact LDIF that would be sent. The
uidNumber shown comes from a scan rather than from claiming one, because
claiming is a write.

**A failed password step rolls the account back.** The entry is added without
`userPassword`, then the password is set. If that second step fails — a
`ppolicy` rejection, say — the entry is deleted again, because a passwordless
account in the directory is worse than no account. `--no-rollback` keeps it and
tells you what was left behind.

**Group failures do not roll back the account.** The account is usable, and
`user add-group` finishes the job without recreating it or reissuing the
password. The command still exits non-zero so it is not mistaken for success.

**Every group is resolved before anything is written**, so a mistyped group name
cannot leave a half-provisioned user. A near miss is suggested:

```
error: group "devlopers" does not exist under ou=groups,dc=example,dc=org
(did you mean: developers?); create it first with: ldap-cli group create devlopers
```

### Email

New accounts get a welcome message when `mail.enabled` is true. Off by default,
in which case the tool says so rather than silently skipping.

`mail` is a **top-level** section, not per-profile — one SMTP setup is shared by
every profile in the file:

```yaml
mail:
  enabled: true
  host: smtp.corp.com
  port: 587
  from: Directory Provisioning <noreply@corp.com>
  encryption: starttls          # none | starttls | tls
  username: ldap-cli@corp.com
  password: the-smtp-password
  sensitivity: company-confidential
  include_password: true
  subject: "Your new account: {{.Username}}"

profiles:
  prod: { ... }
  dev:  { ... }
```

- **The SMTP password can live in the file** as `password`. If you use it,
  `chmod 0600` the config and keep it out of version control — it is otherwise
  the only secret in there. Alternatively `password_env: NAME` reads it from
  the environment instead; that wins if both are set, and setting both is
  reported as a mistake rather than silently resolved.
- Setting `username` with `encryption: none` is a hard error, since AUTH would
  put the password on the wire in clear. A `username` with no password source
  at all is caught at config load, not mid-send.
- **`sensitivity`** sets the RFC 2156 header to `Personal`, `Private` or
  `Company-Confidential`; leave it empty to omit. Clients that honour it mark
  the message and may block forwarding — worth setting when the mail carries a
  password.
- **`include_password: false`** sends the account details without the password,
  for when you deliver credentials another way.
- **`subject` and `body` are templates** over `.Username`, `.FullName`,
  `.Email`, `.DN`, `.Profile` and `.Password`. Add arbitrary `headers` and
  `bcc` recipients if you need an audit copy.
- **A mail failure never fails a provisioning run.** The account already
  exists by then; the error is reported as a warning.

Headers are RFC 2047 encoded and the body is base64 UTF-8, so names like
`Þóra Ærø` arrive intact rather than as mojibake. Values are also stripped of
line breaks, so a directory attribute cannot inject extra headers.

#### Trying it locally

`podman compose up -d mailhog` starts [MailHog](https://github.com/mailhog/MailHog),
which captures every message and delivers none. The `dev` profile already points
at it. Read the results at <http://localhost:8025>, or over its API:

```bash
podman compose run --rm cli user create --given-name John --surname Doe --primary-group users
curl -s http://localhost:8025/api/v2/messages | jq '.items[0].Content.Headers.Subject'
```

MailHog is archived upstream (last release 2020). It still does this job fine;
[Mailpit](https://github.com/axllent/mailpit) is the maintained equivalent if
you ever want to swap it out.

### Backups

**Before the first write of any run**, the user and group subtrees are dumped to
an LDIF snapshot. One artifact per run, not per action — an interactive session
that creates twenty accounts produces one snapshot, taken before the first of
them.

```
$ ldap-cli --profile prod user create --given-name John --surname Doe
backup: /home/you/.local/state/ldap-cli/backups/prod/prod-20260921T210736Z.ldif (131 entries)
created  uid=jdoe,ou=people,dc=corp,dc=com
...
```

- **Location**: `--backup-dir`, then `$LDAP_CLI_BACKUP_DIR`, then `backup_dir`
  in the config, then `$XDG_STATE_HOME/ldap-cli/backups`. One subdirectory per
  profile.
- **Rotation**: the newest 10 per profile are kept, set by `backup_keep`.
  Rotation only ever touches files matching its own `<profile>-*.ldif` pattern,
  and one busy profile cannot evict another's history.
- **Reads never snapshot.** Neither does `--dry-run`, which writes nothing.
- **If the snapshot fails, the write does not happen.** `--no-backup` is the
  deliberate override.

The artifact contains `userPassword` hashes, so it is written `0600` in a `0700`
directory — and `./backups/` is gitignored. Entries are ordered parents-first
and non-ASCII values are base64-encoded, so it reloads as-is:

```bash
ldapadd -x -c -D cn=manager,dc=corp,dc=com -W -f <snapshot>.ldif
```

`-c` continues past entries that still exist, so a snapshot can be used to
restore just the parts that were lost.

### ID allocation

The directory is **always** scanned for the highest in-range id, and that result
is a floor. When `uid.next_dn` names a counter entry, it is read too and claimed
with a compare-and-swap (one modify carrying both the delete of the old value
and the add of the new), so concurrent runs cannot take the same number — a
loser retries with the winner's value.

The counter can only move the answer **up**. That combination handles the two
things that actually go wrong: accounts created outside this tool, which the
counter knows nothing about, and a counter that was reset or restored from an
older backup, which would otherwise reissue live ids.

The counter is optional. Without it, allocation is scan-only and a lost race is
caught by the create retrying with the next username candidate.

## End-to-end walkthrough

```bash
podman compose up -d ldap
podman compose run --rm cli group create developers --description 'Dev team'
podman compose run --rm cli user create --given-name John --surname Doe \
    --primary-group developers
podman compose run --rm cli user create --given-name Jonathan --surname Doe \
    --primary-group developers   # jdoe1, uidNumber + 1
```

Then confirm from outside the tool, which is the check that matters:

```bash
# entry shape and uidNumber sequence
podman compose exec ldap ldapsearch -x -LLL -H ldap://localhost:1389 \
  -D cn=admin,dc=example,dc=org -w adminpassword \
  -b ou=people,dc=example,dc=org '(objectClass=posixAccount)' \
  uid uidNumber gidNumber homeDirectory mail

# the server hashed the password; it is not stored in cleartext
podman compose exec ldap ldapsearch -x -LLL -H ldap://localhost:1389 \
  -D cn=admin,dc=example,dc=org -w adminpassword \
  -b ou=people,dc=example,dc=org '(uid=jdoe)' userPassword   # => {SSHA}...

# the generated password actually authenticates
podman compose exec ldap ldapwhoami -x -H ldap://localhost:1389 \
  -D uid=jdoe,ou=people,dc=example,dc=org -w '<printed password>'
```

The dev tree is bootstrapped from
[`examples/ldifs/01-tree.ldif`](examples/ldifs/01-tree.ldif): `ou=people`,
`ou=groups`, `ou=system`, and a `users` group. Everything else is created by the
tool.

## Layout

```
main.go                      thin entrypoint
internal/config/             profile loading and validation
internal/directory/          LDAP: connect, allocate, users, groups
internal/username/           username derivation and collision handling
internal/secret/             password generation
internal/mailer/             notification interface (stubbed)
internal/cli/                cobra command tree
examples/                    sample config and dev-server bootstrap LDIF
```

The `directory.Conn` interface is the seam for testing: allocation, collision
handling and the create/rollback flow are all exercised against an in-memory
fake, so `podman compose run --rm test` needs no server.

## Not done yet

- Group schemas other than `posixGroup`/`memberUid` (no `groupOfNames`).
- `user delete` and `group delete`.
- HTML mail — the welcome message is plain text only.

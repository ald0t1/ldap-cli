// Command seed generates bulk test data as a single LDIF.
//
// It exists to fill a throwaway directory with enough users and groups to
// exercise the CLI at realistic scale — particularly the filterable pickers in
// the interactive shell, which only earn their keep past a few dozen entries.
//
// Everything is computed in memory and written as one LDIF so it can be loaded
// with a single ldapadd, rather than provisioning accounts one at a time.
// Usernames are derived with the same internal/username code the CLI uses, so
// collisions resolve identically (jdoe, jdoe1, jdoe2) and the data looks like
// something the tool itself produced.
//
// No userPassword is written: hashing client-side is exactly what the real
// provisioning path avoids. Seeded accounts cannot log in until a password is
// set properly, with `ldap-cli user passwd <username>`.
package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"

	"github.com/aldo/ldap-cli/internal/config"
	"github.com/aldo/ldap-cli/internal/username"
)

// Name pools. Deliberately small and top-heavy on J-names and common
// surnames, so a run of any size produces plenty of jdoe/jdoe1/jdoe2
// collisions for the username logic to resolve.
var (
	firstNames = []string{
		"John", "Jonathan", "Jane", "James", "Jack", "Julia", "Joseph", "Jessica",
		"Maria", "Marco", "Anna", "Andrea", "Luca", "Laura", "Marta", "Matteo",
		"Sofia", "Simone", "Elena", "Enrico", "Chiara", "Carlo", "Giulia", "Giovanni",
		"Zoë", "José", "Søren", "Ægir", "Þóra", "Đorđe",
	}
	surnames = []string{
		"Doe", "Smith", "Jones", "Brown", "Wilson", "Taylor",
		"Rossi", "Russo", "Ferrari", "Esposito", "Bianchi", "Romano",
		"Núñez", "O'Brien", "van der Berg", "Straße", "Løkke", "Ærø",
		"Müller", "Schmidt",
	}

	groupPrefixes = []string{
		"platform", "data", "security", "network", "storage", "backup",
		"frontend", "backend", "mobile", "qa", "sre", "devops",
		"finance", "legal", "hr", "sales", "support", "research",
	}
	groupSuffixes = []string{"eng", "team", "admins", "ops", "readonly", "oncall", "leads"}
)

func main() {
	var (
		configPath  = flag.String("config", "", "config file (defaults to the usual search path)")
		profileName = flag.String("profile", "", "profile supplying the base DNs and id ranges")
		userCount   = flag.Int("users", 100, "number of accounts to generate")
		groupCount  = flag.Int("groups", 15, "number of groups to generate")
		uidStart    = flag.Int("uid-start", 0, "first uidNumber (default: the profile's uid.min)")
		gidStart    = flag.Int("gid-start", 0, "first gidNumber (default: the profile's gid.min)")
		maxExtra    = flag.Int("max-extra-groups", 3, "most additional groups any one account joins")
		seed        = flag.Uint64("seed", 1, "random seed; the same seed produces the same data")
		outPath     = flag.String("out", "seed.ldif", "LDIF file to write, or - for stdout")
	)
	flag.Parse()

	if err := run(*configPath, *profileName, *outPath, opts{
		users:      *userCount,
		groups:     *groupCount,
		uidStart:   *uidStart,
		gidStart:   *gidStart,
		maxExtra:   *maxExtra,
		randomSeed: *seed,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type opts struct {
	users, groups      int
	uidStart, gidStart int
	maxExtra           int
	randomSeed         uint64
}

type group struct {
	cn          string
	gidNumber   int
	description string
	members     []string
}

type user struct {
	uid        string
	givenName  string
	surname    string
	commonName string
	mail       string
	uidNumber  int
	gidNumber  int
	home       string
	shell      string
}

func run(configPath, profileName, outPath string, o opts) error {
	if o.users < 0 || o.groups < 1 {
		return fmt.Errorf("need at least one group and a non-negative user count")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	profile, err := cfg.Resolve(profileName)
	if err != nil {
		return err
	}

	if o.uidStart == 0 {
		o.uidStart = profile.UID.Min
	}
	if o.gidStart == 0 {
		o.gidStart = profile.GID.Min
	}
	if end := o.uidStart + o.users - 1; end > profile.UID.Max {
		return fmt.Errorf("%d accounts from uid %d would reach %d, past the profile's uid.max of %d",
			o.users, o.uidStart, end, profile.UID.Max)
	}
	if end := o.gidStart + o.groups - 1; end > profile.GID.Max {
		return fmt.Errorf("%d groups from gid %d would reach %d, past the profile's gid.max of %d",
			o.groups, o.gidStart, end, profile.GID.Max)
	}

	// PCG with an explicit seed keeps runs reproducible, which matters when a
	// bug only shows up for one particular generated name.
	r := rand.New(rand.NewPCG(o.randomSeed, 0x9E3779B97F4A7C15))

	groups := makeGroups(r, o)
	users, err := makeUsers(r, profile, groups, o)
	if err != nil {
		return err
	}

	out := os.Stdout
	if outPath != "-" {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create %s: %w", outPath, err)
		}
		defer f.Close()
		out = f
	}

	w := bufio.NewWriter(out)
	writeLDIF(w, profile, groups, users)
	if err := w.Flush(); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	if outPath != "-" {
		fmt.Fprintf(os.Stderr, "wrote %s: %d groups (gid %d-%d), %d accounts (uid %d-%d)\n",
			outPath, len(groups), o.gidStart, o.gidStart+len(groups)-1,
			len(users), o.uidStart, o.uidStart+len(users)-1)
		fmt.Fprintf(os.Stderr, "load it with a single add:\n"+
			"  podman compose exec -T ldap ldapadd -x -c -H ldap://localhost:1389 \\\n"+
			"      -D %s -w <password> < %s\n", profile.BindDN, outPath)
	}
	return nil
}

// makeGroups builds unique group names from the two word pools.
func makeGroups(r *rand.Rand, o opts) []group {
	seen := make(map[string]bool, o.groups)
	groups := make([]group, 0, o.groups)

	for len(groups) < o.groups {
		cn := groupPrefixes[r.IntN(len(groupPrefixes))]
		// Past the first pass, pair words up to keep names unique without
		// resorting to numeric suffixes.
		if len(groups) >= len(groupPrefixes) || seen[cn] {
			cn += "-" + groupSuffixes[r.IntN(len(groupSuffixes))]
		}
		if seen[cn] {
			continue
		}
		seen[cn] = true

		groups = append(groups, group{
			cn:          cn,
			gidNumber:   o.gidStart + len(groups),
			description: "Seeded test group " + cn,
		})
	}
	return groups
}

// makeUsers builds accounts, resolving username collisions the same way the
// CLI does and recording group membership on the groups themselves.
func makeUsers(r *rand.Rand, profile *config.Profile, groups []group, o opts) ([]user, error) {
	taken := make(map[string]bool, o.users)
	users := make([]user, 0, o.users)

	for i := 0; i < o.users; i++ {
		given := firstNames[r.IntN(len(firstNames))]
		surname := surnames[r.IntN(len(surnames))]

		base, err := username.Generate(given, surname, profile.UsernameMaxLength)
		if err != nil {
			// The pools are known-good, so this means the transliteration
			// rejected something and the data would be wrong.
			return nil, fmt.Errorf("generate a username for %q %q: %w", given, surname, err)
		}
		uid, err := username.Unique(base, taken, profile.UsernameMaxLength)
		if err != nil {
			return nil, err
		}
		taken[uid] = true

		primary := r.IntN(len(groups))
		home, err := profile.HomeDir(uid)
		if err != nil {
			return nil, err
		}

		mail := uid + "@example.org"
		if profile.MailDomain != "" {
			mail = uid + "@" + profile.MailDomain
		}

		users = append(users, user{
			uid:        uid,
			givenName:  given,
			surname:    surname,
			commonName: given + " " + surname,
			mail:       mail,
			uidNumber:  o.uidStart + i,
			gidNumber:  groups[primary].gidNumber,
			home:       home,
			shell:      profile.LoginShell,
		})

		// A handful of extra memberships per account, so the group pickers
		// and `user show` have something interesting to display.
		for _, gi := range pickExtra(r, len(groups), primary, o.maxExtra) {
			groups[gi].members = append(groups[gi].members, uid)
		}
	}
	return users, nil
}

// pickExtra chooses distinct group indexes other than the primary one.
func pickExtra(r *rand.Rand, total, primary, max int) []int {
	if max <= 0 || total <= 1 {
		return nil
	}
	n := r.IntN(max + 1)
	chosen := make(map[int]bool, n)
	var out []int
	// Bounded attempts: with few groups and a high max, some draws collide.
	for attempts := 0; len(out) < n && attempts < n*4; attempts++ {
		gi := r.IntN(total)
		if gi == primary || chosen[gi] {
			continue
		}
		chosen[gi] = true
		out = append(out, gi)
	}
	return out
}

func writeLDIF(w *bufio.Writer, profile *config.Profile, groups []group, users []user) {
	fmt.Fprintf(w, "# Generated by cmd/seed — bulk test data.\n")
	fmt.Fprintf(w, "# %d groups, %d accounts. No userPassword: set one with\n", len(groups), len(users))
	fmt.Fprintf(w, "# `ldap-cli user passwd <username>` if an account needs to log in.\n\n")

	for _, g := range groups {
		fmt.Fprintf(w, "dn: cn=%s,%s\n", g.cn, profile.GroupBaseDN)
		fmt.Fprintf(w, "objectClass: top\nobjectClass: posixGroup\n")
		fmt.Fprintf(w, "cn: %s\n", g.cn)
		fmt.Fprintf(w, "gidNumber: %d\n", g.gidNumber)
		writeAttr(w, "description", g.description)
		for _, m := range g.members {
			fmt.Fprintf(w, "memberUid: %s\n", m)
		}
		fmt.Fprintln(w)
	}

	for _, u := range users {
		fmt.Fprintf(w, "dn: %s=%s,%s\n", profile.UserRDNAttr, u.uid, profile.UserBaseDN)
		fmt.Fprintf(w, "objectClass: top\nobjectClass: person\n")
		fmt.Fprintf(w, "objectClass: organizationalPerson\nobjectClass: inetOrgPerson\n")
		fmt.Fprintf(w, "objectClass: posixAccount\nobjectClass: shadowAccount\n")
		for _, extra := range profile.ExtraUserObjectClasses {
			fmt.Fprintf(w, "objectClass: %s\n", extra)
		}
		fmt.Fprintf(w, "%s: %s\n", profile.UserRDNAttr, u.uid)
		writeAttr(w, "cn", u.commonName)
		writeAttr(w, "sn", u.surname)
		writeAttr(w, "givenName", u.givenName)
		writeAttr(w, "mail", u.mail)
		fmt.Fprintf(w, "uidNumber: %d\n", u.uidNumber)
		fmt.Fprintf(w, "gidNumber: %d\n", u.gidNumber)
		writeAttr(w, "homeDirectory", u.home)
		writeAttr(w, "loginShell", u.shell)
		fmt.Fprintln(w)
	}
}

// writeAttr emits one attribute, base64-encoding when LDIF requires it.
//
// The name pools contain non-ASCII surnames on purpose, and RFC 2849 requires
// any value that is not printable ASCII — or that starts with a character
// LDIF treats specially — to be written as base64 after a double colon.
func writeAttr(w *bufio.Writer, name, value string) {
	if value == "" {
		return
	}
	if needsBase64(value) {
		fmt.Fprintf(w, "%s:: %s\n", name, base64Encode(value))
		return
	}
	fmt.Fprintf(w, "%s: %s\n", name, value)
}

func needsBase64(v string) bool {
	if strings.HasPrefix(v, " ") || strings.HasPrefix(v, ":") || strings.HasPrefix(v, "<") {
		return true
	}
	if strings.HasSuffix(v, " ") {
		return true
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return true
		}
	}
	return false
}

func base64Encode(v string) string {
	return base64.StdEncoding.EncodeToString([]byte(v))
}

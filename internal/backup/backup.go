// Package backup captures a restorable snapshot of the subtrees ldap-cli
// writes to, and keeps a bounded history of them per profile.
//
// A snapshot is taken before the first write of a run, so there is always
// something to compare against or restore from if a bulk change goes wrong.
package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/aldo/ldap-cli/internal/ldif"
)

// DefaultKeep is how many snapshots per profile are retained.
const DefaultKeep = 10

// fileExt identifies our artifacts, so rotation can never delete anything
// else that happens to be in the directory.
const fileExt = ".ldif"

// Searcher is the slice of an LDAP connection a snapshot needs.
type Searcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error)
}

// Result describes what a snapshot produced.
type Result struct {
	Path    string
	Entries int
	Bytes   int64
	Removed []string // older snapshots rotated away
}

// Options configures a snapshot.
type Options struct {
	Dir     string   // root backup directory; a per-profile subdirectory is created
	Profile string   // profile name, used for the subdirectory and file prefix
	BaseDNs []string // subtrees to capture, usually the user and group bases
	Keep    int      // snapshots to retain for this profile; DefaultKeep if zero
	Now     time.Time
}

// Take writes a snapshot of the configured subtrees, then rotates old ones.
//
// The artifact contains userPassword hashes, so the file and its directory are
// created private to the current user.
func Take(conn Searcher, opts Options) (*Result, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("no backup directory configured")
	}
	if opts.Keep <= 0 {
		opts.Keep = DefaultKeep
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	dir := filepath.Join(opts.Dir, opts.Profile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create backup directory %s: %w", dir, err)
	}

	entries, err := collect(conn, opts.BaseDNs)
	if err != nil {
		return nil, err
	}

	// UTC and a fixed-width layout keep filenames sortable, which is what
	// rotation relies on.
	name := fmt.Sprintf("%s-%s%s", opts.Profile, opts.Now.UTC().Format("20060102T150405Z"), fileExt)
	path := filepath.Join(dir, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create backup %s: %w", path, err)
	}

	if err := write(f, opts, entries); err != nil {
		f.Close()
		// A truncated backup is worse than none, because it looks like a
		// usable artifact.
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("close backup %s: %w", path, err)
	}

	res := &Result{Path: path, Entries: len(entries)}
	if st, err := os.Stat(path); err == nil {
		res.Bytes = st.Size()
	}

	removed, err := Rotate(opts.Dir, opts.Profile, opts.Keep)
	if err != nil {
		// The snapshot itself succeeded; failing the run over tidy-up would
		// be the wrong trade.
		return res, fmt.Errorf("snapshot written to %s but rotation failed: %w", path, err)
	}
	res.Removed = removed
	return res, nil
}

// collect fetches every entry under each base DN.
func collect(conn Searcher, baseDNs []string) ([]*ldap.Entry, error) {
	var all []*ldap.Entry
	seen := make(map[string]bool)

	for _, base := range baseDNs {
		if base == "" {
			continue
		}

		req := ldap.NewSearchRequest(
			base,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false,
			"(objectClass=*)",
			// "*" is every user attribute, which is what a restore needs.
			[]string{"*"}, nil,
		)

		res, err := conn.SearchWithPaging(req, 500)
		if err != nil {
			// Fall back for servers that refuse the paging control.
			res, err = conn.Search(req)
			if err != nil {
				return nil, fmt.Errorf("read %s for backup: %w", base, err)
			}
		}

		for _, e := range res.Entries {
			// The configured bases can overlap or nest; an entry must not be
			// written twice or the LDIF will not load back.
			if seen[strings.ToLower(e.DN)] {
				continue
			}
			seen[strings.ToLower(e.DN)] = true
			all = append(all, e)
		}
	}

	// Shallower DNs first, so parents are created before their children on
	// restore.
	sort.SliceStable(all, func(i, j int) bool {
		di, dj := strings.Count(all[i].DN, ","), strings.Count(all[j].DN, ",")
		if di != dj {
			return di < dj
		}
		return all[i].DN < all[j].DN
	})
	return all, nil
}

func write(f *os.File, opts Options, entries []*ldap.Entry) error {
	header := fmt.Sprintf(
		"# ldap-cli backup\n"+
			"# profile: %s\n"+
			"# taken:   %s\n"+
			"# bases:   %s\n"+
			"# entries: %d\n"+
			"#\n"+
			"# Contains password hashes. Restore with:\n"+
			"#   ldapadd -x -c -D <bind-dn> -W -f <this file>\n\n",
		opts.Profile,
		opts.Now.UTC().Format(time.RFC3339),
		strings.Join(opts.BaseDNs, ", "),
		len(entries),
	)
	if _, err := f.WriteString(header); err != nil {
		return fmt.Errorf("write backup header: %w", err)
	}

	for _, e := range entries {
		attrs := make([]ldif.Attr, 0, len(e.Attributes))
		for _, a := range e.Attributes {
			attrs = append(attrs, ldif.Attr{Name: a.Name, Values: a.Values})
		}
		if err := ldif.WriteEntry(f, e.DN, attrs); err != nil {
			return fmt.Errorf("write backup entry %s: %w", e.DN, err)
		}
	}
	return nil
}

// Rotate deletes all but the newest keep snapshots for a profile and returns
// the paths it removed.
func Rotate(root, profile string, keep int) ([]string, error) {
	if keep <= 0 {
		keep = DefaultKeep
	}
	dir := filepath.Join(root, profile)

	names, err := snapshotNames(dir, profile)
	if err != nil {
		return nil, err
	}
	if len(names) <= keep {
		return nil, nil
	}

	// Names embed a fixed-width UTC timestamp, so lexical order is
	// chronological; the oldest are at the front.
	var removed []string
	for _, name := range names[:len(names)-keep] {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil {
			return removed, fmt.Errorf("remove old backup %s: %w", path, err)
		}
		removed = append(removed, path)
	}
	return removed, nil
}

// List returns this profile's snapshot paths, oldest first.
func List(root, profile string) ([]string, error) {
	dir := filepath.Join(root, profile)
	names, err := snapshotNames(dir, profile)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(names))
	for _, n := range names {
		paths = append(paths, filepath.Join(dir, n))
	}
	return paths, nil
}

// snapshotNames lists this profile's artifacts in the directory, sorted.
func snapshotNames(dir, profile string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read backup directory %s: %w", dir, err)
	}

	prefix := profile + "-"
	var names []string
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		// Only our own artifacts are rotation candidates.
		if strings.HasPrefix(de.Name(), prefix) && strings.HasSuffix(de.Name(), fileExt) {
			names = append(names, de.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// DefaultDir is where snapshots go when nothing is configured.
func DefaultDir() string {
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "ldap-cli", "backups")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "ldap-cli", "backups")
	}
	return "backups"
}

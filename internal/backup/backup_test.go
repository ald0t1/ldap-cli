package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// fakeSearcher returns a fixed set of entries per base DN.
type fakeSearcher struct {
	byBase map[string][]*ldap.Entry
	calls  int
	fail   error
	noPage bool
}

func (f *fakeSearcher) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.calls++
	if f.fail != nil {
		return nil, f.fail
	}
	return &ldap.SearchResult{Entries: f.byBase[req.BaseDN]}, nil
}

func (f *fakeSearcher) SearchWithPaging(req *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	if f.noPage {
		return nil, ldap.NewError(ldap.LDAPResultUnavailableCriticalExtension, fmt.Errorf("no paging"))
	}
	return f.Search(req)
}

func entry(dn string, attrs map[string][]string) *ldap.Entry {
	e := &ldap.Entry{DN: dn}
	for name, vals := range attrs {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: name, Values: vals})
	}
	return e
}

func newSearcher() *fakeSearcher {
	return &fakeSearcher{byBase: map[string][]*ldap.Entry{
		"ou=people,dc=example,dc=org": {
			entry("ou=people,dc=example,dc=org", map[string][]string{"ou": {"people"}}),
			entry("uid=jdoe,ou=people,dc=example,dc=org", map[string][]string{
				"uid":          {"jdoe"},
				"uidNumber":    {"10000"},
				"userPassword": {"{SSHA}abc123"},
			}),
		},
		"ou=groups,dc=example,dc=org": {
			entry("cn=devs,ou=groups,dc=example,dc=org", map[string][]string{
				"cn":        {"devs"},
				"gidNumber": {"20001"},
			}),
		},
	}}
}

func opts(t *testing.T, dir string) Options {
	t.Helper()
	return Options{
		Dir:     dir,
		Profile: "dev",
		BaseDNs: []string{"ou=people,dc=example,dc=org", "ou=groups,dc=example,dc=org"},
		Now:     time.Date(2026, 9, 21, 10, 30, 0, 0, time.UTC),
	}
}

func TestTakeWritesRestorableLDIF(t *testing.T) {
	dir := t.TempDir()

	res, err := Take(newSearcher(), opts(t, dir))
	if err != nil {
		t.Fatal(err)
	}

	if want := filepath.Join(dir, "dev", "dev-20260921T103000Z.ldif"); res.Path != want {
		t.Errorf("path = %q, want %q", res.Path, want)
	}
	if res.Entries != 3 {
		t.Errorf("entries = %d, want 3", res.Entries)
	}

	raw, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)

	for _, want := range []string{
		"dn: ou=people,dc=example,dc=org",
		"dn: uid=jdoe,ou=people,dc=example,dc=org",
		"dn: cn=devs,ou=groups,dc=example,dc=org",
		"uidNumber: 10000",
		// The hash has to be in the artifact or a restore silently locks
		// everyone out.
		"userPassword: {SSHA}abc123",
		"# profile: dev",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("backup is missing %q:\n%s", want, body)
		}
	}
}

func TestTakeOrdersParentsBeforeChildren(t *testing.T) {
	// ldapadd fails on a child whose parent does not exist yet.
	dir := t.TempDir()
	res, err := Take(newSearcher(), opts(t, dir))
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(res.Path)
	body := string(raw)
	parent := strings.Index(body, "dn: ou=people,dc=example,dc=org")
	child := strings.Index(body, "dn: uid=jdoe,ou=people,dc=example,dc=org")
	if parent < 0 || child < 0 {
		t.Fatalf("expected both entries:\n%s", body)
	}
	if parent > child {
		t.Error("the child entry was written before its parent")
	}
}

func TestTakeIsPrivate(t *testing.T) {
	// The artifact holds password hashes.
	dir := t.TempDir()
	res, err := Take(newSearcher(), opts(t, dir))
	if err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %#o, want 0600", perm)
	}

	dst, err := os.Stat(filepath.Join(dir, "dev"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dst.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode = %#o, want 0700", perm)
	}
}

func TestTakeDeduplicatesOverlappingBases(t *testing.T) {
	// Nested or repeated bases must not produce the same DN twice, or the
	// LDIF will not load back.
	dir := t.TempDir()
	o := opts(t, dir)
	o.BaseDNs = []string{"ou=people,dc=example,dc=org", "ou=people,dc=example,dc=org"}

	res, err := Take(newSearcher(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 2 {
		t.Errorf("entries = %d, want 2 (deduplicated)", res.Entries)
	}

	raw, _ := os.ReadFile(res.Path)
	if n := strings.Count(string(raw), "dn: uid=jdoe,"); n != 1 {
		t.Errorf("jdoe appears %d times, want 1", n)
	}
}

func TestTakeFallsBackWhenPagingUnsupported(t *testing.T) {
	dir := t.TempDir()
	s := newSearcher()
	s.noPage = true

	res, err := Take(s, opts(t, dir))
	if err != nil {
		t.Fatalf("should fall back to an unpaged search: %v", err)
	}
	if res.Entries != 3 {
		t.Errorf("entries = %d, want 3", res.Entries)
	}
}

func TestTakeLeavesNoFileOnSearchFailure(t *testing.T) {
	// A truncated artifact is worse than none: it looks usable.
	dir := t.TempDir()
	s := newSearcher()
	s.fail = fmt.Errorf("server went away")

	if _, err := Take(s, opts(t, dir)); err == nil {
		t.Fatal("expected an error")
	}

	des, err := os.ReadDir(filepath.Join(dir, "dev"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(des) != 0 {
		t.Errorf("a partial backup was left behind: %v", des)
	}
}

func TestTakeRequiresADirectory(t *testing.T) {
	o := opts(t, "")
	if _, err := Take(newSearcher(), o); err == nil {
		t.Fatal("expected an error with no directory configured")
	}
}

// writeSnapshots creates n fake artifacts with increasing timestamps.
func writeSnapshots(t *testing.T, root, profile string, n int) []string {
	t.Helper()
	dir := filepath.Join(root, profile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	var paths []string
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s-%s.ldif", profile, base.Add(time.Duration(i)*time.Hour).Format("20060102T150405Z"))
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("# snapshot\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

func TestRotateKeepsNewest(t *testing.T) {
	root := t.TempDir()
	paths := writeSnapshots(t, root, "dev", 13)

	removed, err := Rotate(root, "dev", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("removed %d, want 3: %v", len(removed), removed)
	}

	// The three oldest go, the ten newest stay.
	for _, gone := range paths[:3] {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("%s should have been removed", filepath.Base(gone))
		}
	}
	for _, kept := range paths[3:] {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s should have been kept", filepath.Base(kept))
		}
	}
}

func TestRotateUnderLimitDoesNothing(t *testing.T) {
	root := t.TempDir()
	writeSnapshots(t, root, "dev", 4)

	removed, err := Rotate(root, "dev", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Errorf("removed %v, want none", removed)
	}
}

func TestRotateIsPerProfile(t *testing.T) {
	// One busy profile must not evict another's history.
	root := t.TempDir()
	writeSnapshots(t, root, "dev", 12)
	prod := writeSnapshots(t, root, "prod", 3)

	if _, err := Rotate(root, "dev", 10); err != nil {
		t.Fatal(err)
	}

	for _, kept := range prod {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("prod snapshot %s was removed by a dev rotation", filepath.Base(kept))
		}
	}
	if got, _ := List(root, "dev"); len(got) != 10 {
		t.Errorf("dev has %d snapshots, want 10", len(got))
	}
}

func TestRotateIgnoresForeignFiles(t *testing.T) {
	// Rotation deletes files; it must only ever touch its own artifacts.
	root := t.TempDir()
	writeSnapshots(t, root, "dev", 12)

	dir := filepath.Join(root, "dev")
	keep := map[string]string{
		"notes.txt":            "not a snapshot",
		"other-profile.ldif":   "different prefix",
		"dev-manual-dump.txt":  "right prefix, wrong extension",
		"dev-20260101T000000Z": "no extension",
	}
	for name, body := range keep {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := Rotate(root, "dev", 10); err != nil {
		t.Fatal(err)
	}
	for name := range keep {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("rotation deleted the unrelated file %s", name)
		}
	}
}

func TestRotateMissingDirectoryIsNotAnError(t *testing.T) {
	removed, err := Rotate(t.TempDir(), "never-used", 10)
	if err != nil {
		t.Fatalf("a profile with no history should not error: %v", err)
	}
	if removed != nil {
		t.Errorf("removed = %v, want nil", removed)
	}
}

func TestTakeRotatesOnEachRun(t *testing.T) {
	root := t.TempDir()
	writeSnapshots(t, root, "dev", 10)

	o := opts(t, root)
	o.Keep = 10
	res, err := Take(newSearcher(), o)
	if err != nil {
		t.Fatal(err)
	}

	// Eleventh snapshot in: the oldest is evicted, leaving ten.
	if len(res.Removed) != 1 {
		t.Errorf("removed %v, want exactly one", res.Removed)
	}
	got, err := List(root, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 10 {
		t.Errorf("history is %d deep, want 10", len(got))
	}
	if got[len(got)-1] != res.Path {
		t.Errorf("newest = %q, want the snapshot just taken %q", got[len(got)-1], res.Path)
	}
}

func TestDefaultKeepApplies(t *testing.T) {
	root := t.TempDir()
	writeSnapshots(t, root, "dev", 15)

	// Keep left at zero must fall back to DefaultKeep rather than deleting
	// everything or nothing.
	removed, err := Rotate(root, "dev", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 15-DefaultKeep {
		t.Errorf("removed %d, want %d", len(removed), 15-DefaultKeep)
	}
}

package directory

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/aldo/ldap-cli/internal/config"
)

const (
	userBase  = "ou=people,dc=example,dc=org"
	groupBase = "ou=groups,dc=example,dc=org"
	counterDN = "cn=uidNext,ou=system,dc=example,dc=org"
)

// testProfile builds a profile with defaults applied the way Load would.
func testProfile(uid config.Range) *config.Profile {
	p := &config.Profile{
		Name:              "test",
		URL:               "ldap://ldap:1389",
		AllowInsecureBind: true,
		BindDN:            "cn=admin,dc=example,dc=org",
		UserBaseDN:        userBase,
		GroupBaseDN:       groupBase,
		UserRDNAttr:       "uid",
		LoginShell:        "/bin/bash",
		HomeTemplate:      "/home/{{.Username}}",
		MailDomain:        "example.org",
		UsernameMaxLength: 32,
		PasswordLength:    16,
		UID:               uid,
		GID:               config.Range{Min: 20000, Max: 60000},
	}
	return p
}

func newClient(f *fakeConn, uid config.Range) *Client {
	return &Client{Conn: f, Profile: testProfile(uid)}
}

func TestAllocateUIDScanOnly(t *testing.T) {
	tests := []struct {
		name     string
		existing []int
		want     int
	}{
		{"empty directory starts at min", nil, 10000},
		{"one past the highest in use", []int{10041}, 10042},
		{"highest wins regardless of order", []int{10005, 10041, 10002}, 10042},
		{"gaps are not reused", []int{10000, 10001, 10050}, 10051},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			for i, uidNum := range tc.existing {
				f.putUser(fmt.Sprintf("uid=u%d,%s", i, userBase), fmt.Sprintf("u%d", i), uidNum)
			}

			got, err := newClient(f, config.Range{Min: 10000, Max: 60000}).AllocateUID()
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("AllocateUID = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestAllocateUIDIgnoresOutOfRangeAccounts(t *testing.T) {
	// System accounts below the range must not drag the floor down, and ids
	// above it must not push us past the ceiling.
	f := newFake()
	f.putUser("uid=root,"+userBase, "root", 0)
	f.putUser("uid=daemon,"+userBase, "daemon", 1)
	f.putUser("uid=legacy,"+userBase, "legacy", 99999)

	got, err := newClient(f, config.Range{Min: 10000, Max: 60000}).AllocateUID()
	if err != nil {
		t.Fatal(err)
	}
	if got != 10000 {
		t.Errorf("AllocateUID = %d, want 10000 (out-of-range accounts ignored)", got)
	}
}

func TestAllocateUIDIgnoresMalformedIDs(t *testing.T) {
	f := newFake()
	f.put("uid=broken,"+userBase, map[string][]string{
		"objectClass": {"posixAccount"},
		"uid":         {"broken"},
		"uidNumber":   {"not-a-number"},
	})
	f.putUser("uid=ok,"+userBase, "ok", 10007)

	got, err := newClient(f, config.Range{Min: 10000, Max: 60000}).AllocateUID()
	if err != nil {
		t.Fatalf("a malformed id elsewhere should not block provisioning: %v", err)
	}
	if got != 10008 {
		t.Errorf("AllocateUID = %d, want 10008", got)
	}
}

func TestAllocateUIDRangeExhausted(t *testing.T) {
	f := newFake()
	f.putUser("uid=last,"+userBase, "last", 10002)

	_, err := newClient(f, config.Range{Min: 10000, Max: 10002}).AllocateUID()
	if err == nil {
		t.Fatal("expected an exhausted-range error")
	}
	if !strings.Contains(err.Error(), "exhausted") || !strings.Contains(err.Error(), "uid.max") {
		t.Errorf("error should name the exhausted range and the fix, got: %v", err)
	}
}

// The counter and the scan interact; these cases are the reason both exist.
func TestAllocateUIDWithCounter(t *testing.T) {
	rng := config.Range{Min: 10000, Max: 60000, NextDN: counterDN, NextAttr: "uidNumber"}

	tests := []struct {
		name        string
		counter     int
		existing    []int
		want        int
		wantCounter string
	}{
		{
			name:        "counter ahead of the directory is honoured",
			counter:     10100,
			existing:    []int{10041},
			want:        10100,
			wantCounter: "10101",
		},
		{
			// The case that makes the scan worth keeping: a counter that was
			// reset or restored from an old backup would otherwise reissue an
			// id that is already in use.
			name:        "stale counter is corrected by the scan",
			counter:     10000,
			existing:    []int{10041},
			want:        10042,
			wantCounter: "10043",
		},
		{
			name:        "counter used as-is on an empty directory",
			counter:     10500,
			existing:    nil,
			want:        10500,
			wantCounter: "10501",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(counterDN, map[string][]string{
				"objectClass": {"top", "device"},
				"cn":          {"uidNext"},
				"uidNumber":   {fmt.Sprint(tc.counter)},
			})
			for i, uidNum := range tc.existing {
				f.putUser(fmt.Sprintf("uid=u%d,%s", i, userBase), fmt.Sprintf("u%d", i), uidNum)
			}

			got, err := newClient(f, rng).AllocateUID()
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("AllocateUID = %d, want %d", got, tc.want)
			}
			if gotCounter := f.entries[counterDN]["uidNumber"]; len(gotCounter) != 1 || gotCounter[0] != tc.wantCounter {
				t.Errorf("counter = %v, want [%s]", gotCounter, tc.wantCounter)
			}
		})
	}
}

func TestAllocateUIDMissingCounterFallsBackToScan(t *testing.T) {
	// Configured but never created: scanning still gives a correct answer, so
	// this should not be a hard failure.
	rng := config.Range{Min: 10000, Max: 60000, NextDN: counterDN, NextAttr: "uidNumber"}
	f := newFake()
	f.putUser("uid=a,"+userBase, "a", 10041)

	got, err := newClient(f, rng).AllocateUID()
	if err != nil {
		t.Fatalf("a missing counter entry should fall back to scanning: %v", err)
	}
	if got != 10042 {
		t.Errorf("AllocateUID = %d, want 10042", got)
	}
}

func TestAllocateUIDRetriesLostCAS(t *testing.T) {
	rng := config.Range{Min: 10000, Max: 60000, NextDN: counterDN, NextAttr: "uidNumber"}
	f := newFake()
	f.put(counterDN, map[string][]string{
		"objectClass": {"top", "device"},
		"uidNumber":   {"10100"},
	})

	// First swap fails as though another run got there first, and that run's
	// value is what we must pick up on the retry.
	f.failModify = func(call int, _ *ldap.ModifyRequest) error {
		if call == 1 {
			f.entries[counterDN]["uidNumber"] = []string{"10101"}
			return ldap.NewError(ldap.LDAPResultNoSuchAttribute, fmt.Errorf("value changed"))
		}
		return nil
	}

	got, err := newClient(f, rng).AllocateUID()
	if err != nil {
		t.Fatal(err)
	}
	if got != 10101 {
		t.Errorf("AllocateUID = %d, want 10101 (the value the winning run left)", got)
	}
}

func TestAllocateUIDGivesUpAfterPersistentCASFailure(t *testing.T) {
	rng := config.Range{Min: 10000, Max: 60000, NextDN: counterDN, NextAttr: "uidNumber"}
	f := newFake()
	f.put(counterDN, map[string][]string{"uidNumber": {"10100"}})
	f.failModify = func(int, *ldap.ModifyRequest) error {
		return ldap.NewError(ldap.LDAPResultNoSuchAttribute, fmt.Errorf("always loses"))
	}

	_, err := newClient(f, rng).AllocateUID()
	if err == nil {
		t.Fatal("expected an error after exhausting the retries")
	}
	if f.modifyCall != casAttempts {
		t.Errorf("made %d modify attempts, want %d", f.modifyCall, casAttempts)
	}
	if !strings.Contains(err.Error(), "concurrently") {
		t.Errorf("error should hint at concurrency, got: %v", err)
	}
}

func TestAllocateUIDRejectsNonNumericCounter(t *testing.T) {
	rng := config.Range{Min: 10000, Max: 60000, NextDN: counterDN, NextAttr: "uidNumber"}
	f := newFake()
	f.put(counterDN, map[string][]string{"uidNumber": {"lots"}})

	_, err := newClient(f, rng).AllocateUID()
	if err == nil || !strings.Contains(err.Error(), "non-numeric") {
		t.Fatalf("err = %v, want a non-numeric counter error", err)
	}
}

func TestPeekUIDDoesNotWrite(t *testing.T) {
	// --dry-run must not move the counter.
	rng := config.Range{Min: 10000, Max: 60000, NextDN: counterDN, NextAttr: "uidNumber"}
	f := newFake()
	f.put(counterDN, map[string][]string{"uidNumber": {"10100"}})
	f.putUser("uid=a,"+userBase, "a", 10041)

	got, err := newClient(f, rng).PeekUID()
	if err != nil {
		t.Fatal(err)
	}
	if got != 10042 {
		t.Errorf("PeekUID = %d, want 10042", got)
	}
	if f.modifyCall != 0 {
		t.Errorf("PeekUID issued %d modifies, want 0", f.modifyCall)
	}
	if v := f.entries[counterDN]["uidNumber"]; v[0] != "10100" {
		t.Errorf("counter moved to %v during a peek", v)
	}
}

func TestScanFallsBackWhenPagingUnsupported(t *testing.T) {
	f := newFake()
	f.noPaging = true
	f.putUser("uid=a,"+userBase, "a", 10041)

	got, err := newClient(f, config.Range{Min: 10000, Max: 60000}).AllocateUID()
	if err != nil {
		t.Fatalf("should fall back to an unpaged search: %v", err)
	}
	if got != 10042 {
		t.Errorf("AllocateUID = %d, want 10042", got)
	}
}

func TestAllocateGIDUsesGroupBase(t *testing.T) {
	f := newFake()
	f.putGroup("cn=users,"+groupBase, "users", 20000)
	f.putGroup("cn=devs,"+groupBase, "devs", 20007)
	// A user-side id must not influence the group range.
	f.putUser("uid=a,"+userBase, "a", 59000)

	got, err := newClient(f, config.Range{Min: 10000, Max: 60000}).AllocateGID()
	if err != nil {
		t.Fatal(err)
	}
	if got != 20008 {
		t.Errorf("AllocateGID = %d, want 20008", got)
	}
}

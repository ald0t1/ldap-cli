package directory

import (
	"strings"
	"testing"

	"github.com/aldo/ldap-cli/internal/config"
)

func TestCreateGroupAllocatesGID(t *testing.T) {
	f := newFake()
	f.putGroup("cn=users,"+groupBase, "users", 20000)
	c := newClient(f, defaultUIDRange)

	got, err := c.CreateGroup(NewGroup{CN: "developers", Description: "Dev team"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GIDNumber != 20001 {
		t.Errorf("gidNumber = %d, want 20001", got.GIDNumber)
	}
	if got.DN != "cn=developers,"+groupBase {
		t.Errorf("dn = %q", got.DN)
	}

	entry := f.entries[got.DN]
	if !contains(entry["objectClass"], "posixGroup") {
		t.Errorf("objectClass = %v, want it to include posixGroup", entry["objectClass"])
	}
	if entry["description"][0] != "Dev team" {
		t.Errorf("description = %v", entry["description"])
	}
}

func TestCreateGroupHonoursExplicitGID(t *testing.T) {
	f := newFake()
	c := newClient(f, defaultUIDRange)

	got, err := c.CreateGroup(NewGroup{CN: "developers", GIDNumber: 25000})
	if err != nil {
		t.Fatal(err)
	}
	if got.GIDNumber != 25000 {
		t.Errorf("gidNumber = %d, want 25000", got.GIDNumber)
	}
}

func TestCreateGroupRejectsDuplicateGID(t *testing.T) {
	// Two groups on one gidNumber silently merges their POSIX identity.
	f := newFake()
	f.putGroup("cn=users,"+groupBase, "users", 20000)
	c := newClient(f, defaultUIDRange)

	_, err := c.CreateGroup(NewGroup{CN: "developers", GIDNumber: 20000})
	if err == nil {
		t.Fatal("expected a rejection for an in-use gidNumber")
	}
	if !strings.Contains(err.Error(), "already used by") {
		t.Errorf("error should name the conflicting group, got: %v", err)
	}
}

func TestCreateGroupRejectsDuplicateName(t *testing.T) {
	f := newFake()
	f.putGroup("cn=users,"+groupBase, "users", 20000)
	c := newClient(f, defaultUIDRange)

	_, err := c.CreateGroup(NewGroup{CN: "users"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want an already-exists error", err)
	}
}

func TestRequireGroupSuggestsNearMisses(t *testing.T) {
	f := newFake()
	f.putGroup("cn=developers,"+groupBase, "developers", 20001)
	f.putGroup("cn=devops,"+groupBase, "devops", 20002)
	c := newClient(f, defaultUIDRange)

	_, err := c.RequireGroup("devs")
	if err == nil {
		t.Fatal("expected an error for a missing group")
	}
	for _, want := range []string{"does not exist", "developers", "devops", "group create devs"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestAddMemberIsIdempotent(t *testing.T) {
	// These commands are meant to be safe to re-run after a partial failure.
	f := newFake()
	f.putGroup("cn=docker,"+groupBase, "docker", 20001)
	c := newClient(f, defaultUIDRange)

	g, err := c.RequireGroup("docker")
	if err != nil {
		t.Fatal(err)
	}

	added, err := c.AddMember(g, "jdoe")
	if err != nil || !added {
		t.Fatalf("first add: added=%v err=%v", added, err)
	}

	added, err = c.AddMember(g, "jdoe")
	if err != nil {
		t.Fatalf("re-adding an existing member should not error: %v", err)
	}
	if added {
		t.Error("second add reported a change")
	}
	if got := f.entries[g.DN]["memberUid"]; len(got) != 1 {
		t.Errorf("memberUid = %v, want one entry", got)
	}
}

func TestRemoveMemberIsIdempotent(t *testing.T) {
	f := newFake()
	f.putGroup("cn=docker,"+groupBase, "docker", 20001, "jdoe")
	c := newClient(f, defaultUIDRange)

	g, err := c.RequireGroup("docker")
	if err != nil {
		t.Fatal(err)
	}

	removed, err := c.RemoveMember(g, "jdoe")
	if err != nil || !removed {
		t.Fatalf("first remove: removed=%v err=%v", removed, err)
	}

	removed, err = c.RemoveMember(g, "jdoe")
	if err != nil {
		t.Fatalf("removing a non-member should not error: %v", err)
	}
	if removed {
		t.Error("second remove reported a change")
	}
}

func TestListGroupsSorted(t *testing.T) {
	f := newFake()
	f.putGroup("cn=vpn,"+groupBase, "vpn", 20003)
	f.putGroup("cn=admins,"+groupBase, "admins", 20001)
	f.putGroup("cn=docker,"+groupBase, "docker", 20002)
	c := newClient(f, defaultUIDRange)

	groups, err := c.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"admins", "docker", "vpn"}
	if len(groups) != len(want) {
		t.Fatalf("got %d groups, want %d", len(groups), len(want))
	}
	for i := range want {
		if groups[i].CN != want[i] {
			t.Errorf("groups[%d] = %q, want %q", i, groups[i].CN, want[i])
		}
	}
}

func TestFindGroupRejectsNonNumericGID(t *testing.T) {
	f := newFake()
	f.put("cn=broken,"+groupBase, map[string][]string{
		"objectClass": {"posixGroup"},
		"cn":          {"broken"},
		"gidNumber":   {"twenty"},
	})
	c := newClient(f, defaultUIDRange)

	if _, err := c.FindGroup("broken"); err == nil {
		t.Fatal("expected an error for a non-numeric gidNumber")
	}
}

func TestGroupDNEscapesSpecialCharacters(t *testing.T) {
	f := newFake()
	c := newClient(f, config.Range{Min: 10000, Max: 60000})

	// A comma in a cn would otherwise split the DN into extra components.
	if got := c.GroupDN("a,b"); !strings.HasPrefix(got, `cn=a\,b,`) {
		t.Errorf("GroupDN = %q, want the comma escaped", got)
	}
}

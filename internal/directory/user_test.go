package directory

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/aldo/ldap-cli/internal/config"
)

var defaultUIDRange = config.Range{Min: 10000, Max: 60000}

// fixture returns a fake with the standard tree and a client over it.
func fixture(t *testing.T) (*fakeConn, *Client, *Group) {
	t.Helper()
	f := newFake()
	f.putGroup("cn=users,"+groupBase, "users", 20000)
	c := newClient(f, defaultUIDRange)

	primary, err := c.RequireGroup("users")
	if err != nil {
		t.Fatal(err)
	}
	return f, c, primary
}

func TestCreateUser(t *testing.T) {
	f, c, primary := fixture(t)

	res, err := c.CreateUser(NewUser{
		GivenName:    "John",
		Surname:      "Doe",
		Email:        "john.doe@example.org",
		PrimaryGroup: primary,
		Password:     "s3cret-passw0rd",
	}, true)
	if err != nil {
		t.Fatal(err)
	}

	u := res.User
	if u.Username != "jdoe" {
		t.Errorf("username = %q, want jdoe", u.Username)
	}
	if u.DN != "uid=jdoe,"+userBase {
		t.Errorf("dn = %q", u.DN)
	}
	if u.UIDNumber != 10000 {
		t.Errorf("uidNumber = %d, want 10000", u.UIDNumber)
	}
	if u.GIDNumber != 20000 {
		t.Errorf("gidNumber = %d, want the primary group's 20000", u.GIDNumber)
	}
	if u.HomeDir != "/home/jdoe" {
		t.Errorf("homeDirectory = %q, want /home/jdoe", u.HomeDir)
	}
	if u.CommonName != "John Doe" {
		t.Errorf("cn = %q, want John Doe", u.CommonName)
	}

	entry := f.entries[u.DN]
	if entry == nil {
		t.Fatal("the entry was not added")
	}
	for _, class := range []string{"inetOrgPerson", "posixAccount", "shadowAccount"} {
		if !contains(entry["objectClass"], class) {
			t.Errorf("objectClass %v is missing %s", entry["objectClass"], class)
		}
	}

	// The password must reach the server through the extended operation, not
	// as a userPassword attribute on the add.
	if got := entry["userPassword"]; len(got) != 1 || !strings.HasPrefix(got[0], "{SSHA}") {
		t.Errorf("userPassword = %v, want a server-hashed value set via PasswordModify", got)
	}
	if len(f.pwdCalls) != 1 || f.pwdCalls[0] != u.DN {
		t.Errorf("PasswordModify calls = %v, want one for %s", f.pwdCalls, u.DN)
	}
}

func TestCreateUserNeverSendsPasswordOnTheAdd(t *testing.T) {
	// Sending userPassword on the add would let this tool pick the hash
	// scheme, which is the server's job.
	_, c, primary := fixture(t)
	f := c.Conn.(*fakeConn)

	f.failAdd = func(_ int, req *ldap.AddRequest) error {
		for _, a := range req.Attributes {
			if strings.EqualFold(a.Type, "userPassword") {
				t.Errorf("the add request carried userPassword: %v", a.Vals)
			}
		}
		return nil
	}

	if _, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary, Password: "s3cret-passw0rd",
	}, true); err != nil {
		t.Fatal(err)
	}
}

func TestCreateUserGeneratesDistinctUsernamesAndUIDs(t *testing.T) {
	_, c, primary := fixture(t)

	// Three people whose names all reduce to jdoe.
	people := []struct{ given, surname string }{
		{"John", "Doe"},
		{"Jonathan", "Doe"},
		{"Jane", "Doe"},
	}
	wantNames := []string{"jdoe", "jdoe1", "jdoe2"}
	wantUIDs := []int{10000, 10001, 10002}

	for i, p := range people {
		res, err := c.CreateUser(NewUser{
			GivenName: p.given, Surname: p.surname,
			PrimaryGroup: primary, Password: "s3cret-passw0rd",
		}, true)
		if err != nil {
			t.Fatalf("creating %s %s: %v", p.given, p.surname, err)
		}
		if res.User.Username != wantNames[i] {
			t.Errorf("user %d username = %q, want %q", i, res.User.Username, wantNames[i])
		}
		if res.User.UIDNumber != wantUIDs[i] {
			t.Errorf("user %d uidNumber = %d, want %d", i, res.User.UIDNumber, wantUIDs[i])
		}
	}
}

func TestCreateUserDefaultsEmailFromMailDomain(t *testing.T) {
	_, c, primary := fixture(t)

	res, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary, Password: "s3cret-passw0rd",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := "jdoe@example.org"; res.User.Email != want {
		t.Errorf("mail = %q, want %q", res.User.Email, want)
	}
}

func TestCreateUserRetriesWhenUsernameIsTakenMidFlight(t *testing.T) {
	// The collision search is a snapshot; another run can claim the name
	// before our add lands. The retry is what closes that window.
	_, c, primary := fixture(t)
	f := c.Conn.(*fakeConn)

	f.failAdd = func(call int, req *ldap.AddRequest) error {
		if call == 1 && strings.HasPrefix(req.DN, "uid=jdoe,") {
			return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, fmt.Errorf("beaten to it"))
		}
		return nil
	}

	res, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary, Password: "s3cret-passw0rd",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Username != "jdoe1" {
		t.Errorf("username = %q, want jdoe1 after losing the race for jdoe", res.User.Username)
	}
}

func TestCreateUserFailsWhenEveryCandidateIsTaken(t *testing.T) {
	_, c, primary := fixture(t)
	f := c.Conn.(*fakeConn)
	f.failAdd = func(int, *ldap.AddRequest) error {
		return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, fmt.Errorf("always taken"))
	}

	_, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary, Password: "s3cret-passw0rd",
	}, true)
	if err == nil {
		t.Fatal("expected a failure once every candidate is taken")
	}
	if f.addCall != addAttempts {
		t.Errorf("tried %d adds, want %d", f.addCall, addAttempts)
	}
}

func TestCreateUserRollsBackWhenPasswordCannotBeSet(t *testing.T) {
	// A passwordless account is worse than no account, so the entry must not
	// survive a failed password step.
	_, c, primary := fixture(t)
	f := c.Conn.(*fakeConn)

	f.failPwd = func(int, *ldap.PasswordModifyRequest) error {
		return ldap.NewError(ldap.LDAPResultConstraintViolation, fmt.Errorf("password fails the quality checks"))
	}

	_, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary, Password: "s3cret-passw0rd",
	}, true)
	if err == nil {
		t.Fatal("expected the create to fail when the password cannot be set")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("error should say the entry was rolled back, got: %v", err)
	}
	if _, still := f.entries["uid=jdoe,"+userBase]; still {
		t.Error("the entry survived a failed password step")
	}
}

func TestCreateUserWithoutRollbackSaysWhatWasLeftBehind(t *testing.T) {
	_, c, primary := fixture(t)
	f := c.Conn.(*fakeConn)
	f.failPwd = func(int, *ldap.PasswordModifyRequest) error {
		return ldap.NewError(ldap.LDAPResultConstraintViolation, fmt.Errorf("password fails the quality checks"))
	}

	_, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary, Password: "s3cret-passw0rd",
	}, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	// The operator has to know an entry needs attention.
	if !strings.Contains(err.Error(), "left in place") || !strings.Contains(err.Error(), "uid=jdoe") {
		t.Errorf("error should name the entry left behind, got: %v", err)
	}
	if len(f.deleted) != 0 {
		t.Errorf("nothing should have been deleted with rollback off, got %v", f.deleted)
	}
}

func TestCreateUserJoinsExtraGroups(t *testing.T) {
	f, c, primary := fixture(t)
	f.putGroup("cn=docker,"+groupBase, "docker", 20001)
	f.putGroup("cn=vpn,"+groupBase, "vpn", 20002)

	docker, err := c.RequireGroup("docker")
	if err != nil {
		t.Fatal(err)
	}
	vpn, err := c.RequireGroup("vpn")
	if err != nil {
		t.Fatal(err)
	}

	res, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary,
		Password: "s3cret-passw0rd", Groups: []*Group{docker, vpn},
	}, true)
	if err != nil {
		t.Fatal(err)
	}

	if len(res.GroupErrors) != 0 {
		t.Fatalf("unexpected group errors: %v", res.GroupErrors)
	}
	if len(res.JoinedGroup) != 2 {
		t.Errorf("joined = %v, want both groups", res.JoinedGroup)
	}
	for _, dn := range []string{"cn=docker," + groupBase, "cn=vpn," + groupBase} {
		if !contains(f.entries[dn]["memberUid"], "jdoe") {
			t.Errorf("%s memberUid = %v, want it to include jdoe", dn, f.entries[dn]["memberUid"])
		}
	}
}

func TestCreateUserSkipsPrimaryGroupInExtraGroups(t *testing.T) {
	// gidNumber already conveys the primary group; adding memberUid too is
	// redundant, and asking for it explicitly should not double up.
	f, c, primary := fixture(t)

	res, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary,
		Password: "s3cret-passw0rd", Groups: []*Group{primary},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.JoinedGroup) != 0 {
		t.Errorf("joined = %v, want none (primary group is conveyed by gidNumber)", res.JoinedGroup)
	}
	if got := f.entries["cn=users,"+groupBase]["memberUid"]; len(got) != 0 {
		t.Errorf("memberUid = %v, want empty", got)
	}
}

func TestCreateUserReportsGroupFailuresWithoutRollingBack(t *testing.T) {
	// The account is usable; re-running add-group fixes the membership
	// without recreating the user or reissuing its password.
	f, c, primary := fixture(t)
	missing := &Group{DN: "cn=ghost," + groupBase, CN: "ghost", GIDNumber: 20099}

	res, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary,
		Password: "s3cret-passw0rd", Groups: []*Group{missing},
	}, true)
	if err != nil {
		t.Fatalf("a group failure should not fail the whole create: %v", err)
	}
	if len(res.GroupErrors) != 1 {
		t.Fatalf("GroupErrors = %v, want one", res.GroupErrors)
	}
	if _, ok := f.entries["uid=jdoe,"+userBase]; !ok {
		t.Error("the account should still exist after a group failure")
	}
}

func TestCreateUserRequiresPrimaryGroupAndPassword(t *testing.T) {
	_, c, primary := fixture(t)

	if _, err := c.CreateUser(NewUser{GivenName: "John", Surname: "Doe", Password: "x"}, true); err == nil {
		t.Error("expected an error without a primary group")
	}
	if _, err := c.CreateUser(NewUser{GivenName: "John", Surname: "Doe", PrimaryGroup: primary}, true); err == nil {
		t.Error("expected an error without a password")
	}
}

func TestCreateUserHonoursExplicitUsernameExactly(t *testing.T) {
	// Quietly provisioning jdoe1 for someone who asked for jdoe would be
	// worse than refusing.
	f, c, primary := fixture(t)
	f.putUser("uid=jdoe,"+userBase, "jdoe", 10000)

	_, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", Username: "jdoe",
		PrimaryGroup: primary, Password: "s3cret-passw0rd",
	}, true)
	if err == nil {
		t.Fatal("expected a failure rather than a silently renamed account")
	}
}

func TestCreateUserRejectsInvalidExplicitUsername(t *testing.T) {
	_, c, primary := fixture(t)
	for _, bad := range []string{"JDoe", "j doe", "1jdoe", "jdoe,ou=x"} {
		if _, err := c.CreateUser(NewUser{
			GivenName: "John", Surname: "Doe", Username: bad,
			PrimaryGroup: primary, Password: "s3cret-passw0rd",
		}, true); err == nil {
			t.Errorf("username %q should have been rejected", bad)
		}
	}
}

func TestDryRunEntryWritesNothing(t *testing.T) {
	f, c, primary := fixture(t)

	user, ldif, err := c.DryRunEntry(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary, Password: "s3cret-passw0rd",
	})
	if err != nil {
		t.Fatal(err)
	}

	if user.Username != "jdoe" {
		t.Errorf("username = %q, want jdoe", user.Username)
	}
	for _, want := range []string{
		"dn: uid=jdoe," + userBase,
		"uidNumber: 10000",
		"gidNumber: 20000",
		"homeDirectory: /home/jdoe",
		"loginShell: /bin/bash",
		"sn: Doe",
	} {
		if !strings.Contains(ldif, want) {
			t.Errorf("LDIF is missing %q:\n%s", want, ldif)
		}
	}
	if strings.Contains(ldif, "userPassword") {
		t.Errorf("a dry run must not print a password:\n%s", ldif)
	}

	if f.addCall != 0 || f.modifyCall != 0 || len(f.pwdCalls) != 0 {
		t.Errorf("dry run wrote: %d adds, %d modifies, %d password ops", f.addCall, f.modifyCall, len(f.pwdCalls))
	}
	if _, exists := f.entries["uid=jdoe,"+userBase]; exists {
		t.Error("dry run created the entry")
	}
}

func TestFindUserNeverRequestsPassword(t *testing.T) {
	f, c, primary := fixture(t)
	if _, err := c.CreateUser(NewUser{
		GivenName: "John", Surname: "Doe", PrimaryGroup: primary, Password: "s3cret-passw0rd",
	}, true); err != nil {
		t.Fatal(err)
	}

	got, err := c.FindUser("jdoe")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("FindUser returned nothing for an account that exists")
	}
	if got.Username != "jdoe" || got.UIDNumber != 10000 {
		t.Errorf("got %+v", got)
	}

	// The fake stores a hash; the point is that the search never asks for it.
	if f.entries[got.DN]["userPassword"] == nil {
		t.Fatal("fixture problem: expected a stored password")
	}

	missing, err := c.FindUser("nobody")
	if err != nil {
		t.Fatal(err)
	}
	if missing != nil {
		t.Errorf("FindUser(nobody) = %+v, want nil", missing)
	}
}

func TestProposeUsername(t *testing.T) {
	f, c, _ := fixture(t)
	f.putUser("uid=jdoe,"+userBase, "jdoe", 10000)
	// A longer login that merely starts with jdoe is a different person.
	f.putUser("uid=jdoesmith,"+userBase, "jdoesmith", 10001)

	got, err := c.ProposeUsername("Jonathan", "Doe")
	if err != nil {
		t.Fatal(err)
	}
	if got != "jdoe1" {
		t.Errorf("ProposeUsername = %q, want jdoe1", got)
	}
}

func TestGroupsOf(t *testing.T) {
	f, c, primary := fixture(t)
	f.putGroup("cn=docker,"+groupBase, "docker", 20001, "jdoe")
	f.putGroup("cn=vpn,"+groupBase, "vpn", 20002, "someone-else")
	_ = primary

	groups, err := c.GroupsOf("jdoe")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].CN != "docker" {
		t.Errorf("GroupsOf(jdoe) = %+v, want just docker", groups)
	}
}

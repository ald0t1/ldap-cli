package directory

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/aldo/ldap-cli/internal/username"
)

// addAttempts bounds how many username candidates an add will try before
// giving up. Each retry means another run claimed the name in between.
const addAttempts = 3

// User is a provisioned account.
type User struct {
	DN         string
	Username   string
	GivenName  string
	Surname    string
	CommonName string
	Email      string
	UIDNumber  int
	GIDNumber  int
	HomeDir    string
	LoginShell string
}

// NewUser is the request to provision an account.
type NewUser struct {
	GivenName string
	Surname   string
	Email     string

	// Username overrides the generated name when non-empty.
	Username string

	// PrimaryGroup supplies gidNumber; it must already exist.
	PrimaryGroup *Group

	// Password is set through the Password Modify extended operation after
	// the entry is added, so the server applies its own hashing policy.
	Password string

	// Groups are additional posixGroups to add the account to.
	Groups []*Group
}

// CreateResult reports what a create actually did, including any group
// memberships that failed after the account itself was created.
type CreateResult struct {
	User        *User
	Password    string
	JoinedGroup []string
	GroupErrors []error
}

// UserDN is where an account with this username lives.
func (c *Client) UserDN(uid string) string {
	return fmt.Sprintf("%s=%s,%s", c.Profile.UserRDNAttr, ldap.EscapeDN(uid), c.Profile.UserBaseDN)
}

// FindUser looks an account up by its login name, returning nil when absent.
func (c *Client) FindUser(uid string) (*User, error) {
	filter := fmt.Sprintf("(&(objectClass=posixAccount)(%s=%s))",
		c.Profile.UserRDNAttr, ldap.EscapeFilter(uid))
	req := ldap.NewSearchRequest(
		c.Profile.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false,
		filter,
		// userPassword is deliberately never requested.
		[]string{c.Profile.UserRDNAttr, "cn", "sn", "givenName", "mail",
			"uidNumber", "gidNumber", "homeDirectory", "loginShell"}, nil,
	)

	res, err := c.Conn.Search(req)
	if err != nil {
		if resultCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, nil
		}
		return nil, fmt.Errorf("search for user %q under %s: %w", uid, c.Profile.UserBaseDN, err)
	}
	if len(res.Entries) == 0 {
		return nil, nil
	}

	e := res.Entries[0]
	uidNum, _ := strconv.Atoi(e.GetAttributeValue("uidNumber"))
	gidNum, _ := strconv.Atoi(e.GetAttributeValue("gidNumber"))

	return &User{
		DN:         e.DN,
		Username:   e.GetAttributeValue(c.Profile.UserRDNAttr),
		GivenName:  e.GetAttributeValue("givenName"),
		Surname:    e.GetAttributeValue("sn"),
		CommonName: e.GetAttributeValue("cn"),
		Email:      e.GetAttributeValue("mail"),
		UIDNumber:  uidNum,
		GIDNumber:  gidNum,
		HomeDir:    e.GetAttributeValue("homeDirectory"),
		LoginShell: e.GetAttributeValue("loginShell"),
	}, nil
}

// GroupsOf lists the groups a username is a member of.
func (c *Client) GroupsOf(uid string) ([]Group, error) {
	filter := fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", ldap.EscapeFilter(uid))
	req := ldap.NewSearchRequest(
		c.Profile.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"cn", "gidNumber"}, nil,
	)

	res, err := searchAll(c.Conn, req)
	if err != nil {
		return nil, fmt.Errorf("find groups for %q: %w", uid, err)
	}

	groups := make([]Group, 0, len(res.Entries))
	for _, e := range res.Entries {
		gid, _ := strconv.Atoi(e.GetAttributeValue("gidNumber"))
		groups = append(groups, Group{DN: e.DN, CN: e.GetAttributeValue("cn"), GIDNumber: gid})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].CN < groups[j].CN })
	return groups, nil
}

// ListUsers returns every account under the user base, sorted by login.
//
// The interactive shell uses this to offer a picker instead of making the
// operator remember and retype logins.
func (c *Client) ListUsers() ([]User, error) {
	req := ldap.NewSearchRequest(
		c.Profile.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=posixAccount)",
		[]string{c.Profile.UserRDNAttr, "cn", "sn", "givenName", "mail",
			"uidNumber", "gidNumber", "homeDirectory", "loginShell"}, nil,
	)

	res, err := searchAll(c.Conn, req)
	if err != nil {
		return nil, fmt.Errorf("list accounts under %s: %w", c.Profile.UserBaseDN, err)
	}

	users := make([]User, 0, len(res.Entries))
	for _, e := range res.Entries {
		uidNum, _ := strconv.Atoi(e.GetAttributeValue("uidNumber"))
		gidNum, _ := strconv.Atoi(e.GetAttributeValue("gidNumber"))
		users = append(users, User{
			DN:         e.DN,
			Username:   e.GetAttributeValue(c.Profile.UserRDNAttr),
			GivenName:  e.GetAttributeValue("givenName"),
			Surname:    e.GetAttributeValue("sn"),
			CommonName: e.GetAttributeValue("cn"),
			Email:      e.GetAttributeValue("mail"),
			UIDNumber:  uidNum,
			GIDNumber:  gidNum,
			HomeDir:    e.GetAttributeValue("homeDirectory"),
			LoginShell: e.GetAttributeValue("loginShell"),
		})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users, nil
}

// TakenUsernames returns the set of logins that begin with prefix.
//
// One search up front is cheaper than probing each candidate, and the result
// feeds username.Unique. It is only a snapshot, which is why CreateUser still
// handles a losing add.
func (c *Client) TakenUsernames(prefix string) (map[string]bool, error) {
	filter := fmt.Sprintf("(%s=%s*)", c.Profile.UserRDNAttr, ldap.EscapeFilter(prefix))
	req := ldap.NewSearchRequest(
		c.Profile.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{c.Profile.UserRDNAttr}, nil,
	)

	res, err := searchAll(c.Conn, req)
	if err != nil {
		return nil, fmt.Errorf("check existing usernames under %s: %w", c.Profile.UserBaseDN, err)
	}

	taken := make(map[string]bool, len(res.Entries))
	for _, e := range res.Entries {
		if v := e.GetAttributeValue(c.Profile.UserRDNAttr); v != "" {
			taken[v] = true
		}
	}
	return taken, nil
}

// ProposeUsername picks the login a new account would get.
func (c *Client) ProposeUsername(given, surname string) (string, error) {
	base, err := username.Generate(given, surname, c.Profile.UsernameMaxLength)
	if err != nil {
		return "", err
	}
	taken, err := c.TakenUsernames(base)
	if err != nil {
		return "", err
	}
	return username.Unique(base, taken, c.Profile.UsernameMaxLength)
}

// usernameCandidates builds the ordered list of logins CreateUser will try.
func (c *Client) usernameCandidates(spec NewUser) ([]string, error) {
	if spec.Username != "" {
		if err := username.Valid(spec.Username, c.Profile.UsernameMaxLength); err != nil {
			return nil, err
		}
		// An explicit name is honoured exactly; silently provisioning
		// "jdoe1" for someone who asked for "jdoe" would be worse than
		// failing.
		return []string{spec.Username}, nil
	}

	base, err := username.Generate(spec.GivenName, spec.Surname, c.Profile.UsernameMaxLength)
	if err != nil {
		return nil, err
	}
	taken, err := c.TakenUsernames(base)
	if err != nil {
		return nil, err
	}

	candidates := username.Candidates(base, taken, c.Profile.UsernameMaxLength, addAttempts)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no free username available for %s %s", spec.GivenName, spec.Surname)
	}
	return candidates, nil
}

// CreateUser provisions an account: add the entry, set the password through
// the extended operation, then join the extra groups.
//
// The entry is added without userPassword and the password is set afterwards,
// so slapd hashes it according to its own policy rather than this tool
// choosing a scheme. If that second step fails the entry is removed again,
// because a passwordless account in the directory is worse than no account.
func (c *Client) CreateUser(spec NewUser, rollback bool) (*CreateResult, error) {
	if spec.PrimaryGroup == nil {
		return nil, errors.New("a primary group is required to set gidNumber")
	}
	if spec.Password == "" {
		return nil, errors.New("no password supplied")
	}

	candidates, err := c.usernameCandidates(spec)
	if err != nil {
		return nil, err
	}

	user, err := c.addEntry(spec, candidates)
	if err != nil {
		return nil, err
	}

	if err := c.setPassword(user.DN, spec.Password); err != nil {
		if !rollback {
			return nil, fmt.Errorf("%w\nthe entry %s was left in place without a password; "+
				"set one with `ldap-cli user passwd %s` or delete it", err, user.DN, user.Username)
		}
		if delErr := c.Conn.Del(ldap.NewDelRequest(user.DN, nil)); delErr != nil {
			return nil, fmt.Errorf("%w\nrolling back %s also failed: %v", err, user.DN, delErr)
		}
		return nil, fmt.Errorf("%w\nthe half-created entry %s was rolled back", err, user.DN)
	}

	result := &CreateResult{User: user, Password: spec.Password}

	// Group membership failures are reported but not rolled back: the account
	// is usable, and re-running `user add-group` fixes it without recreating
	// the user or reissuing the password.
	for _, g := range spec.Groups {
		if g.CN == spec.PrimaryGroup.CN {
			continue
		}
		added, err := c.AddMember(g, user.Username)
		switch {
		case err != nil:
			result.GroupErrors = append(result.GroupErrors, err)
		case added:
			result.JoinedGroup = append(result.JoinedGroup, g.CN)
		}
	}

	return result, nil
}

// addEntry tries each username candidate until one is accepted.
func (c *Client) addEntry(spec NewUser, candidates []string) (*User, error) {
	var lastErr error

	for _, uid := range candidates {
		// Allocated per attempt: a retry means a different account won this
		// name, and its uidNumber is now taken too.
		uidNumber, err := c.AllocateUID()
		if err != nil {
			return nil, err
		}

		user, req, err := c.buildEntry(spec, uid, uidNumber)
		if err != nil {
			return nil, err
		}

		err = c.Conn.Add(req)
		switch {
		case err == nil:
			return user, nil
		case isAlreadyExists(err):
			// Another run took this name between the collision check and
			// now. Move to the next candidate.
			lastErr = err
			continue
		default:
			return nil, fmt.Errorf("create user %s: %w", user.DN, err)
		}
	}

	return nil, fmt.Errorf("every username candidate (%s) was taken while creating the account; "+
		"re-run to pick a fresh name: %w", strings.Join(candidates, ", "), lastErr)
}

// buildEntry assembles the add request for one username and uidNumber.
//
// Allocation is the caller's job so that a dry run can render an entry without
// claiming an id from the counter.
func (c *Client) buildEntry(spec NewUser, uid string, uidNumber int) (*User, *ldap.AddRequest, error) {
	p := c.Profile

	home, err := p.HomeDir(uid)
	if err != nil {
		return nil, nil, err
	}

	email := spec.Email
	if email == "" && p.MailDomain != "" {
		email = uid + "@" + p.MailDomain
	}

	cn := strings.TrimSpace(spec.GivenName + " " + spec.Surname)
	user := &User{
		DN:         c.UserDN(uid),
		Username:   uid,
		GivenName:  spec.GivenName,
		Surname:    spec.Surname,
		CommonName: cn,
		Email:      email,
		UIDNumber:  uidNumber,
		GIDNumber:  spec.PrimaryGroup.GIDNumber,
		HomeDir:    home,
		LoginShell: p.LoginShell,
	}

	classes := append([]string{
		"top", "person", "organizationalPerson", "inetOrgPerson",
		"posixAccount", "shadowAccount",
	}, p.ExtraUserObjectClasses...)

	req := ldap.NewAddRequest(user.DN, nil)
	req.Attribute("objectClass", classes)
	req.Attribute(p.UserRDNAttr, []string{uid})
	req.Attribute("cn", []string{cn})
	req.Attribute("sn", []string{spec.Surname})
	req.Attribute("givenName", []string{spec.GivenName})
	req.Attribute("uidNumber", []string{strconv.Itoa(uidNumber)})
	req.Attribute("gidNumber", []string{strconv.Itoa(spec.PrimaryGroup.GIDNumber)})
	req.Attribute("homeDirectory", []string{home})
	req.Attribute("loginShell", []string{p.LoginShell})
	if email != "" {
		req.Attribute("mail", []string{email})
	}

	return user, req, nil
}

// setPassword sets an account's password via RFC 3062, letting the server
// choose the hash.
func (c *Client) setPassword(dn, password string) error {
	// An empty old password is what a manager bind uses to set a password it
	// does not know.
	req := ldap.NewPasswordModifyRequest(dn, "", password)
	if _, err := c.Conn.PasswordModify(req); err != nil {
		return fmt.Errorf("set password for %s via the password modify operation: %w", dn, err)
	}
	return nil
}

// SetPassword changes an existing account's password.
func (c *Client) SetPassword(dn, password string) error {
	return c.setPassword(dn, password)
}

// LDIF renders what an add request would send, for --dry-run.
func LDIF(req *ldap.AddRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "dn: %s\n", req.DN)
	for _, attr := range req.Attributes {
		for _, v := range attr.Vals {
			fmt.Fprintf(&b, "%s: %s\n", attr.Type, v)
		}
	}
	return b.String()
}

// DryRunEntry builds the entry for a dry run without writing anything.
//
// The uidNumber shown is the one a real run would most likely get. It comes
// from a scan rather than the counter, because claiming an id is a write and a
// dry run must not make any.
func (c *Client) DryRunEntry(spec NewUser) (*User, string, error) {
	candidates, err := c.usernameCandidates(spec)
	if err != nil {
		return nil, "", err
	}

	uidNumber, err := c.PeekUID()
	if err != nil {
		return nil, "", err
	}

	user, req, err := c.buildEntry(spec, candidates[0], uidNumber)
	if err != nil {
		return nil, "", err
	}
	return user, LDIF(req), nil
}

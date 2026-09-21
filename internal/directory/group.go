package directory

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Group is a posixGroup entry.
type Group struct {
	DN          string
	CN          string
	GIDNumber   int
	Description string
	MemberUIDs  []string
}

// GroupDN is where a group with this cn lives under the profile's group base.
func (c *Client) GroupDN(cn string) string {
	return fmt.Sprintf("cn=%s,%s", ldap.EscapeDN(cn), c.Profile.GroupBaseDN)
}

// FindGroup looks a group up by cn, returning nil when it does not exist.
func (c *Client) FindGroup(cn string) (*Group, error) {
	filter := fmt.Sprintf("(&(objectClass=posixGroup)(cn=%s))", ldap.EscapeFilter(cn))
	req := ldap.NewSearchRequest(
		c.Profile.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 0, false,
		filter,
		[]string{"cn", "gidNumber", "description", "memberUid"}, nil,
	)

	res, err := c.Conn.Search(req)
	if err != nil {
		if resultCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, nil
		}
		return nil, fmt.Errorf("search for group %q under %s: %w", cn, c.Profile.GroupBaseDN, err)
	}
	if len(res.Entries) == 0 {
		return nil, nil
	}
	if len(res.Entries) > 1 {
		return nil, fmt.Errorf("group %q is ambiguous: %d entries match under %s", cn, len(res.Entries), c.Profile.GroupBaseDN)
	}

	e := res.Entries[0]
	gid, err := strconv.Atoi(e.GetAttributeValue("gidNumber"))
	if err != nil {
		return nil, fmt.Errorf("group %s has a non-numeric gidNumber %q", e.DN, e.GetAttributeValue("gidNumber"))
	}

	return &Group{
		DN:          e.DN,
		CN:          e.GetAttributeValue("cn"),
		GIDNumber:   gid,
		Description: e.GetAttributeValue("description"),
		MemberUIDs:  e.GetAttributeValues("memberUid"),
	}, nil
}

// RequireGroup fetches a group or explains that it is missing, listing similar
// names so a typo is obvious without a second command.
func (c *Client) RequireGroup(cn string) (*Group, error) {
	g, err := c.FindGroup(cn)
	if err != nil {
		return nil, err
	}
	if g != nil {
		return g, nil
	}

	msg := fmt.Sprintf("group %q does not exist under %s", cn, c.Profile.GroupBaseDN)
	if near, _ := c.similarGroups(cn); len(near) > 0 {
		msg += fmt.Sprintf(" (did you mean: %s?)", strings.Join(near, ", "))
	}
	return nil, fmt.Errorf("%s; create it first with: ldap-cli group create %s", msg, cn)
}

// similarGroups finds groups whose name shares a prefix with cn.
func (c *Client) similarGroups(cn string) ([]string, error) {
	if len(cn) < 2 {
		return nil, nil
	}
	filter := fmt.Sprintf("(&(objectClass=posixGroup)(cn=%s*))", ldap.EscapeFilter(cn[:2]))
	req := ldap.NewSearchRequest(
		c.Profile.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		10, 0, false,
		filter,
		[]string{"cn"}, nil,
	)

	res, err := c.Conn.Search(req)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range res.Entries {
		names = append(names, e.GetAttributeValue("cn"))
	}
	sort.Strings(names)
	return names, nil
}

// ListGroups returns every posixGroup under the group base, sorted by name.
func (c *Client) ListGroups() ([]Group, error) {
	req := ldap.NewSearchRequest(
		c.Profile.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=posixGroup)",
		[]string{"cn", "gidNumber", "description", "memberUid"}, nil,
	)

	res, err := searchAll(c.Conn, req)
	if err != nil {
		return nil, fmt.Errorf("list groups under %s: %w", c.Profile.GroupBaseDN, err)
	}

	groups := make([]Group, 0, len(res.Entries))
	for _, e := range res.Entries {
		gid, _ := strconv.Atoi(e.GetAttributeValue("gidNumber"))
		groups = append(groups, Group{
			DN:          e.DN,
			CN:          e.GetAttributeValue("cn"),
			GIDNumber:   gid,
			Description: e.GetAttributeValue("description"),
			MemberUIDs:  e.GetAttributeValues("memberUid"),
		})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].CN < groups[j].CN })
	return groups, nil
}

// NewGroup describes a group to create. A zero GIDNumber means allocate one.
type NewGroup struct {
	CN          string
	GIDNumber   int
	Description string
}

// CreateGroup adds a posixGroup, allocating a gidNumber when one is not given.
func (c *Client) CreateGroup(spec NewGroup) (*Group, error) {
	if existing, err := c.FindGroup(spec.CN); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, fmt.Errorf("group %q already exists as %s with gidNumber %d",
			spec.CN, existing.DN, existing.GIDNumber)
	}

	gid := spec.GIDNumber
	if gid == 0 {
		allocated, err := c.AllocateGID()
		if err != nil {
			return nil, err
		}
		gid = allocated
	} else if err := c.assertGIDFree(gid); err != nil {
		return nil, err
	}

	dn := c.GroupDN(spec.CN)
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"top", "posixGroup"})
	req.Attribute("cn", []string{spec.CN})
	req.Attribute("gidNumber", []string{strconv.Itoa(gid)})
	if spec.Description != "" {
		req.Attribute("description", []string{spec.Description})
	}

	if err := c.Conn.Add(req); err != nil {
		if isAlreadyExists(err) {
			return nil, fmt.Errorf("group %q already exists at %s", spec.CN, dn)
		}
		return nil, fmt.Errorf("create group %s: %w", dn, err)
	}

	return &Group{DN: dn, CN: spec.CN, GIDNumber: gid, Description: spec.Description}, nil
}

// assertGIDFree rejects an explicitly requested gidNumber that is already in
// use, so --gid cannot collide two groups onto one id.
func (c *Client) assertGIDFree(gid int) error {
	filter := fmt.Sprintf("(&(objectClass=posixGroup)(gidNumber=%d))", gid)
	req := ldap.NewSearchRequest(
		c.Profile.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 0, false,
		filter,
		[]string{"cn"}, nil,
	)

	res, err := c.Conn.Search(req)
	if err != nil {
		if resultCode(err, ldap.LDAPResultNoSuchObject) {
			return nil
		}
		return fmt.Errorf("check whether gidNumber %d is free: %w", gid, err)
	}
	if len(res.Entries) > 0 {
		return fmt.Errorf("gidNumber %d is already used by %s", gid, res.Entries[0].DN)
	}
	return nil
}

// AddMember adds a username to a group's memberUid.
//
// A user who is already a member is a no-op rather than an error: these
// commands are meant to be safe to re-run after a partial failure.
func (c *Client) AddMember(group *Group, uid string) (added bool, err error) {
	mod := ldap.NewModifyRequest(group.DN, nil)
	mod.Add("memberUid", []string{uid})

	if err := c.Conn.Modify(mod); err != nil {
		if isValueExists(err) {
			return false, nil
		}
		return false, fmt.Errorf("add %s to group %s: %w", uid, group.CN, err)
	}
	return true, nil
}

// RemoveMember drops a username from a group's memberUid.
func (c *Client) RemoveMember(group *Group, uid string) (removed bool, err error) {
	mod := ldap.NewModifyRequest(group.DN, nil)
	mod.Delete("memberUid", []string{uid})

	if err := c.Conn.Modify(mod); err != nil {
		if resultCode(err, ldap.LDAPResultNoSuchAttribute) {
			return false, nil
		}
		return false, fmt.Errorf("remove %s from group %s: %w", uid, group.CN, err)
	}
	return true, nil
}

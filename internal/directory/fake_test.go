package directory

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// fakeConn is an in-memory stand-in for an LDAP server, good enough to drive
// the allocation and create flows without a container.
//
// It is intentionally simplistic about filters: it understands only the shapes
// this package actually sends.
type fakeConn struct {
	// entries maps DN to attribute name to values.
	entries map[string]map[string][]string

	// failModify, when non-nil, is consulted on each Modify. Returning an
	// error simulates losing a compare-and-swap race.
	failModify func(call int, req *ldap.ModifyRequest) error
	modifyCall int

	// failAdd likewise simulates another run winning a DN.
	failAdd func(call int, req *ldap.AddRequest) error
	addCall int

	// failPwd simulates the server rejecting a password, as a password policy
	// (ppolicy minimum length, history, quality checks) would.
	failPwd  func(call int, req *ldap.PasswordModifyRequest) error
	pwdCalls []string

	// noPaging makes SearchWithPaging refuse, exercising the fallback.
	noPaging bool

	deleted []string
}

func newFake() *fakeConn {
	return &fakeConn{entries: map[string]map[string][]string{}}
}

func (f *fakeConn) put(dn string, attrs map[string][]string) {
	f.entries[dn] = attrs
}

// putUser adds a posixAccount with the given login and uidNumber.
func (f *fakeConn) putUser(dn, uid string, uidNumber int) {
	f.put(dn, map[string][]string{
		"objectClass": {"top", "posixAccount"},
		"uid":         {uid},
		"uidNumber":   {fmt.Sprint(uidNumber)},
	})
}

// putGroup adds a posixGroup.
func (f *fakeConn) putGroup(dn, cn string, gidNumber int, members ...string) {
	attrs := map[string][]string{
		"objectClass": {"top", "posixGroup"},
		"cn":          {cn},
		"gidNumber":   {fmt.Sprint(gidNumber)},
	}
	if len(members) > 0 {
		attrs["memberUid"] = members
	}
	f.put(dn, attrs)
}

func (f *fakeConn) Close() error { return nil }

func (f *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	res := &ldap.SearchResult{}

	for dn, attrs := range f.entries {
		if !inScope(dn, req) {
			continue
		}
		if !matches(attrs, req.Filter) {
			continue
		}

		e := &ldap.Entry{DN: dn}
		for _, name := range req.Attributes {
			if vals, ok := attrs[name]; ok {
				e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: name, Values: vals})
			}
		}
		res.Entries = append(res.Entries, e)
	}

	if req.SizeLimit > 0 && len(res.Entries) > req.SizeLimit {
		res.Entries = res.Entries[:req.SizeLimit]
	}
	return res, nil
}

func (f *fakeConn) SearchWithPaging(req *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	if f.noPaging {
		return nil, ldap.NewError(ldap.LDAPResultUnavailableCriticalExtension, fmt.Errorf("no paging here"))
	}
	return f.Search(req)
}

func (f *fakeConn) Add(req *ldap.AddRequest) error {
	f.addCall++
	if f.failAdd != nil {
		if err := f.failAdd(f.addCall, req); err != nil {
			return err
		}
	}
	if _, exists := f.entries[req.DN]; exists {
		return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, fmt.Errorf("%s exists", req.DN))
	}

	attrs := map[string][]string{}
	for _, a := range req.Attributes {
		attrs[a.Type] = append(attrs[a.Type], a.Vals...)
	}
	f.entries[req.DN] = attrs
	return nil
}

func (f *fakeConn) Modify(req *ldap.ModifyRequest) error {
	f.modifyCall++
	if f.failModify != nil {
		if err := f.failModify(f.modifyCall, req); err != nil {
			return err
		}
	}

	attrs, ok := f.entries[req.DN]
	if !ok {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("%s missing", req.DN))
	}

	// Apply deletes before adds, which is what makes the delete-old/add-new
	// pair behave as a compare-and-swap.
	for _, change := range req.Changes {
		name := change.Modification.Type
		vals := change.Modification.Vals

		switch change.Operation {
		case ldap.DeleteAttribute:
			for _, v := range vals {
				if !contains(attrs[name], v) {
					return ldap.NewError(ldap.LDAPResultNoSuchAttribute,
						fmt.Errorf("%s on %s has no value %q", name, req.DN, v))
				}
			}
			attrs[name] = without(attrs[name], vals)
		case ldap.AddAttribute:
			for _, v := range vals {
				if contains(attrs[name], v) {
					return ldap.NewError(ldap.LDAPResultAttributeOrValueExists,
						fmt.Errorf("%s on %s already has %q", name, req.DN, v))
				}
			}
			attrs[name] = append(attrs[name], vals...)
		case ldap.ReplaceAttribute:
			attrs[name] = vals
		}
	}
	return nil
}

func (f *fakeConn) Del(req *ldap.DelRequest) error {
	if _, ok := f.entries[req.DN]; !ok {
		return ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("%s missing", req.DN))
	}
	delete(f.entries, req.DN)
	f.deleted = append(f.deleted, req.DN)
	return nil
}

func (f *fakeConn) PasswordModify(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	f.pwdCalls = append(f.pwdCalls, req.UserIdentity)
	if f.failPwd != nil {
		if err := f.failPwd(len(f.pwdCalls), req); err != nil {
			return nil, err
		}
	}
	if _, ok := f.entries[req.UserIdentity]; !ok {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("%s missing", req.UserIdentity))
	}
	// Record it the way a server would: hashed, never cleartext.
	f.entries[req.UserIdentity]["userPassword"] = []string{"{SSHA}" + req.NewPassword}
	return &ldap.PasswordModifyResult{}, nil
}

// inScope applies the search base and scope.
func inScope(dn string, req *ldap.SearchRequest) bool {
	switch req.Scope {
	case ldap.ScopeBaseObject:
		return strings.EqualFold(dn, req.BaseDN)
	default:
		return strings.EqualFold(dn, req.BaseDN) ||
			strings.HasSuffix(strings.ToLower(dn), ","+strings.ToLower(req.BaseDN))
	}
}

// matches evaluates the filter shapes this package emits: (objectClass=*),
// conjunctions, equality, prefix wildcards and >=/<= on numbers.
func matches(attrs map[string][]string, filter string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "(objectClass=*)" || filter == "" {
		return true
	}

	if strings.HasPrefix(filter, "(&") {
		for _, clause := range splitClauses(filter[2 : len(filter)-1]) {
			if !matches(attrs, clause) {
				return false
			}
		}
		return true
	}

	inner := strings.TrimSuffix(strings.TrimPrefix(filter, "("), ")")

	for _, op := range []string{">=", "<="} {
		if name, want, ok := strings.Cut(inner, op); ok {
			return compareNum(attrs[name], want, op)
		}
	}

	name, want, ok := strings.Cut(inner, "=")
	if !ok {
		return false
	}
	vals := attrs[name]
	if want == "*" {
		return len(vals) > 0
	}
	if strings.HasSuffix(want, "*") {
		prefix := strings.TrimSuffix(want, "*")
		for _, v := range vals {
			if strings.HasPrefix(v, prefix) {
				return true
			}
		}
		return false
	}
	return contains(vals, want)
}

func compareNum(vals []string, want, op string) bool {
	target, err := atoi(want)
	if err != nil {
		return false
	}
	for _, v := range vals {
		n, err := atoi(v)
		if err != nil {
			continue
		}
		if op == ">=" && n >= target {
			return true
		}
		if op == "<=" && n <= target {
			return true
		}
	}
	return false
}

func atoi(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	return n, nil
}

// splitClauses splits a conjunction body into its parenthesised clauses.
func splitClauses(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				out = append(out, s[start:i+1])
			}
		}
	}
	return out
}

func contains(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

func without(vals, remove []string) []string {
	var out []string
	for _, v := range vals {
		if !contains(remove, v) {
			out = append(out, v)
		}
	}
	return out
}

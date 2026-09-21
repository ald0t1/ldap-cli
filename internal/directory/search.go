package directory

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// pageSize is the paged-results page size. slapd's default size limit is 500
// entries, which an unpaged scan of every posixAccount would quietly hit.
const pageSize = 500

// searchAll runs a search across every page of results.
//
// Truncation matters here: the id allocator derives the next free number from
// the highest one it sees, so a silently short result set would hand out an id
// that is already in use. Paging keeps the scan complete, and a server that
// refuses the paging control falls back to a plain search.
func searchAll(conn Conn, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	res, err := conn.SearchWithPaging(req, pageSize)
	if err == nil {
		return res, nil
	}

	// unavailableCriticalExtension / unwillingToPerform mean this server does
	// not do paged results. Anything else is a real failure.
	if !resultCode(err, ldap.LDAPResultUnavailableCriticalExtension) &&
		!resultCode(err, ldap.LDAPResultUnwillingToPerform) {
		return nil, err
	}

	res, err = conn.Search(req)
	if err != nil {
		if resultCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, fmt.Errorf(
				"search of %s hit the server size limit and this server does not support paged results; "+
					"raise the server's sizelimit so the scan can be trusted: %w", req.BaseDN, err)
		}
		return nil, err
	}
	return res, nil
}

// searchOne fetches a single entry by DN, returning nil when it is absent.
func searchOne(conn Conn, dn string, attrs ...string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		attrs, nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		if resultCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, nil
		}
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, nil
	}
	return res.Entries[0], nil
}

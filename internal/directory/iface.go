// Package directory wraps the LDAP operations ldap-cli needs: connecting under
// a profile's TLS policy, allocating POSIX ids, and creating users and groups.
package directory

import (
	"github.com/go-ldap/ldap/v3"
)

// Conn is the slice of *ldap.Conn this package uses.
//
// Everything above this interface — id allocation, username collision
// handling, entry construction — is testable against a fake, which is where
// the interesting logic lives.
type Conn interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	SearchWithPaging(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error)
	Add(*ldap.AddRequest) error
	Modify(*ldap.ModifyRequest) error
	Del(*ldap.DelRequest) error
	PasswordModify(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	Close() error
}

// resultCode reports whether err is an LDAP error carrying the given result
// code. Several flows depend on distinguishing an expected code from a real
// failure: 68 (entryAlreadyExists) means a username was taken between the
// collision check and the add, and 20 (attributeOrValueExists) means the user
// was already in the group.
func resultCode(err error, code uint16) bool {
	return ldap.IsErrorWithCode(err, code)
}

// isAlreadyExists reports whether an Add lost a race for its DN.
func isAlreadyExists(err error) bool {
	return resultCode(err, ldap.LDAPResultEntryAlreadyExists)
}

// isValueExists reports whether a Modify tried to add a value that was
// already present, which for group membership is success, not failure.
func isValueExists(err error) bool {
	return resultCode(err, ldap.LDAPResultAttributeOrValueExists)
}

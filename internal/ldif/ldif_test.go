package ldif

import (
	"strings"
	"testing"
)

func TestNeedsBase64(t *testing.T) {
	plain := []string{"jdoe", "John Doe", "/home/jdoe", "{SSHA}abc+/=", "a:b"}
	encoded := []string{
		"Straße",          // non-ASCII
		"Zoë",             // non-ASCII
		" leading space",  // leading space is syntax
		":leading colon",  // leading colon means base64 already
		"<leading angle",  // leading < means a URL reference
		"trailing space ", // a parser would drop the space
		"with\nnewline",   // control character
	}

	for _, v := range plain {
		if NeedsBase64(v) {
			t.Errorf("NeedsBase64(%q) = true, want false", v)
		}
	}
	for _, v := range encoded {
		if !NeedsBase64(v) {
			t.Errorf("NeedsBase64(%q) = false, want true", v)
		}
	}
	if NeedsBase64("") {
		t.Error("an empty value needs no encoding")
	}
}

func TestWriteEntry(t *testing.T) {
	var b strings.Builder
	err := WriteEntry(&b, "uid=jdoe,ou=people,dc=example,dc=org", []Attr{
		{Name: "objectClass", Values: []string{"posixAccount", "inetOrgPerson"}},
		{Name: "uid", Values: []string{"jdoe"}},
		{Name: "sn", Values: []string{"Straße"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := b.String()

	for _, want := range []string{
		"dn: uid=jdoe,ou=people,dc=example,dc=org\n",
		"objectClass: posixAccount\n",
		"objectClass: inetOrgPerson\n",
		"uid: jdoe\n",
		// Straße base64-encoded, with the double colon that marks it.
		"sn:: U3RyYcOfZQ==\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output is missing %q:\n%s", want, got)
		}
	}

	// A blank separator line is what makes a multi-entry LDIF parseable.
	if !strings.HasSuffix(got, "\n\n") {
		t.Errorf("entry should end with a blank line:\n%q", got)
	}
}

func TestWriteEntryMultipleEntriesAreSeparated(t *testing.T) {
	var b strings.Builder
	for _, dn := range []string{"cn=a,dc=x", "cn=b,dc=x"} {
		if err := WriteEntry(&b, dn, []Attr{{Name: "cn", Values: []string{dn[3:4]}}}); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(b.String(), "\n\n"); n != 2 {
		t.Errorf("found %d separators, want 2:\n%q", n, b.String())
	}
}

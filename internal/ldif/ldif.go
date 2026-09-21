// Package ldif writes entries in the LDIF interchange format (RFC 2849).
package ldif

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// Attr is one attribute and all of its values.
type Attr struct {
	Name   string
	Values []string
}

// WriteEntry writes one entry followed by a blank separator line.
//
// Values are base64-encoded when the format requires it, which matters more
// than it looks: a surname like "Straße" or a binary password hash written as
// a plain value produces an LDIF that will not load back.
func WriteEntry(w io.Writer, dn string, attrs []Attr) error {
	if err := writeLine(w, "dn", dn); err != nil {
		return err
	}
	for _, a := range attrs {
		for _, v := range a.Values {
			if err := writeLine(w, a.Name, v); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

// writeLine emits a single attribute line, choosing plain or base64 form.
func writeLine(w io.Writer, name, value string) error {
	if NeedsBase64(value) {
		_, err := fmt.Fprintf(w, "%s:: %s\n", name, base64.StdEncoding.EncodeToString([]byte(value)))
		return err
	}
	_, err := fmt.Fprintf(w, "%s: %s\n", name, value)
	return err
}

// NeedsBase64 reports whether a value must be base64-encoded.
//
// Per RFC 2849 that covers anything outside printable ASCII, plus values whose
// first character would be read as syntax (a space, a colon, or a less-than
// sign) and values with trailing whitespace that a parser would discard.
func NeedsBase64(v string) bool {
	if v == "" {
		return false
	}
	switch v[0] {
	case ' ', ':', '<':
		return true
	}
	if strings.HasSuffix(v, " ") {
		return true
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return true
		}
	}
	return false
}

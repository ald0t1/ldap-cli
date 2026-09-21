// Package username derives POSIX usernames from a person's name and resolves
// collisions against what is already in the directory.
package username

import (
	"fmt"
	"strconv"
	"strings"
)

// MaxSuffix bounds the numeric suffix search. Needing jdoe1000 means something
// is wrong upstream, not that we should keep probing.
const MaxSuffix = 999

// translit maps the accented and ligatured Latin letters that appear in
// European names onto ASCII.
//
// Unicode decomposition alone is not enough here: é does decompose to e +
// combining acute, but æ, ß, ø, đ and þ have no decomposition at all and would
// simply vanish, turning "Straße" into "strae" and "Ærø" into "r". Spelling
// the mapping out keeps those names correct and removes the need for a
// normalization dependency.
var translit = map[rune]string{
	'à': "a", 'á': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a", 'ā': "a", 'ă': "a", 'ą': "a",
	'æ': "ae",
	'ç': "c", 'ć': "c", 'č': "c", 'ĉ': "c", 'ċ': "c",
	'ď': "d", 'đ': "d", 'ð': "d",
	'è': "e", 'é': "e", 'ê': "e", 'ë': "e", 'ē': "e", 'ĕ': "e", 'ė': "e", 'ę': "e", 'ě': "e",
	'ĝ': "g", 'ğ': "g", 'ġ': "g", 'ģ': "g",
	'ĥ': "h", 'ħ': "h",
	'ì': "i", 'í': "i", 'î': "i", 'ï': "i", 'ĩ': "i", 'ī': "i", 'ĭ': "i", 'į': "i", 'ı': "i",
	'ĵ': "j",
	'ķ': "k",
	'ĺ': "l", 'ļ': "l", 'ľ': "l", 'ł': "l",
	'ñ': "n", 'ń': "n", 'ņ': "n", 'ň': "n", 'ŋ': "n",
	'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ø': "o", 'ō': "o", 'ŏ': "o", 'ő': "o",
	'œ': "oe",
	'ŕ': "r", 'ŗ': "r", 'ř': "r",
	'ś': "s", 'ŝ': "s", 'ş': "s", 'š': "s", 'ș': "s",
	'ß': "ss",
	'ţ': "t", 'ť': "t", 'ŧ': "t", 'ț': "t",
	'þ': "th",
	'ù': "u", 'ú': "u", 'û': "u", 'ü': "u", 'ũ': "u", 'ū': "u", 'ŭ': "u", 'ů': "u", 'ű': "u", 'ų': "u",
	'ŵ': "w",
	'ý': "y", 'ÿ': "y", 'ŷ': "y",
	'ź': "z", 'ż': "z", 'ž': "z",
}

// Generate builds the base username: the first letter of the given name
// followed by the surname, transliterated to ASCII and stripped to [a-z0-9].
//
//	John Doe         -> jdoe
//	Zoë Ó'Brien      -> zobrien
//	Jan van der Berg -> jvanderberg
//	Jens Straße      -> jstrasse
//
// maxLen caps the result, leaving room for a numeric suffix so that a
// truncated base can still be made unique.
func Generate(given, surname string, maxLen int) (string, error) {
	g := fold(given)
	s := fold(surname)

	if g == "" {
		return "", fmt.Errorf("given name %q has no usable characters after transliteration", given)
	}
	if s == "" {
		return "", fmt.Errorf("surname %q has no usable characters after transliteration", surname)
	}

	return Truncate(g[:1]+s, maxLen), nil
}

// Truncate shortens a username to fit maxLen while reserving room for the
// suffix Unique may need to append.
func Truncate(base string, maxLen int) string {
	room := maxLen - len(strconv.Itoa(MaxSuffix))
	if room < 1 {
		room = maxLen
	}
	if len(base) > room {
		return base[:room]
	}
	return base
}

// fold reduces a name fragment to lowercase ASCII letters and digits.
func fold(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			// Anything unmapped (spaces, apostrophes, hyphens, scripts we
			// cannot transliterate) is dropped.
			b.WriteString(translit[r])
		}
	}
	return b.String()
}

// Unique returns the first of base, base1, base2, ... that is not in taken.
//
// The caller supplies taken from a single directory search. That makes this a
// hint rather than a guarantee: two concurrent runs can agree on the same
// answer, so the entry add must still handle "already exists" by moving on to
// the next candidate.
func Unique(base string, taken map[string]bool, maxLen int) (string, error) {
	if !taken[base] {
		return base, nil
	}
	for n := 1; n <= MaxSuffix; n++ {
		if candidate := withSuffix(base, n, maxLen); !taken[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no free username for base %q after %d attempts", base, MaxSuffix)
}

// withSuffix appends n to base, trimming base so the result fits maxLen.
func withSuffix(base string, n, maxLen int) string {
	suffix := strconv.Itoa(n)
	stem := base
	if len(stem)+len(suffix) > maxLen {
		stem = stem[:maxLen-len(suffix)]
	}
	return stem + suffix
}

// Candidates lists usernames to try in order, so an add that loses a race can
// fall forward to the next one. The first element is the preferred name.
func Candidates(base string, taken map[string]bool, maxLen, count int) []string {
	local := make(map[string]bool, len(taken)+count)
	for k, v := range taken {
		local[k] = v
	}

	out := make([]string, 0, count)
	for len(out) < count {
		next, err := Unique(base, local, maxLen)
		if err != nil {
			break
		}
		out = append(out, next)
		local[next] = true
	}
	return out
}

// Valid reports whether a user-supplied username is usable as a POSIX login
// and safe to place in a DN without escaping surprises.
func Valid(name string, maxLen int) error {
	if name == "" {
		return fmt.Errorf("username is empty")
	}
	if len(name) > maxLen {
		return fmt.Errorf("username %q is longer than the %d character limit", name, maxLen)
	}
	if name[0] >= '0' && name[0] <= '9' {
		return fmt.Errorf("username %q must not start with a digit", name)
	}
	for _, r := range name {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_'
		if !ok {
			return fmt.Errorf("username %q contains %q; allowed characters are a-z, 0-9, dot, dash and underscore", name, r)
		}
	}
	return nil
}

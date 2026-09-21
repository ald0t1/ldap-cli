// Package secret generates the initial passwords handed to new accounts.
package secret

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// Character classes. Symbols are deliberately restricted to characters that
// survive a shell copy-paste and an LDIF round-trip without quoting, so an
// operator reading a password aloud or pasting it into a form does not get
// tripped up by quotes, backslashes or spaces.
const (
	lower   = "abcdefghijkmnopqrstuvwxyz" // no l
	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"  // no I, O
	digits  = "23456789"                  // no 0, 1
	symbols = "!#%&*+-=?@^_"
)

// MinLength is the shortest password Generate will produce. Four classes must
// each be represented, and anything shorter is not worth generating.
const MinLength = 12

var classes = []string{lower, upper, digits, symbols}

// Generate returns a random password of the requested length containing at
// least one character from each class.
//
// Lookalike characters (l, I, O, 0, 1) are excluded so a password read off a
// terminal and typed somewhere else arrives intact.
func Generate(length int) (string, error) {
	if length < MinLength {
		return "", fmt.Errorf("password length %d is below the minimum of %d", length, MinLength)
	}

	all := strings.Join(classes, "")
	out := make([]byte, 0, length)

	// Seed one character per class so the result always satisfies a policy
	// that demands all four, then fill the remainder from the union.
	for _, class := range classes {
		c, err := pick(class)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}
	for len(out) < length {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}

	// Without this the first four positions would leak the class order.
	if err := shuffle(out); err != nil {
		return "", err
	}
	return string(out), nil
}

// pick returns one uniformly random byte from set.
func pick(set string) (byte, error) {
	// crypto/rand.Int rejection-samples internally, so there is no modulo
	// bias from a set size that is not a power of two.
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, fmt.Errorf("read random source: %w", err)
	}
	return set[n.Int64()], nil
}

// shuffle performs a Fisher-Yates shuffle using the crypto random source.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("read random source: %w", err)
		}
		b[i], b[j.Int64()] = b[j.Int64()], b[i]
	}
	return nil
}

package username

import (
	"strconv"
	"strings"
	"testing"
)

const maxLen = 32

func TestGenerate(t *testing.T) {
	tests := []struct {
		given, surname, want string
	}{
		{"John", "Doe", "jdoe"},
		{"Jonathan", "Doe", "jdoe"}, // same base; Unique separates them
		{"john", "doe", "jdoe"},
		{"Zoë", "Ó'Brien", "zobrien"},
		{"José", "Núñez", "jnunez"},
		{"Jan", "van der Berg", "jvanderberg"},
		{"Anne-Marie", "Smith-Jones", "asmithjones"},
		{"Mary", "O'Connor", "moconnor"},
		// Ligatures and strokes have no Unicode decomposition; the explicit
		// table is what keeps these names intact.
		{"Jens", "Straße", "jstrasse"},
		{"Æsa", "Ærø", "aaero"},
		{"Þóra", "Þorsteinn", "tthorsteinn"},
		{"Lars", "Løkke", "llokke"},
		{"Đorđe", "Đukić", "ddukic"},
		{"J", "Doe2", "jdoe2"},
	}

	for _, tc := range tests {
		got, err := Generate(tc.given, tc.surname, maxLen)
		if err != nil {
			t.Errorf("Generate(%q, %q) errored: %v", tc.given, tc.surname, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Generate(%q, %q) = %q, want %q", tc.given, tc.surname, got, tc.want)
		}
	}
}

func TestGenerateRejectsUnusableNames(t *testing.T) {
	for _, tc := range []struct{ given, surname string }{
		{"John", ""},
		{"John", "!!!"},
		{"", "Doe"},
		{"...", "Doe"},
	} {
		if got, err := Generate(tc.given, tc.surname, maxLen); err == nil {
			t.Errorf("Generate(%q, %q) = %q, want an error", tc.given, tc.surname, got)
		}
	}
}

func TestGenerateLeavesRoomForSuffix(t *testing.T) {
	// A long surname must be cut short enough that a 3-digit suffix still
	// fits inside maxLen.
	long := strings.Repeat("a", 60)
	got, err := Generate("John", long, maxLen)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxLen-3 {
		t.Errorf("len(%q) = %d, want %d (maxLen minus suffix room)", got, len(got), maxLen-3)
	}
}

func TestUnique(t *testing.T) {
	tests := []struct {
		name  string
		taken []string
		want  string
	}{
		{"free", nil, "jdoe"},
		{"base taken", []string{"jdoe"}, "jdoe1"},
		{"base and 1 taken", []string{"jdoe", "jdoe1"}, "jdoe2"},
		{"gap is reused", []string{"jdoe", "jdoe2"}, "jdoe1"},
		// A longer login that merely starts with jdoe is a different user and
		// must not push jdoe aside.
		{"prefix match is not a collision", []string{"jdoesmith", "jdoerty"}, "jdoe"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			taken := map[string]bool{}
			for _, u := range tc.taken {
				taken[u] = true
			}
			got, err := Unique("jdoe", taken, maxLen)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Unique = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUniqueRespectsMaxLen(t *testing.T) {
	// When the base already fills maxLen, the suffix must replace trailing
	// characters instead of overflowing.
	base := strings.Repeat("a", maxLen)
	taken := map[string]bool{base: true}
	got, err := Unique(base, taken, maxLen)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > maxLen {
		t.Errorf("Unique = %q (len %d), want at most %d", got, len(got), maxLen)
	}
	if !strings.HasSuffix(got, "1") {
		t.Errorf("Unique = %q, want it to end with the suffix", got)
	}
}

func TestUniqueExhausted(t *testing.T) {
	taken := map[string]bool{"jdoe": true}
	for n := 1; n <= MaxSuffix; n++ {
		taken["jdoe"+strconv.Itoa(n)] = true
	}
	if _, err := Unique("jdoe", taken, maxLen); err == nil {
		t.Fatal("expected an error once every suffix is taken")
	}
}

func TestCandidates(t *testing.T) {
	taken := map[string]bool{"jdoe": true, "jdoe1": true}
	got := Candidates("jdoe", taken, maxLen, 3)
	want := []string{"jdoe2", "jdoe3", "jdoe4"}
	if len(got) != len(want) {
		t.Fatalf("Candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Candidates[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestValid(t *testing.T) {
	for _, ok := range []string{"jdoe", "j.doe", "j-doe", "j_doe", "jdoe1"} {
		if err := Valid(ok, maxLen); err != nil {
			t.Errorf("Valid(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "JDoe", "j doe", "j*doe", "1jdoe", strings.Repeat("a", maxLen+1), "jdoe,ou=x"} {
		if err := Valid(bad, maxLen); err == nil {
			t.Errorf("Valid(%q) = nil, want an error", bad)
		}
	}
}

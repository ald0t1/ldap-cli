package secret

import (
	"strings"
	"testing"
)

func TestGenerateLength(t *testing.T) {
	for _, n := range []int{12, 16, 24, 64, 200} {
		got, err := Generate(n)
		if err != nil {
			t.Fatalf("Generate(%d): %v", n, err)
		}
		if len(got) != n {
			t.Errorf("len(Generate(%d)) = %d, want %d", n, len(got), n)
		}
	}
}

func TestGenerateRejectsShortLengths(t *testing.T) {
	for _, n := range []int{0, 1, 11, -5} {
		if _, err := Generate(n); err == nil {
			t.Errorf("Generate(%d) = nil error, want a minimum-length error", n)
		}
	}
}

func TestGenerateAlwaysCoversEveryClass(t *testing.T) {
	// A password missing a class can be rejected by a server-side password
	// policy, so this must hold on every single generation, not on average.
	names := []string{"lower", "upper", "digits", "symbols"}
	for i := 0; i < 2000; i++ {
		got, err := Generate(MinLength)
		if err != nil {
			t.Fatal(err)
		}
		for c, class := range classes {
			if !strings.ContainsAny(got, class) {
				t.Fatalf("Generate() = %q, missing a %s character", got, names[c])
			}
		}
	}
}

func TestGenerateExcludesLookalikes(t *testing.T) {
	for i := 0; i < 500; i++ {
		got, err := Generate(32)
		if err != nil {
			t.Fatal(err)
		}
		if idx := strings.IndexAny(got, "lIO01"); idx >= 0 {
			t.Fatalf("Generate() = %q, contains lookalike %q", got, got[idx])
		}
	}
}

func TestGenerateIsUnpredictable(t *testing.T) {
	const runs = 1000
	seen := make(map[string]bool, runs)
	for i := 0; i < runs; i++ {
		got, err := Generate(16)
		if err != nil {
			t.Fatal(err)
		}
		if seen[got] {
			t.Fatalf("Generate() produced %q twice in %d runs", got, runs)
		}
		seen[got] = true
	}
}

func TestGenerateDoesNotLeakClassOrder(t *testing.T) {
	// The generator seeds one character per class before filling; if the
	// shuffle were skipped, position 0 would always be lowercase.
	var lowerFirst int
	const runs = 1000
	for i := 0; i < runs; i++ {
		got, err := Generate(MinLength)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsRune(lower, rune(got[0])) {
			lowerFirst++
		}
	}
	// Expected share is len(lower)/len(all) ~= 0.39; an unshuffled generator
	// would sit at 1.0. A generous band keeps this from flaking.
	if lowerFirst > runs*3/4 {
		t.Errorf("first character was lowercase %d/%d times; shuffle looks ineffective", lowerFirst, runs)
	}
}

func TestGenerateUsesFullAlphabet(t *testing.T) {
	// Every character in every class should be reachable. This catches an
	// off-by-one in the index range that would silently drop the last rune.
	all := strings.Join(classes, "")
	seen := map[rune]bool{}
	for i := 0; i < 5000; i++ {
		got, err := Generate(32)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range got {
			seen[r] = true
		}
	}
	for _, r := range all {
		if !seen[r] {
			t.Errorf("character %q was never generated", r)
		}
	}
}

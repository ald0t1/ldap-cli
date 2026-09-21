package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// prompter reads interactive answers for values not supplied as flags.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter() *prompter {
	// Prompts go to stderr so that piping stdout stays useful.
	return &prompter{in: bufio.NewReader(os.Stdin), out: os.Stderr}
}

// interactive reports whether there is a human to ask.
func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// ask requests a value, re-prompting until non-empty. def, when non-empty, is
// used if the answer is blank.
func (p *prompter) ask(label, def string) (string, error) {
	for {
		if def != "" {
			fmt.Fprintf(p.out, "%s [%s]: ", label, def)
		} else {
			fmt.Fprintf(p.out, "%s: ", label)
		}

		line, err := p.in.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read %s: %w", label, err)
		}

		answer := strings.TrimSpace(line)
		switch {
		case answer != "":
			return answer, nil
		case def != "":
			return def, nil
		}
		fmt.Fprintf(p.out, "  %s is required\n", label)
	}
}

// askOptional requests a value that may be left blank.
func (p *prompter) askOptional(label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(p.out, "%s (optional): ", label)
	}

	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read %s: %w", label, err)
	}

	if answer := strings.TrimSpace(line); answer != "" {
		return answer, nil
	}
	return def, nil
}

// confirm asks a yes/no question, defaulting to no.
func (p *prompter) confirm(label string) (bool, error) {
	fmt.Fprintf(p.out, "%s [y/N]: ", label)
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// requireFlag reports a missing value in a way that works for both humans and
// scripts: the flag name is always named, so a non-interactive run knows what
// to add.
func requireFlag(name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("--%s is required when stdin is not a terminal", name)
	}
	return nil
}

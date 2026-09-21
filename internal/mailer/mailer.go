// Package mailer sends new-account notifications.
//
// Two implementations satisfy Mailer: SMTP, used when mail.enabled is set in
// the config, and Noop, which reports that delivery is switched off. The
// provisioning path only ever sees the interface.
package mailer

import (
	"context"
	"fmt"
	"io"
)

// Notice is everything a welcome message would need.
//
// Password is the generated cleartext. It is in this struct because a welcome
// mail is the intended way to deliver it; any implementation must treat it as
// a secret and must not log it.
type Notice struct {
	Profile  string
	FullName string
	Email    string
	Username string
	DN       string
	Password string
}

// Mailer delivers account notifications.
type Mailer interface {
	SendWelcome(ctx context.Context, n Notice) error
}

// Noop is the current implementation: it reports that delivery is not
// configured rather than pretending to send anything.
type Noop struct {
	Out io.Writer
}

// SendWelcome announces that no mail was sent.
//
// It returns nil on purpose: mail being switched off is a configuration
// choice, not a failure, and it must not fail a provisioning run that
// otherwise succeeded.
func (n Noop) SendWelcome(_ context.Context, notice Notice) error {
	if n.Out == nil {
		return nil
	}
	to := notice.Email
	if to == "" {
		to = "(no address on the account)"
	}
	fmt.Fprintf(n.Out, "email: not sent to %s — set mail.enabled in the config to send\n", to)
	return nil
}

// Package mailer is where new-account notification email will live.
//
// Delivery is deliberately unimplemented for now. The interface and the call
// site exist so that adding a real transport later is one new type plus one
// wiring line in the CLI, with no change to the provisioning path.
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
// It returns nil on purpose: email is not yet wired up, and a hard error here
// would fail a provisioning run that otherwise fully succeeded.
func (n Noop) SendWelcome(_ context.Context, notice Notice) error {
	if n.Out == nil {
		return nil
	}
	to := notice.Email
	if to == "" {
		to = "(no address on the account)"
	}
	fmt.Fprintf(n.Out, "email: not sent to %s — delivery is not configured yet\n", to)
	return nil
}

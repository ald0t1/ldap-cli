package mailer

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"net/mail"
	"strings"
	"text/template"
	"time"
)

// Sensitivity values defined by RFC 2156. An empty setting omits the header,
// which is the normal case for ordinary mail.
const (
	SensitivityNone     = ""
	SensitivityPersonal = "personal"
	SensitivityPrivate  = "private"
	SensitivityCompany  = "company-confidential"
)

// sensitivityHeader maps our lowercase config values onto the exact header
// values the RFC defines. Clients match these case-insensitively but only
// recognise these three tokens.
var sensitivityHeader = map[string]string{
	SensitivityPersonal: "Personal",
	SensitivityPrivate:  "Private",
	SensitivityCompany:  "Company-Confidential",
}

// ValidSensitivity reports whether s is a usable sensitivity setting.
func ValidSensitivity(s string) bool {
	if s == SensitivityNone {
		return true
	}
	_, ok := sensitivityHeader[strings.ToLower(s)]
	return ok
}

// DefaultSubject is used when none is configured.
const DefaultSubject = "Your new account: {{.Username}}"

// DefaultBody is the welcome message. It is a text/template over Notice.
const DefaultBody = `Hello {{.FullName}},

An account has been created for you.

  Username:  {{.Username}}
  Email:     {{.Email}}
{{- if .Password}}
  Password:  {{.Password}}

Please sign in and change this password as soon as you can. It was generated
for you and is stored only as a hash on the server, so nobody can look it up
again — if it is lost it has to be reset.
{{- else}}

Your password has been set separately and is not included in this message.
{{- end}}

Regards,
Directory provisioning
`

// message is a rendered mail ready to hand to an SMTP server.
type message struct {
	from    string // envelope sender, address only
	rcpts   []string
	data    []byte
	subject string
}

// build renders a Notice into an RFC 5322 message.
//
// Encoding is not optional here: the name pools this tool deals with include
// people like "Ærø" and "Straße", and an un-encoded non-ASCII header or body
// produces mail that renders as mojibake or gets rejected outright.
func build(cfg Config, n Notice, now time.Time) (*message, error) {
	if n.Email == "" {
		return nil, fmt.Errorf("account %s has no email address to send to", n.Username)
	}

	fromAddr, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("mail.from %q is not a valid address: %w", cfg.From, err)
	}

	toAddr, err := mail.ParseAddress(n.Email)
	if err != nil {
		return nil, fmt.Errorf("account email %q is not a valid address: %w", n.Email, err)
	}

	// The password is only ever in the body if the operator opted in.
	view := n
	if !cfg.IncludePassword {
		view.Password = ""
	}

	subject, err := render("mail.subject", orDefault(cfg.Subject, DefaultSubject), view)
	if err != nil {
		return nil, err
	}
	body, err := render("mail.body", orDefault(cfg.Body, DefaultBody), view)
	if err != nil {
		return nil, err
	}

	msgID, err := messageID(fromAddr.Address)
	if err != nil {
		return nil, err
	}

	var h strings.Builder
	writeHeader(&h, "From", fromAddr.String())
	writeHeader(&h, "To", toAddr.String())
	writeHeader(&h, "Subject", mime.QEncoding.Encode("utf-8", subject))
	writeHeader(&h, "Date", now.Format(time.RFC1123Z))
	writeHeader(&h, "Message-ID", msgID)
	writeHeader(&h, "MIME-Version", "1.0")
	writeHeader(&h, "Content-Type", `text/plain; charset="utf-8"`)
	writeHeader(&h, "Content-Transfer-Encoding", "base64")

	// Tells well-behaved mail systems not to send vacation replies or
	// bounces back into a provisioning run.
	writeHeader(&h, "Auto-Submitted", "auto-generated")

	if v, ok := sensitivityHeader[strings.ToLower(cfg.Sensitivity)]; ok {
		writeHeader(&h, "Sensitivity", v)
	}
	for _, extra := range cfg.Headers {
		if name, value, found := strings.Cut(extra, ":"); found {
			writeHeader(&h, strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}

	var out strings.Builder
	out.WriteString(h.String())
	out.WriteString("\r\n")
	out.WriteString(wrapBase64(body))

	rcpts := append([]string{toAddr.Address}, cfg.BCC...)
	return &message{
		from:    fromAddr.Address,
		rcpts:   rcpts,
		data:    []byte(out.String()),
		subject: subject,
	}, nil
}

// writeHeader appends one header line with CRLF, as SMTP requires.
func writeHeader(b *strings.Builder, name, value string) {
	// Strip anything that could inject additional headers. Values here come
	// from config and from directory attributes, neither of which should be
	// able to add a Bcc. CRLF collapses to one space rather than two.
	value = strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ").Replace(value)
	fmt.Fprintf(b, "%s: %s\r\n", name, value)
}

// render expands a configured template over the notice.
func render(name, tmpl string, n Notice) (string, error) {
	t, err := template.New(name).Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid template: %w", name, err)
	}
	var b strings.Builder
	if err := t.Execute(&b, n); err != nil {
		return "", fmt.Errorf("render %s: %w", name, err)
	}
	return b.String(), nil
}

// wrapBase64 encodes a body and folds it to the 76-column SMTP limit.
func wrapBase64(body string) string {
	// CRLF line endings inside the body, per RFC 5322, before encoding.
	normalised := strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(normalised))

	var b strings.Builder
	for len(encoded) > 76 {
		b.WriteString(encoded[:76])
		b.WriteString("\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded)
	b.WriteString("\r\n")
	return b.String()
}

// messageID builds a globally unique id in the sender's domain.
func messageID(from string) (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate a Message-ID: %w", err)
	}

	domain := "ldap-cli.local"
	if _, d, ok := strings.Cut(from, "@"); ok && d != "" {
		domain = d
	}
	return fmt.Sprintf("<%s@%s>", hex.EncodeToString(buf[:]), domain), nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

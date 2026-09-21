package mailer

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 9, 21, 21, 30, 0, 0, time.UTC)

func baseConfig() Config {
	return Config{
		Enabled:         true,
		Host:            "mailhog",
		Port:            1025,
		From:            "Directory Provisioning <noreply@example.org>",
		Encryption:      EncryptionNone,
		IncludePassword: true,
	}
}

func baseNotice() Notice {
	return Notice{
		Profile:  "dev",
		FullName: "John Doe",
		Email:    "jdoe@example.org",
		Username: "jdoe",
		DN:       "uid=jdoe,ou=people,dc=example,dc=org",
		Password: "xK7#mPq2vLz9",
	}
}

// decodeBody pulls the base64 body back out of a rendered message.
func decodeBody(t *testing.T, data []byte) string {
	t.Helper()
	_, body, found := strings.Cut(string(data), "\r\n\r\n")
	if !found {
		t.Fatalf("no header/body separator in:\n%s", data)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
	if err != nil {
		t.Fatalf("body is not valid base64: %v", err)
	}
	return string(decoded)
}

func TestBuildHeaders(t *testing.T) {
	msg, err := build(baseConfig(), baseNotice(), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	head := string(msg.data)

	for _, want := range []string{
		"From: \"Directory Provisioning\" <noreply@example.org>\r\n",
		"To: <jdoe@example.org>\r\n",
		"Subject: Your new account: jdoe\r\n",
		"Date: Mon, 21 Sep 2026 21:30:00 +0000\r\n",
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/plain; charset=\"utf-8\"\r\n",
		"Content-Transfer-Encoding: base64\r\n",
		// Keeps vacation replies and bounces out of a provisioning run.
		"Auto-Submitted: auto-generated\r\n",
	} {
		if !strings.Contains(head, want) {
			t.Errorf("missing header %q in:\n%s", want, head)
		}
	}

	if msg.from != "noreply@example.org" {
		t.Errorf("envelope sender = %q, want the bare address", msg.from)
	}
	if len(msg.rcpts) != 1 || msg.rcpts[0] != "jdoe@example.org" {
		t.Errorf("recipients = %v", msg.rcpts)
	}
	if !strings.Contains(head, "@example.org>") || !strings.Contains(head, "Message-ID: <") {
		t.Errorf("Message-ID should be in the sender's domain:\n%s", head)
	}
}

func TestBuildSensitivity(t *testing.T) {
	tests := []struct {
		setting string
		want    string
	}{
		{"", ""},
		{"personal", "Sensitivity: Personal\r\n"},
		{"private", "Sensitivity: Private\r\n"},
		{"company-confidential", "Sensitivity: Company-Confidential\r\n"},
		// Config values are lowercase by convention but must not be
		// case-sensitive.
		{"Company-Confidential", "Sensitivity: Company-Confidential\r\n"},
	}

	for _, tc := range tests {
		cfg := baseConfig()
		cfg.Sensitivity = tc.setting

		msg, err := build(cfg, baseNotice(), fixedTime)
		if err != nil {
			t.Fatalf("sensitivity %q: %v", tc.setting, err)
		}
		head := string(msg.data)

		if tc.want == "" {
			if strings.Contains(head, "Sensitivity:") {
				t.Errorf("sensitivity %q should omit the header entirely", tc.setting)
			}
			continue
		}
		if !strings.Contains(head, tc.want) {
			t.Errorf("sensitivity %q: missing %q", tc.setting, tc.want)
		}
	}
}

func TestValidSensitivity(t *testing.T) {
	for _, ok := range []string{"", "personal", "private", "company-confidential", "PRIVATE"} {
		if !ValidSensitivity(ok) {
			t.Errorf("ValidSensitivity(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"confidential", "secret", "high", "normal"} {
		if ValidSensitivity(bad) {
			t.Errorf("ValidSensitivity(%q) = true, want false", bad)
		}
	}
}

func TestBuildIncludePassword(t *testing.T) {
	cfg := baseConfig()
	cfg.IncludePassword = true
	msg, err := build(cfg, baseNotice(), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if body := decodeBody(t, msg.data); !strings.Contains(body, "xK7#mPq2vLz9") {
		t.Errorf("password should appear when include_password is on:\n%s", body)
	}

	cfg.IncludePassword = false
	msg, err = build(cfg, baseNotice(), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	body := decodeBody(t, msg.data)
	if strings.Contains(body, "xK7#mPq2vLz9") {
		t.Errorf("password must not leak when include_password is off:\n%s", body)
	}
	if !strings.Contains(body, "set separately") {
		t.Errorf("body should explain the password is elsewhere:\n%s", body)
	}
}

func TestBuildEncodesNonASCII(t *testing.T) {
	// The directory really does contain these names; an unencoded header or
	// body produces mail that renders as mojibake or is rejected.
	n := baseNotice()
	n.FullName = "Þóra Ærø"
	n.Username = "taero"

	cfg := baseConfig()
	cfg.Subject = "Konto for {{.FullName}}"

	msg, err := build(cfg, n, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(string(msg.data), "\r\n\r\n")

	// Raw UTF-8 must never appear in a header.
	if strings.Contains(head, "Þóra") {
		t.Errorf("subject was not RFC 2047 encoded:\n%s", head)
	}
	if !strings.Contains(head, "=?utf-8?q?") && !strings.Contains(head, "=?utf-8?b?") {
		t.Errorf("expected an encoded-word subject:\n%s", head)
	}
	// The body is base64, so the name survives a round trip intact.
	if body := decodeBody(t, msg.data); !strings.Contains(body, "Þóra Ærø") {
		t.Errorf("body lost the name:\n%s", body)
	}
}

func TestBuildRejectsHeaderInjection(t *testing.T) {
	// Values reach here from config and from directory attributes; neither
	// should be able to add a Bcc or forge headers.
	n := baseNotice()
	n.Username = "jdoe\r\nBcc: attacker@evil.test"

	msg, err := build(baseConfig(), n, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(string(msg.data), "\r\n\r\n")

	// What matters is that no new header *line* appeared. The injected text
	// surviving inside an encoded-word (as =0D=0A) is inert, so checking for
	// the substring anywhere would flag a defence that is working.
	for _, line := range strings.Split(head, "\r\n") {
		name, _, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "bcc") {
			t.Errorf("an injected Bcc header line got through:\n%s", head)
		}
	}

	// And the recipient list is still just the intended one.
	if len(msg.rcpts) != 1 || msg.rcpts[0] != "jdoe@example.org" {
		t.Errorf("recipients = %v, want only the account address", msg.rcpts)
	}
}

func TestWriteHeaderNeutralisesLineBreaks(t *testing.T) {
	// A value that reaches writeHeader with raw CRLF must not become two
	// header lines. This is the backstop for any header not passed through
	// RFC 2047 encoding first.
	var b strings.Builder
	writeHeader(&b, "X-Test", "value\r\nBcc: attacker@evil.test")

	got := b.String()
	if n := strings.Count(got, "\r\n"); n != 1 {
		t.Errorf("produced %d line breaks, want 1: %q", n, got)
	}
	if !strings.HasPrefix(got, "X-Test: value Bcc: attacker@evil.test") {
		t.Errorf("unexpected folding: %q", got)
	}
}

func TestBuildBCCIsEnvelopeOnly(t *testing.T) {
	cfg := baseConfig()
	cfg.BCC = []string{"audit@example.org"}

	msg, err := build(cfg, baseNotice(), fixedTime)
	if err != nil {
		t.Fatal(err)
	}

	if len(msg.rcpts) != 2 || msg.rcpts[1] != "audit@example.org" {
		t.Errorf("recipients = %v, want the bcc added", msg.rcpts)
	}
	// A Bcc that appears in the headers is not blind.
	if strings.Contains(string(msg.data), "audit@example.org") {
		t.Error("the bcc address leaked into the message headers")
	}
}

func TestBuildCustomTemplates(t *testing.T) {
	cfg := baseConfig()
	cfg.Subject = "[{{.Profile}}] account {{.Username}}"
	cfg.Body = "DN is {{.DN}} for {{.FullName}}."

	msg, err := build(cfg, baseNotice(), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(msg.data), "Subject: [dev] account jdoe") {
		t.Errorf("custom subject not applied:\n%s", msg.data)
	}
	if body := decodeBody(t, msg.data); body != "DN is uid=jdoe,ou=people,dc=example,dc=org for John Doe." {
		t.Errorf("custom body = %q", body)
	}
}

func TestBuildErrors(t *testing.T) {
	t.Run("no recipient", func(t *testing.T) {
		n := baseNotice()
		n.Email = ""
		if _, err := build(baseConfig(), n, fixedTime); err == nil {
			t.Error("expected an error with no email address")
		}
	})

	t.Run("bad from", func(t *testing.T) {
		cfg := baseConfig()
		cfg.From = "not an address"
		if _, err := build(cfg, baseNotice(), fixedTime); err == nil {
			t.Error("expected an error for an unparseable mail.from")
		}
	})

	t.Run("bad template", func(t *testing.T) {
		cfg := baseConfig()
		cfg.Subject = "{{.Nope"
		if _, err := build(cfg, baseNotice(), fixedTime); err == nil {
			t.Error("expected an error for a malformed template")
		}
	})
}

func TestBuildFoldsLongBodyLines(t *testing.T) {
	cfg := baseConfig()
	cfg.Body = strings.Repeat("abcdefghij", 50)

	msg, err := build(cfg, baseNotice(), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := strings.Cut(string(msg.data), "\r\n\r\n")
	for _, line := range strings.Split(strings.TrimRight(body, "\r\n"), "\r\n") {
		if len(line) > 76 {
			t.Fatalf("body line is %d chars, over the 76 limit", len(line))
		}
	}
	// And it still decodes to the original.
	if decodeBody(t, msg.data) != cfg.Body {
		t.Error("folding corrupted the body")
	}
}

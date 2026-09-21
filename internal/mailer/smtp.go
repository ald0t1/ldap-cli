package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Transport security modes for the SMTP connection.
const (
	// EncryptionNone is plaintext, for a local dev sink like MailHog.
	EncryptionNone = "none"
	// EncryptionStartTLS upgrades a plaintext connection, the usual choice
	// for port 587.
	EncryptionStartTLS = "starttls"
	// EncryptionTLS opens TLS immediately, the usual choice for port 465.
	EncryptionTLS = "tls"
)

// DefaultTimeout bounds the whole send.
const DefaultTimeout = 10 * time.Second

// Config describes how and what to send.
type Config struct {
	Enabled bool `yaml:"enabled"`

	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	From string `yaml:"from"`

	Encryption         string `yaml:"encryption"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`

	Username string `yaml:"username"`

	// Password is the SMTP password held directly in the config file. Simple,
	// and fine when the file is already the trusted place for this — but it
	// does mean the file needs 0600 and must stay out of version control.
	Password string `yaml:"password"`

	// PasswordEnv names an environment variable to read the password from
	// instead, for setups that keep secrets out of files. It takes precedence
	// over Password when both are set.
	PasswordEnv string `yaml:"password_env"`

	Subject string   `yaml:"subject"`
	Body    string   `yaml:"body"`
	BCC     []string `yaml:"bcc"`
	Headers []string `yaml:"headers"`

	// Sensitivity sets the RFC 2156 header: personal, private or
	// company-confidential. Empty omits it.
	Sensitivity string `yaml:"sensitivity"`

	// IncludePassword controls whether the generated password appears in the
	// message at all.
	IncludePassword bool `yaml:"include_password"`

	Timeout time.Duration `yaml:"timeout"`

	// HELO name; defaults to the local hostname.
	HeloName string `yaml:"helo_name"`
}

// Addr is the host:port to dial.
func (c Config) Addr() string {
	return net.JoinHostPort(c.Host, fmt.Sprint(c.Port))
}

// Validate reports configuration problems, all of them at once.
func (c Config) Validate() []string {
	var probs []string
	if !c.Enabled {
		return nil
	}

	if c.Host == "" {
		probs = append(probs, "mail.host is required when mail.enabled is true")
	}
	if c.Port <= 0 || c.Port > 65535 {
		probs = append(probs, fmt.Sprintf("mail.port %d is not a valid port", c.Port))
	}
	if c.From == "" {
		probs = append(probs, "mail.from is required when mail.enabled is true")
	}

	switch strings.ToLower(c.Encryption) {
	case "", EncryptionNone, EncryptionStartTLS, EncryptionTLS:
	default:
		probs = append(probs, fmt.Sprintf(
			"mail.encryption %q must be one of none, starttls or tls", c.Encryption))
	}

	if !ValidSensitivity(c.Sensitivity) {
		probs = append(probs, fmt.Sprintf(
			"mail.sensitivity %q must be one of personal, private or company-confidential (or empty)",
			c.Sensitivity))
	}

	// Credentials in the clear would be sent on every message, so this is a
	// hard error rather than a warning.
	if c.Username != "" && strings.ToLower(c.Encryption) == EncryptionNone {
		probs = append(probs,
			"mail.username is set but mail.encryption is none; SMTP auth would send the password in the clear")
	}
	if c.InsecureSkipVerify && strings.ToLower(c.Encryption) == EncryptionNone {
		probs = append(probs, "mail.insecure_skip_verify has no effect when mail.encryption is none")
	}

	// Catch a username with no way to get a password at config time, rather
	// than failing mid-send after the account has already been created.
	if c.Username != "" && c.Password == "" && c.PasswordEnv == "" {
		probs = append(probs,
			"mail.username is set but neither mail.password nor mail.password_env provides a password")
	}
	if c.Password != "" && c.PasswordEnv != "" {
		probs = append(probs,
			"mail.password and mail.password_env are both set; password_env wins, so remove one")
	}

	for _, h := range c.Headers {
		if !strings.Contains(h, ":") {
			probs = append(probs, fmt.Sprintf("mail.headers entry %q must be in \"Name: value\" form", h))
		}
	}
	return probs
}

// SMTP delivers notifications over SMTP.
type SMTP struct {
	cfg Config
	// now is injectable so tests can assert on the Date header.
	now func() time.Time
}

// NewSMTP builds a mailer from config.
func NewSMTP(cfg Config) *SMTP {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Encryption == "" {
		cfg.Encryption = EncryptionNone
	}
	return &SMTP{cfg: cfg, now: time.Now}
}

// SendWelcome renders and delivers the new-account message.
func (s *SMTP) SendWelcome(ctx context.Context, n Notice) error {
	msg, err := build(s.cfg, n, s.now())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	if err := s.send(ctx, msg); err != nil {
		return fmt.Errorf("send the welcome message to %s via %s: %w", n.Email, s.cfg.Addr(), err)
	}
	return nil
}

func (s *SMTP) send(ctx context.Context, msg *message) error {
	conn, err := s.dial(ctx)
	if err != nil {
		return err
	}

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("start the SMTP session: %w", err)
	}
	defer client.Close()

	helo := s.cfg.HeloName
	if helo == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			helo = h
		} else {
			helo = "localhost"
		}
	}
	if err := client.Hello(helo); err != nil {
		return fmt.Errorf("HELO as %q: %w", helo, err)
	}

	if strings.EqualFold(s.cfg.Encryption, EncryptionStartTLS) {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return fmt.Errorf("mail.encryption is starttls but %s does not advertise STARTTLS", s.cfg.Addr())
		}
		if err := client.StartTLS(s.tlsConfig()); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}

	if err := s.authenticate(client); err != nil {
		return err
	}

	if err := client.Mail(msg.from); err != nil {
		return fmt.Errorf("MAIL FROM %s: %w", msg.from, err)
	}
	for _, rcpt := range msg.rcpts {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", rcpt, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg.data); err != nil {
		return fmt.Errorf("write the message body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finish the message: %w", err)
	}
	return client.Quit()
}

// dial opens the connection, honouring the context deadline.
func (s *SMTP) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{}

	if strings.EqualFold(s.cfg.Encryption, EncryptionTLS) {
		conn, err := (&tls.Dialer{NetDialer: d, Config: s.tlsConfig()}).DialContext(ctx, "tcp", s.cfg.Addr())
		if err != nil {
			return nil, fmt.Errorf("connect to %s over TLS: %w", s.cfg.Addr(), err)
		}
		return conn, nil
	}

	conn, err := d.DialContext(ctx, "tcp", s.cfg.Addr())
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", s.cfg.Addr(), err)
	}
	return conn, nil
}

func (s *SMTP) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         s.cfg.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: s.cfg.InsecureSkipVerify,
	}
}

// password resolves the SMTP password: the environment variable when one is
// named, otherwise the value from the config file.
func (s *SMTP) password() (string, error) {
	if s.cfg.PasswordEnv != "" {
		v := os.Getenv(s.cfg.PasswordEnv)
		if v == "" {
			return "", fmt.Errorf("mail.password_env names %s but that variable is empty", s.cfg.PasswordEnv)
		}
		return v, nil
	}
	return s.cfg.Password, nil
}

// authenticate performs SMTP AUTH when a username is configured.
func (s *SMTP) authenticate(client *smtp.Client) error {
	if s.cfg.Username == "" {
		return nil
	}

	password, err := s.password()
	if err != nil {
		return err
	}

	if ok, _ := client.Extension("AUTH"); !ok {
		return fmt.Errorf("mail.username is set but %s does not advertise AUTH", s.cfg.Addr())
	}

	// net/smtp refuses PLAIN over an unencrypted link, which is the correct
	// behaviour; surface it as configuration advice rather than a raw error.
	auth := smtp.PlainAuth("", s.cfg.Username, password, s.cfg.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("authenticate as %s (set mail.encryption to starttls or tls if this is a TLS complaint): %w",
			s.cfg.Username, err)
	}
	return nil
}

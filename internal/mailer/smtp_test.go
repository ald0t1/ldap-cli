package mailer

import (
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"disabled skips every check", func(c *Config) { c.Enabled = false; c.Host = ""; c.From = "" }, ""},
		{"host required", func(c *Config) { c.Host = "" }, "mail.host is required"},
		{"from required", func(c *Config) { c.From = "" }, "mail.from is required"},
		{"port range", func(c *Config) { c.Port = 0 }, "is not a valid port"},
		{"bad encryption", func(c *Config) { c.Encryption = "ssl" }, "must be one of none, starttls or tls"},
		{"bad sensitivity", func(c *Config) { c.Sensitivity = "top-secret" }, "mail.sensitivity"},
		{"header form", func(c *Config) { c.Headers = []string{"nope"} }, `must be in "Name: value" form`},
		{
			// Auth over a cleartext link would send the password on every
			// message, so this is an error rather than a warning.
			name: "auth without encryption",
			edit: func(c *Config) { c.Username = "bot@corp.com"; c.Encryption = EncryptionNone },
			want: "would send the password in the clear",
		},
		{
			name: "skip verify without encryption",
			edit: func(c *Config) { c.InsecureSkipVerify = true; c.Encryption = EncryptionNone },
			want: "has no effect",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			tc.edit(&cfg)
			probs := cfg.Validate()

			if tc.want == "" {
				if len(probs) != 0 {
					t.Fatalf("expected no problems, got %v", probs)
				}
				return
			}
			if !strings.Contains(strings.Join(probs, "\n"), tc.want) {
				t.Errorf("problems = %v, want one containing %q", probs, tc.want)
			}
		})
	}
}

func TestConfigValidateAcceptsRealRelaySettings(t *testing.T) {
	// Both ways of supplying the password are legitimate: in the file, or
	// from the environment.
	for name, creds := range map[string]Config{
		"password in the config file": {Password: "s3cret"},
		"password from the env":       {PasswordEnv: "LDAP_CLI_SMTP_PASSWORD"},
	} {
		cfg := Config{
			Enabled:     true,
			Host:        "smtp.corp.com",
			Port:        587,
			From:        "ldap-cli@corp.com",
			Encryption:  EncryptionStartTLS,
			Username:    "ldap-cli@corp.com",
			Password:    creds.Password,
			PasswordEnv: creds.PasswordEnv,
			Sensitivity: SensitivityCompany,
		}
		if probs := cfg.Validate(); len(probs) != 0 {
			t.Errorf("%s should validate, got %v", name, probs)
		}
	}
}

func TestConfigValidateCredentialProblems(t *testing.T) {
	base := func() Config {
		c := baseConfig()
		c.Encryption = EncryptionStartTLS
		c.Username = "bot@corp.com"
		return c
	}

	t.Run("username with no password", func(t *testing.T) {
		probs := strings.Join(base().Validate(), "\n")
		if !strings.Contains(probs, "neither mail.password nor mail.password_env") {
			t.Errorf("problems = %q", probs)
		}
	})

	t.Run("both password sources set", func(t *testing.T) {
		c := base()
		c.Password = "s3cret"
		c.PasswordEnv = "LDAP_CLI_SMTP_PASSWORD"
		probs := strings.Join(c.Validate(), "\n")
		if !strings.Contains(probs, "both set") {
			t.Errorf("problems = %q", probs)
		}
	})
}

func TestPasswordResolution(t *testing.T) {
	t.Run("from the config file", func(t *testing.T) {
		s := NewSMTP(Config{Password: "from-file"})
		got, err := s.password()
		if err != nil || got != "from-file" {
			t.Errorf("password = %q, err = %v", got, err)
		}
	})

	t.Run("env wins over the file", func(t *testing.T) {
		t.Setenv("TEST_SMTP_PW", "from-env")
		s := NewSMTP(Config{Password: "from-file", PasswordEnv: "TEST_SMTP_PW"})
		got, err := s.password()
		if err != nil || got != "from-env" {
			t.Errorf("password = %q, err = %v", got, err)
		}
	})

	t.Run("named env var is empty", func(t *testing.T) {
		// Silently falling back to the file would mask a deployment mistake.
		s := NewSMTP(Config{Password: "from-file", PasswordEnv: "TEST_SMTP_PW_UNSET"})
		if _, err := s.password(); err == nil {
			t.Error("expected an error when the named variable is empty")
		}
	})
}

func TestNewSMTPDefaults(t *testing.T) {
	s := NewSMTP(Config{Host: "mailhog", Port: 1025})
	if s.cfg.Timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", s.cfg.Timeout, DefaultTimeout)
	}
	if s.cfg.Encryption != EncryptionNone {
		t.Errorf("encryption = %q, want none", s.cfg.Encryption)
	}
}

func TestConfigAddr(t *testing.T) {
	if got := (Config{Host: "mailhog", Port: 1025}).Addr(); got != "mailhog:1025" {
		t.Errorf("Addr = %q", got)
	}
	// IPv6 literals have to come back bracketed or the dial fails.
	if got := (Config{Host: "::1", Port: 25}).Addr(); got != "[::1]:25" {
		t.Errorf("Addr = %q, want a bracketed IPv6 host", got)
	}
}

func TestSendWelcomeFailsWithoutRecipient(t *testing.T) {
	// Must fail during render, before any connection is attempted.
	s := NewSMTP(baseConfig())
	n := baseNotice()
	n.Email = ""

	if err := s.SendWelcome(nil, n); err == nil {
		t.Fatal("expected an error with no email address")
	}
}

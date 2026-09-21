package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimal is a valid single-profile config; tests mutate one field at a time
// so each validation rule is exercised in isolation.
const minimal = `
profiles:
  dev:
    url: ldap://localhost:389
    allow_insecure_bind: true
    bind_dn: cn=admin,dc=example,dc=org
    user_base_dn: ou=people,dc=example,dc=org
    group_base_dn: ou=groups,dc=example,dc=org
    uid: {min: 10000, max: 60000}
    gid: {min: 20000, max: 60000}
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ldap-cli.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadExampleConfig(t *testing.T) {
	// The shipped sample must stay loadable as-is, including the prod profile
	// whose CA file only exists on a real server.
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(writeConfig(t, string(raw)))
	if err != nil {
		t.Fatalf("example config should load: %v", err)
	}
	if got := cfg.ProfileNames(); len(got) != 2 {
		t.Fatalf("profiles = %v, want 2", got)
	}

	p, err := cfg.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "dev" {
		t.Errorf("default profile = %q, want dev", p.Name)
	}
	if p.UserRDNAttr != "uid" || p.LoginShell != DefaultLoginShell || p.PasswordLength != 16 {
		t.Errorf("defaults not applied: %+v", p)
	}
}

func TestDefaultPathsPrecedence(t *testing.T) {
	t.Setenv("LDAP_CLI_CONFIG", "/explicit/from-env.yaml")
	t.Setenv("XDG_CONFIG_HOME", "/xdg")

	got := DefaultPaths()

	// The env override must be consulted first and the machine-wide file last,
	// so a single admin can override a shared profile set.
	if got[0] != "/explicit/from-env.yaml" {
		t.Errorf("first path = %q, want the env override", got[0])
	}
	if last := got[len(got)-1]; last != SystemPath {
		t.Errorf("last path = %q, want %q", last, SystemPath)
	}

	indexOf := func(want string) int {
		for i, p := range got {
			if p == want {
				return i
			}
		}
		return -1
	}
	cwd := indexOf("ldap-cli.yaml")
	xdg := indexOf("/xdg/ldap-cli/config.yaml")
	if cwd < 0 || xdg < 0 {
		t.Fatalf("expected both the cwd and XDG paths, got %v", got)
	}
	if !(cwd < xdg && xdg < len(got)-1) {
		t.Errorf("expected cwd < xdg < system ordering, got %v", got)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// A typo'd key is a silent misconfiguration otherwise.
	body := strings.Replace(minimal, "bind_dn:", "bnid_dn:", 1)
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("expected an error for an unknown field")
	}
}

func TestValidateRejections(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{
			name: "missing url",
			edit: func(s string) string { return strings.Replace(s, "url: ldap://localhost:389", "url:", 1) },
			want: "url is required",
		},
		{
			name: "bad scheme",
			edit: func(s string) string { return strings.Replace(s, "ldap://localhost:389", "http://localhost", 1) },
			want: "must be ldap or ldaps",
		},
		{
			name: "missing bind_dn",
			edit: func(s string) string {
				return strings.Replace(s, "bind_dn: cn=admin,dc=example,dc=org", "bind_dn:", 1)
			},
			want: "bind_dn is required",
		},
		{
			name: "missing group_base_dn",
			edit: func(s string) string {
				return strings.Replace(s, "group_base_dn: ou=groups,dc=example,dc=org", "group_base_dn:", 1)
			},
			want: "group_base_dn is required",
		},
		{
			name: "max not above min",
			edit: func(s string) string {
				return strings.Replace(s, "uid: {min: 10000, max: 60000}", "uid: {min: 10000, max: 10000}", 1)
			},
			want: "uid.max (10000) must be greater than uid.min (10000)",
		},
		{
			name: "next_attr without next_dn",
			edit: func(s string) string {
				return strings.Replace(s, "uid: {min: 10000, max: 60000}",
					"uid: {min: 10000, max: 60000, next_attr: uidNumber}", 1)
			},
			want: "uid.next_attr is set but uid.next_dn is empty",
		},
		{
			name: "insecure_skip_verify with ca_cert",
			edit: func(s string) string {
				return strings.Replace(s, "allow_insecure_bind: true",
					"insecure_skip_verify: true\n    ca_cert: /etc/ssl/some-ca.pem", 1)
			},
			want: "contradictory",
		},
		{
			name: "password too short",
			edit: func(s string) string {
				return strings.Replace(s, "allow_insecure_bind: true", "password_length: 8", 1)
			},
			want: "below the minimum of 12",
		},
		{
			name: "home_template without username",
			edit: func(s string) string {
				return strings.Replace(s, "allow_insecure_bind: true", "home_template: /home/shared", 1)
			},
			want: "must contain {{.Username}}",
		},
		{
			name: "unknown default_profile",
			edit: func(s string) string { return "default_profile: staging\n" + s },
			want: `default_profile "staging" is not a defined profile`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.edit(minimal)))
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v\nwant it to contain %q", err, tc.want)
			}
		})
	}
}

func TestValidateRejectsStartTLSWithLDAPS(t *testing.T) {
	body := strings.Replace(minimal, "url: ldap://localhost:389",
		"url: ldaps://localhost:636\n    start_tls: true", 1)
	_, err := Load(writeConfig(t, body))
	if err == nil || !strings.Contains(err.Error(), "start_tls cannot be used with an ldaps:// url") {
		t.Fatalf("err = %v, want a start_tls/ldaps conflict", err)
	}
}

func TestResolve(t *testing.T) {
	// One profile and no default: it is unambiguous, so resolve it.
	cfg, err := Load(writeConfig(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	p, err := cfg.Resolve("")
	if err != nil {
		t.Fatalf("single profile should resolve without a default: %v", err)
	}
	if p.Name != "dev" {
		t.Errorf("name = %q, want dev", p.Name)
	}

	if _, err := cfg.Resolve("prod"); err == nil {
		t.Error("expected an error for an unknown profile")
	} else if !strings.Contains(err.Error(), "have: dev") {
		t.Errorf("error should list known profiles, got: %v", err)
	}
}

func TestResolveAmbiguousWithoutDefault(t *testing.T) {
	body := minimal + `
  prod:
    url: ldaps://ldap.corp.com:636
    bind_dn: cn=manager,dc=corp,dc=com
    user_base_dn: ou=people,dc=corp,dc=com
    group_base_dn: ou=groups,dc=corp,dc=com
    uid: {min: 10000, max: 60000}
    gid: {min: 20000, max: 60000}
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Resolve(""); err == nil {
		t.Fatal("two profiles and no default should require --profile")
	}
}

func TestHomeDirAndEncrypted(t *testing.T) {
	p := &Profile{HomeTemplate: "/export/home/{{.Username}}", URL: "ldap://x:389"}
	got, err := p.HomeDir("jdoe")
	if err != nil {
		t.Fatal(err)
	}
	if want := "/export/home/jdoe"; got != want {
		t.Errorf("HomeDir = %q, want %q", got, want)
	}

	for _, tc := range []struct {
		url      string
		startTLS bool
		want     bool
	}{
		{"ldap://x:389", false, false},
		{"ldap://x:389", true, true},
		{"ldaps://x:636", false, true},
		{"LDAPS://x:636", false, true},
	} {
		p := &Profile{URL: tc.url, StartTLS: tc.startTLS}
		if got := p.Encrypted(); got != tc.want {
			t.Errorf("Encrypted(%s, startTLS=%v) = %v, want %v", tc.url, tc.startTLS, got, tc.want)
		}
	}
}

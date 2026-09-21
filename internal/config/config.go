// Package config loads and validates the profile file that tells ldap-cli how
// to reach each OpenLDAP server.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// Defaults applied when a profile leaves a field empty.
const (
	DefaultUserRDNAttr    = "uid"
	DefaultLoginShell     = "/bin/bash"
	DefaultHomeTemplate   = "/home/{{.Username}}"
	DefaultUsernameMaxLen = 32
	DefaultPasswordLength = 16
	MinPasswordLength     = 12
	MinUsernameMaxLen     = 3
)

// Range describes how numeric ids are handed out for either users or groups.
//
// NextDN is optional: when set, that entry holds a counter which is claimed
// atomically. The directory is scanned either way, and the scan result acts as
// a floor, so a stale or restored counter can never reissue a live id.
type Range struct {
	Min      int    `yaml:"min"`
	Max      int    `yaml:"max"`
	NextDN   string `yaml:"next_dn"`
	NextAttr string `yaml:"next_attr"`
}

// Profile is everything needed to talk to one server.
type Profile struct {
	// Name is filled in from the map key by Load; it is not read from YAML.
	Name string `yaml:"-"`

	URL                string `yaml:"url"`
	StartTLS           bool   `yaml:"start_tls"`
	CACert             string `yaml:"ca_cert"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	AllowInsecureBind  bool   `yaml:"allow_insecure_bind"`

	BindDN      string `yaml:"bind_dn"`
	UserBaseDN  string `yaml:"user_base_dn"`
	GroupBaseDN string `yaml:"group_base_dn"`

	UserRDNAttr            string   `yaml:"user_rdn_attr"`
	DefaultPrimaryGroup    string   `yaml:"default_primary_group"`
	LoginShell             string   `yaml:"login_shell"`
	HomeTemplate           string   `yaml:"home_template"`
	MailDomain             string   `yaml:"mail_domain"`
	ExtraUserObjectClasses []string `yaml:"extra_user_object_classes"`
	UsernameMaxLength      int      `yaml:"username_max_length"`
	PasswordLength         int      `yaml:"password_length"`

	UID Range `yaml:"uid"`
	GID Range `yaml:"gid"`
}

// Config is the whole file.
type Config struct {
	DefaultProfile string              `yaml:"default_profile"`
	Profiles       map[string]*Profile `yaml:"profiles"`

	// Path records where this config was read from, for error messages.
	Path string `yaml:"-"`
}

// Load reads and validates a config file. An empty path triggers the search
// order documented in DefaultPaths.
func Load(path string) (*Config, error) {
	if path == "" {
		found, err := discover()
		if err != nil {
			return nil, err
		}
		path = found
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.Path = path

	for name, p := range cfg.Profiles {
		p.Name = name
		p.applyDefaults()
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

// DefaultPaths lists, in order, where Load looks when given no explicit path.
func DefaultPaths() []string {
	var paths []string
	if env := os.Getenv("LDAP_CLI_CONFIG"); env != "" {
		paths = append(paths, env)
	}
	paths = append(paths, "ldap-cli.yaml", "ldap-cli.yml")
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "ldap-cli", "config.yaml"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "ldap-cli", "config.yaml"))
	}
	return paths
}

func discover() (string, error) {
	candidates := DefaultPaths()
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("no config file found; looked in %s (use --config)", strings.Join(candidates, ", "))
}

func (p *Profile) applyDefaults() {
	if p.UserRDNAttr == "" {
		p.UserRDNAttr = DefaultUserRDNAttr
	}
	if p.LoginShell == "" {
		p.LoginShell = DefaultLoginShell
	}
	if p.HomeTemplate == "" {
		p.HomeTemplate = DefaultHomeTemplate
	}
	if p.UsernameMaxLength == 0 {
		p.UsernameMaxLength = DefaultUsernameMaxLen
	}
	if p.PasswordLength == 0 {
		p.PasswordLength = DefaultPasswordLength
	}
	if p.UID.NextDN != "" && p.UID.NextAttr == "" {
		p.UID.NextAttr = "uidNumber"
	}
	if p.GID.NextDN != "" && p.GID.NextAttr == "" {
		p.GID.NextAttr = "gidNumber"
	}
}

// Validate checks the whole file. It reports every problem it finds rather
// than stopping at the first, so a misconfigured file can be fixed in one pass.
func (c *Config) Validate() error {
	if len(c.Profiles) == 0 {
		return errors.New("no profiles defined")
	}

	var problems []string
	if c.DefaultProfile != "" {
		if _, ok := c.Profiles[c.DefaultProfile]; !ok {
			problems = append(problems, fmt.Sprintf("default_profile %q is not a defined profile (have: %s)",
				c.DefaultProfile, strings.Join(c.ProfileNames(), ", ")))
		}
	}

	for _, name := range c.ProfileNames() {
		for _, prob := range c.Profiles[name].problems() {
			problems = append(problems, fmt.Sprintf("profile %q: %s", name, prob))
		}
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n  "))
	}
	return nil
}

func (p *Profile) problems() []string {
	var probs []string

	switch {
	case p.URL == "":
		probs = append(probs, "url is required (e.g. ldaps://ldap.example.com:636)")
	default:
		u, err := url.Parse(p.URL)
		if err != nil {
			probs = append(probs, fmt.Sprintf("url %q is not parseable: %v", p.URL, err))
		} else if u.Scheme != "ldap" && u.Scheme != "ldaps" {
			probs = append(probs, fmt.Sprintf("url scheme %q must be ldap or ldaps", u.Scheme))
		} else if u.Scheme == "ldaps" && p.StartTLS {
			probs = append(probs, "start_tls cannot be used with an ldaps:// url (it is already encrypted)")
		}
	}

	for _, req := range []struct{ name, val string }{
		{"bind_dn", p.BindDN},
		{"user_base_dn", p.UserBaseDN},
		{"group_base_dn", p.GroupBaseDN},
	} {
		if req.val == "" {
			probs = append(probs, req.name+" is required")
		}
	}

	if p.InsecureSkipVerify && p.CACert != "" {
		probs = append(probs, "insecure_skip_verify and ca_cert are contradictory; set only one")
	}
	// ca_cert is deliberately not opened here. Validation covers every profile
	// in the file, and a prod CA that is absent on this machine must not stop
	// a dev command from running. The file is read when that profile connects.

	if p.PasswordLength < MinPasswordLength {
		probs = append(probs, fmt.Sprintf("password_length %d is below the minimum of %d", p.PasswordLength, MinPasswordLength))
	}
	if p.UsernameMaxLength < MinUsernameMaxLen {
		probs = append(probs, fmt.Sprintf("username_max_length %d is below the minimum of %d", p.UsernameMaxLength, MinUsernameMaxLen))
	}
	if !strings.Contains(p.HomeTemplate, "{{.Username}}") {
		probs = append(probs, `home_template must contain {{.Username}}`)
	}

	probs = append(probs, p.UID.problems("uid")...)
	probs = append(probs, p.GID.problems("gid")...)
	return probs
}

func (r Range) problems(field string) []string {
	var probs []string
	if r.Min <= 0 {
		probs = append(probs, fmt.Sprintf("%s.min must be a positive number", field))
	}
	if r.Max <= r.Min {
		probs = append(probs, fmt.Sprintf("%s.max (%d) must be greater than %s.min (%d)", field, r.Max, field, r.Min))
	}
	if r.NextAttr != "" && r.NextDN == "" {
		probs = append(probs, fmt.Sprintf("%s.next_attr is set but %s.next_dn is empty", field, field))
	}
	return probs
}

// HomeDir renders HomeTemplate for a username.
func (p *Profile) HomeDir(username string) (string, error) {
	tmpl, err := template.New("home").Parse(p.HomeTemplate)
	if err != nil {
		return "", fmt.Errorf("home_template %q is not a valid template: %w", p.HomeTemplate, err)
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, struct{ Username string }{username}); err != nil {
		return "", fmt.Errorf("render home_template: %w", err)
	}
	return buf.String(), nil
}

// Encrypted reports whether traffic to this profile is protected, which
// decides whether a bind password may be sent at all.
func (p *Profile) Encrypted() bool {
	return strings.HasPrefix(strings.ToLower(p.URL), "ldaps://") || p.StartTLS
}

// ProfileNames returns the defined profile names, sorted.
func (c *Config) ProfileNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Resolve returns the named profile, falling back to default_profile when name
// is empty, or to the sole profile when exactly one is defined.
func (c *Config) Resolve(name string) (*Profile, error) {
	if name == "" {
		switch {
		case c.DefaultProfile != "":
			name = c.DefaultProfile
		case len(c.Profiles) == 1:
			name = c.ProfileNames()[0]
		default:
			return nil, fmt.Errorf("no profile selected and no default_profile set; use --profile (have: %s)",
				strings.Join(c.ProfileNames(), ", "))
		}
	}

	p, ok := c.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q (have: %s)", name, strings.Join(c.ProfileNames(), ", "))
	}
	return p, nil
}

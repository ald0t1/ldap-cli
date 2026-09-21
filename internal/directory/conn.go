package directory

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"

	"github.com/go-ldap/ldap/v3"

	"github.com/aldo/ldap-cli/internal/config"
)

// Client is a bound connection to one profile's server.
type Client struct {
	Conn    Conn
	Profile *config.Profile
}

// Connect dials the profile's server, applies its TLS policy, and binds as the
// manager DN.
//
// The plaintext check happens here rather than in the callers: this is the only
// place the bind password is put on the wire, so it is the only place that can
// be sure it is never sent in the clear by accident.
func Connect(p *config.Profile, bindPassword string) (*Client, error) {
	if !p.Encrypted() && !p.AllowInsecureBind {
		return nil, fmt.Errorf(
			"profile %q would send the bind password over an unencrypted connection to %s; "+
				"use ldaps://, set start_tls: true, or set allow_insecure_bind: true to permit it",
			p.Name, p.URL)
	}

	tlsConf, err := tlsConfig(p)
	if err != nil {
		return nil, err
	}

	// DialURL handles TLS itself for ldaps://; for ldap:// it returns a
	// plaintext connection that StartTLS can upgrade.
	conn, err := ldap.DialURL(p.URL, ldap.DialWithTLSConfig(tlsConf))
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", p.URL, err)
	}

	if p.StartTLS {
		if err := conn.StartTLS(tlsConf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("start_tls against %s: %w", p.URL, err)
		}
	}

	if err := conn.Bind(p.BindDN, bindPassword); err != nil {
		conn.Close()
		if resultCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, fmt.Errorf("bind as %s failed: invalid credentials", p.BindDN)
		}
		return nil, fmt.Errorf("bind as %s: %w", p.BindDN, err)
	}

	return &Client{Conn: conn, Profile: p}, nil
}

// Close releases the connection.
func (c *Client) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.Close()
}

func tlsConfig(p *config.Profile) (*tls.Config, error) {
	conf := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: p.InsecureSkipVerify,
	}

	// Verification is against the hostname in the URL, which is not
	// necessarily what DialURL passes through for every scheme.
	if u, err := url.Parse(p.URL); err == nil && u.Hostname() != "" {
		conf.ServerName = u.Hostname()
	}

	if p.CACert != "" {
		pem, err := os.ReadFile(p.CACert)
		if err != nil {
			return nil, fmt.Errorf("read ca_cert %s: %w", p.CACert, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_cert %s contains no usable PEM certificates", p.CACert)
		}
		conf.RootCAs = pool
	}

	return conf, nil
}

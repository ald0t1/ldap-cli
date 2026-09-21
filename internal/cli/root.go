// Package cli wires the command tree.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aldo/ldap-cli/internal/backup"
	"github.com/aldo/ldap-cli/internal/config"
	"github.com/aldo/ldap-cli/internal/directory"
	"github.com/aldo/ldap-cli/internal/mailer"
)

// bindPasswordEnv lets scripts and the compose dev server skip the prompt.
const bindPasswordEnv = "LDAP_CLI_BIND_PASSWORD"

// backupDirEnv overrides where pre-write snapshots are written.
const backupDirEnv = "LDAP_CLI_BACKUP_DIR"

// app holds the global flags and the lazily-built connection.
type app struct {
	configPath       string
	profileName      string
	bindPasswordFile string
	jsonOut          bool
	backupDir        string
	noBackup         bool

	cfg    *config.Config
	client *directory.Client
	mail   mailer.Mailer

	// backupDone keeps a run to a single snapshot. The interactive shell
	// performs many writes in one process, and one artifact per session is
	// the useful granularity — not one per action.
	backupDone bool
}

// Execute runs the CLI, returning the process exit code.
func Execute() int {
	a := &app{}

	root := &cobra.Command{
		Use:   "ldap-cli",
		Short: "Provision users and groups on OpenLDAP servers",
		Long: "ldap-cli provisions accounts on the OpenLDAP servers named in its config file.\n\n" +
			"Run it with no arguments for an interactive menu — pick a server, authenticate\n" +
			"once, then choose actions from a list with nothing to memorise. The commands\n" +
			"below do the same things with flags, for scripting.\n\n" +
			"Usernames, uidNumbers and passwords are generated automatically; the manager\n" +
			"bind password is prompted for unless " + bindPasswordEnv + " or\n" +
			"--bind-password-file supplies it.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// With no subcommand, start the menu for a human and print help for a
		// script, so a piped invocation cannot hang waiting on a prompt.
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !interactive() {
				return cmd.Help()
			}
			return a.runShell(cmd)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVarP(&a.configPath, "config", "c", "", "config file (default: search "+strings.Join(config.DefaultPaths(), ", ")+")")
	pf.StringVarP(&a.profileName, "profile", "p", "", "profile to use (default: the config's default_profile)")
	pf.StringVar(&a.bindPasswordFile, "bind-password-file", "", "read the manager bind password from this file instead of prompting")
	pf.BoolVar(&a.jsonOut, "json", false, "emit machine-readable JSON")
	pf.StringVar(&a.backupDir, "backup-dir", "", "where to write pre-write snapshots (default: $"+backupDirEnv+", backup_dir, then "+backup.DefaultDir()+")")
	pf.BoolVar(&a.noBackup, "no-backup", false, "skip the snapshot taken before the first write")

	root.AddCommand(
		a.shellCmd(),
		a.profileCmd(),
		a.userCmd(),
		a.groupCmd(),
	)

	// The connection is opened by whichever command needs it and closed here.
	defer func() {
		if a.client != nil {
			a.client.Close()
		}
	}()

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// loadConfig reads the config file once.
func (a *app) loadConfig() (*config.Config, error) {
	if a.cfg != nil {
		return a.cfg, nil
	}
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, err
	}
	a.cfg = cfg
	return cfg, nil
}

// profile resolves the selected profile without connecting.
func (a *app) profile() (*config.Profile, error) {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	return cfg.Resolve(a.profileName)
}

// connect resolves the profile, obtains the bind password, and binds.
func (a *app) connect() (*directory.Client, error) {
	if a.client != nil {
		return a.client, nil
	}

	p, err := a.profile()
	if err != nil {
		return nil, err
	}

	password, err := a.bindPassword(p)
	if err != nil {
		return nil, err
	}

	client, err := directory.Connect(p, password)
	if err != nil {
		return nil, err
	}
	a.client = client
	return client, nil
}

// connectForWrite binds and, on the first write of the run, captures a
// snapshot of the subtrees about to change.
//
// Every mutating command goes through here rather than connect(), so a new
// write command cannot forget the backup. Read-only commands deliberately do
// not snapshot.
func (a *app) connectForWrite(cmd *cobra.Command) (*directory.Client, error) {
	client, err := a.connect()
	if err != nil {
		return nil, err
	}
	if err := a.snapshot(cmd, client); err != nil {
		return nil, err
	}
	return client, nil
}

// snapshot writes one pre-write backup per run and rotates old ones.
func (a *app) snapshot(cmd *cobra.Command, client *directory.Client) error {
	if a.noBackup || a.backupDone {
		return nil
	}

	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}

	dir := a.backupDir
	if dir == "" {
		dir = os.Getenv(backupDirEnv)
	}
	if dir == "" {
		dir = cfg.BackupDir
	}
	if dir == "" {
		dir = backup.DefaultDir()
	}

	res, err := backup.Take(client.Conn, backup.Options{
		Dir:     dir,
		Profile: client.Profile.Name,
		BaseDNs: []string{client.Profile.UserBaseDN, client.Profile.GroupBaseDN},
		Keep:    cfg.BackupKeep,
	})
	if err != nil {
		// Refusing to proceed is the point: the operator asked for a backup
		// before every run, so a write without one is not what they wanted.
		// --no-backup is the deliberate override.
		return fmt.Errorf("%w\n(pass --no-backup to write without a snapshot)", err)
	}

	// Mark it done even on the JSON path, so a failure cannot cause a second
	// attempt mid-run.
	a.backupDone = true

	if !a.jsonOut {
		fmt.Fprintf(os.Stderr, "backup: %s (%d entries)\n", res.Path, res.Entries)
		if n := len(res.Removed); n > 0 {
			fmt.Fprintf(os.Stderr, "backup: rotated %d older snapshot(s)\n", n)
		}
	}
	return nil
}

// bindPassword obtains the manager password: environment, then file, then an
// interactive prompt.
//
// It is never echoed, never written to the config file, and never included in
// --json output.
func (a *app) bindPassword(p *config.Profile) (string, error) {
	if v := os.Getenv(bindPasswordEnv); v != "" {
		return v, nil
	}

	if a.bindPasswordFile != "" {
		raw, err := os.ReadFile(a.bindPasswordFile)
		if err != nil {
			return "", fmt.Errorf("read --bind-password-file: %w", err)
		}
		// A trailing newline from `echo > file` is not part of the password.
		password := strings.TrimRight(string(raw), "\r\n")
		if password == "" {
			return "", fmt.Errorf("--bind-password-file %s is empty", a.bindPasswordFile)
		}
		return password, nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf(
			"no bind password available and stdin is not a terminal; set %s or use --bind-password-file",
			bindPasswordEnv)
	}

	// The prompt goes to stderr so that --json output stays pipeable.
	fmt.Fprintf(os.Stderr, "Bind password for %s (profile %q): ", p.BindDN, p.Name)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read bind password: %w", err)
	}
	if len(raw) == 0 {
		return "", errors.New("no bind password entered")
	}
	return string(raw), nil
}

// mailerFor returns the notification mailer: SMTP when mail.enabled is set in
// the config, otherwise a Noop that says so.
func (a *app) mailerFor(cmd *cobra.Command) mailer.Mailer {
	if a.mail != nil {
		return a.mail
	}

	// A config that failed to load is reported by whatever command needed it;
	// here it just means mail stays off.
	if cfg, err := a.loadConfig(); err == nil && cfg.Mail.Enabled {
		a.mail = mailer.NewSMTP(cfg.Mail)
		return a.mail
	}

	// Silence the "switched off" note in JSON mode so the output stays valid
	// JSON.
	var out io.Writer = cmd.OutOrStdout()
	if a.jsonOut {
		out = nil
	}
	a.mail = mailer.Noop{Out: out}
	return a.mail
}

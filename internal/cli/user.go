package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/aldo/ldap-cli/internal/directory"
	"github.com/aldo/ldap-cli/internal/mailer"
	"github.com/aldo/ldap-cli/internal/secret"
)

func (a *app) userCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Create and manage accounts",
	}
	cmd.AddCommand(
		a.userCreateCmd(),
		a.userShowCmd(),
		a.userAddGroupCmd(),
		a.userRemoveGroupCmd(),
		a.userPasswdCmd(),
	)
	return cmd
}

type createOpts struct {
	givenName    string
	surname      string
	email        string
	username     string
	primaryGroup string
	groups       []string
	passwordLen  int
	dryRun       bool
	noRollback   bool
}

func (a *app) userCreateCmd() *cobra.Command {
	var o createOpts

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an account with a generated username, uidNumber and password",
		Long: "Creates a posixAccount.\n\n" +
			"The username is derived from the name (John Doe becomes jdoe, and a second\n" +
			"J. Doe becomes jdoe1), the uidNumber comes from the profile's range, and the\n" +
			"password is generated and set through the LDAP password modify operation so\n" +
			"the server applies its own hashing policy.\n\n" +
			"The generated password is printed once and cannot be retrieved afterwards.",
		Args: cobra.NoArgs,
		Example: "  ldap-cli --profile prod user create \\\n" +
			"      --given-name John --surname Doe \\\n" +
			"      --email john.doe@corp.com \\\n" +
			"      --primary-group developers --group docker --group vpn",
		RunE: func(cmd *cobra.Command, _ []string) error { return a.runUserCreate(cmd, &o) },
	}

	f := cmd.Flags()
	f.StringVar(&o.givenName, "given-name", "", "first name (prompted if omitted)")
	f.StringVar(&o.surname, "surname", "", "last name (prompted if omitted)")
	f.StringVar(&o.email, "email", "", "email address (defaults to <username>@<mail_domain>)")
	f.StringVar(&o.username, "username", "", "override the generated username; used exactly as given")
	f.StringVar(&o.primaryGroup, "primary-group", "", "existing group supplying gidNumber (defaults to the profile's default_primary_group)")
	f.StringSliceVarP(&o.groups, "group", "g", nil, "additional group to join (repeatable)")
	f.IntVar(&o.passwordLen, "password-length", 0, "generated password length (defaults to the profile's password_length)")
	f.BoolVar(&o.dryRun, "dry-run", false, "print the LDIF that would be sent and exit without writing")
	f.BoolVar(&o.noRollback, "no-rollback", false, "keep the entry if the password cannot be set (default is to remove it)")

	return cmd
}

func (a *app) runUserCreate(cmd *cobra.Command, o *createOpts) error {
	if err := a.gatherNames(o); err != nil {
		return err
	}

	client, err := a.connect()
	if err != nil {
		return err
	}
	p := client.Profile

	// Resolve every group before touching the account, so a typo cannot leave
	// a half-provisioned user behind.
	primaryName := o.primaryGroup
	if primaryName == "" {
		primaryName = p.DefaultPrimaryGroup
	}
	if primaryName == "" {
		return fmt.Errorf("no primary group given and profile %q sets no default_primary_group; use --primary-group", p.Name)
	}

	primary, err := client.RequireGroup(primaryName)
	if err != nil {
		return err
	}

	extra := make([]*directory.Group, 0, len(o.groups))
	for _, name := range o.groups {
		g, err := client.RequireGroup(name)
		if err != nil {
			return err
		}
		extra = append(extra, g)
	}

	spec := directory.NewUser{
		GivenName:    o.givenName,
		Surname:      o.surname,
		Email:        o.email,
		Username:     o.username,
		PrimaryGroup: primary,
		Groups:       extra,
	}

	if o.dryRun {
		return a.reportDryRun(cmd, client, spec, primary, extra)
	}

	length := o.passwordLen
	if length == 0 {
		length = p.PasswordLength
	}
	password, err := secret.Generate(length)
	if err != nil {
		return err
	}
	spec.Password = password

	res, err := client.CreateUser(spec, !o.noRollback)
	if err != nil {
		return err
	}

	if err := a.reportCreated(cmd, res, primary); err != nil {
		return err
	}

	// Notification is stubbed; see internal/mailer.
	notice := mailer.Notice{
		Profile:  p.Name,
		FullName: res.User.CommonName,
		Email:    res.User.Email,
		Username: res.User.Username,
		DN:       res.User.DN,
		Password: res.Password,
	}
	if err := a.mailerFor(cmd).SendWelcome(cmd.Context(), notice); err != nil {
		fmt.Fprintf(os.Stderr, "warning: sending the welcome email failed: %v\n", err)
	}

	// Group failures do not undo the account, but they must not be mistaken
	// for success either.
	if len(res.GroupErrors) > 0 {
		for _, e := range res.GroupErrors {
			fmt.Fprintf(os.Stderr, "warning: %v\n", e)
		}
		return fmt.Errorf("the account was created but %d group membership(s) failed; "+
			"re-run `ldap-cli user add-group %s ...` to finish", len(res.GroupErrors), res.User.Username)
	}
	return nil
}

// gatherNames fills in missing name fields, prompting when there is a human.
func (a *app) gatherNames(o *createOpts) error {
	if interactive() {
		p := newPrompter()
		var err error
		if o.givenName == "" {
			if o.givenName, err = p.ask("First name", ""); err != nil {
				return err
			}
		}
		if o.surname == "" {
			if o.surname, err = p.ask("Last name", ""); err != nil {
				return err
			}
		}
		if o.email == "" {
			// Blank is allowed: it falls back to <username>@<mail_domain>.
			if o.email, err = p.askOptional("Email", ""); err != nil {
				return err
			}
		}
		return nil
	}

	if err := requireFlag("given-name", o.givenName); err != nil {
		return err
	}
	return requireFlag("surname", o.surname)
}

func (a *app) reportDryRun(cmd *cobra.Command, client *directory.Client, spec directory.NewUser, primary *directory.Group, extra []*directory.Group) error {
	user, ldif, err := client.DryRunEntry(spec)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if a.jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"dry_run":       true,
			"username":      user.Username,
			"dn":            user.DN,
			"uid_number":    user.UIDNumber,
			"gid_number":    user.GIDNumber,
			"primary_group": primary.CN,
			"groups":        groupNames(extra),
			"ldif":          ldif,
		})
	}

	fmt.Fprintf(out, "dry run — nothing was written\n\n%s\n", ldif)
	if len(extra) > 0 {
		fmt.Fprintf(out, "would also add memberUid: %s to %s\n",
			user.Username, strings.Join(groupNames(extra), ", "))
	}
	fmt.Fprintf(out, "a password would be generated and set via the password modify operation\n")
	fmt.Fprintf(out, "note: the uidNumber above is from a scan; a real run may land higher if\n"+
		"      another account is created first\n")
	return nil
}

func (a *app) reportCreated(cmd *cobra.Command, res *directory.CreateResult, primary *directory.Group) error {
	out := cmd.OutOrStdout()
	u := res.User

	if a.jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"username":      u.Username,
			"dn":            u.DN,
			"uid_number":    u.UIDNumber,
			"gid_number":    u.GIDNumber,
			"primary_group": primary.CN,
			"email":         u.Email,
			"home":          u.HomeDir,
			"shell":         u.LoginShell,
			"groups":        res.JoinedGroup,
			"password":      res.Password,
		})
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "created\t%s\n", u.DN)
	fmt.Fprintf(tw, "username\t%s\n", u.Username)
	fmt.Fprintf(tw, "uidNumber\t%d\n", u.UIDNumber)
	fmt.Fprintf(tw, "gidNumber\t%d (%s)\n", u.GIDNumber, primary.CN)
	if u.Email != "" {
		fmt.Fprintf(tw, "email\t%s\n", u.Email)
	}
	fmt.Fprintf(tw, "home\t%s\n", u.HomeDir)
	fmt.Fprintf(tw, "shell\t%s\n", u.LoginShell)
	if len(res.JoinedGroup) > 0 {
		fmt.Fprintf(tw, "groups\t%s\n", strings.Join(res.JoinedGroup, ", "))
	}
	fmt.Fprintf(tw, "password\t%s\n", res.Password)
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintf(out, "\nThe password is shown only once — the server stores it hashed.\n")
	return nil
}

func (a *app) userShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <username>",
		Short: "Show an account and its group memberships",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := a.connect()
			if err != nil {
				return err
			}

			user, err := client.FindUser(args[0])
			if err != nil {
				return err
			}
			if user == nil {
				return fmt.Errorf("no account %q under %s", args[0], client.Profile.UserBaseDN)
			}

			groups, err := client.GroupsOf(user.Username)
			if err != nil {
				return err
			}
			names := make([]string, 0, len(groups))
			for _, g := range groups {
				names = append(names, g.CN)
			}

			out := cmd.OutOrStdout()
			if a.jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"username":   user.Username,
					"dn":         user.DN,
					"cn":         user.CommonName,
					"given_name": user.GivenName,
					"surname":    user.Surname,
					"email":      user.Email,
					"uid_number": user.UIDNumber,
					"gid_number": user.GIDNumber,
					"home":       user.HomeDir,
					"shell":      user.LoginShell,
					"groups":     names,
				})
			}

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "dn\t%s\n", user.DN)
			fmt.Fprintf(tw, "username\t%s\n", user.Username)
			fmt.Fprintf(tw, "name\t%s\n", user.CommonName)
			fmt.Fprintf(tw, "email\t%s\n", user.Email)
			fmt.Fprintf(tw, "uidNumber\t%d\n", user.UIDNumber)
			fmt.Fprintf(tw, "gidNumber\t%d\n", user.GIDNumber)
			fmt.Fprintf(tw, "home\t%s\n", user.HomeDir)
			fmt.Fprintf(tw, "shell\t%s\n", user.LoginShell)
			fmt.Fprintf(tw, "groups\t%s\n", strings.Join(names, ", "))
			return tw.Flush()
		},
	}
}

func (a *app) userAddGroupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add-group <username> <group>...",
		Short: "Add an account to one or more groups",
		Long:  "Adds memberUid entries. Groups the account is already in are left alone, so this is safe to re-run.",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.changeMembership(cmd, args[0], args[1:], true)
		},
	}
}

func (a *app) userRemoveGroupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove-group <username> <group>...",
		Short: "Remove an account from one or more groups",
		Long: "Removes memberUid entries. This does not change the account's primary group, " +
			"which is set by its gidNumber.",
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.changeMembership(cmd, args[0], args[1:], false)
		},
	}
}

// changeMembership adds or removes a user across several groups, resolving all
// of them first so a typo does not leave the change half applied.
func (a *app) changeMembership(cmd *cobra.Command, uid string, names []string, add bool) error {
	client, err := a.connect()
	if err != nil {
		return err
	}

	user, err := client.FindUser(uid)
	if err != nil {
		return err
	}
	if user == nil {
		return fmt.Errorf("no account %q under %s", uid, client.Profile.UserBaseDN)
	}

	groups := make([]*directory.Group, 0, len(names))
	for _, name := range names {
		g, err := client.RequireGroup(name)
		if err != nil {
			return err
		}
		groups = append(groups, g)
	}

	out := cmd.OutOrStdout()
	var changed, unchanged []string
	var failures []error

	for _, g := range groups {
		var did bool
		var err error
		if add {
			did, err = client.AddMember(g, user.Username)
		} else {
			did, err = client.RemoveMember(g, user.Username)
		}

		switch {
		case err != nil:
			failures = append(failures, err)
		case did:
			changed = append(changed, g.CN)
		default:
			unchanged = append(unchanged, g.CN)
		}
	}

	verb, already := "added to", "already in"
	if !add {
		verb, already = "removed from", "not in"
	}

	if a.jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		payload := map[string]any{"username": user.Username, "changed": changed, "unchanged": unchanged}
		if len(failures) > 0 {
			msgs := make([]string, len(failures))
			for i, e := range failures {
				msgs[i] = e.Error()
			}
			payload["errors"] = msgs
		}
		if err := enc.Encode(payload); err != nil {
			return err
		}
	} else {
		if len(changed) > 0 {
			fmt.Fprintf(out, "%s %s %s\n", user.Username, verb, strings.Join(changed, ", "))
		}
		if len(unchanged) > 0 {
			fmt.Fprintf(out, "%s was %s %s — no change\n", user.Username, already, strings.Join(unchanged, ", "))
		}
	}

	if len(failures) > 0 {
		for _, e := range failures {
			fmt.Fprintf(os.Stderr, "warning: %v\n", e)
		}
		return fmt.Errorf("%d group change(s) failed", len(failures))
	}
	return nil
}

func (a *app) userPasswdCmd() *cobra.Command {
	var length int

	cmd := &cobra.Command{
		Use:   "passwd <username>",
		Short: "Generate and set a new password for an account",
		Long: "Generates a new password and sets it through the LDAP password modify operation. " +
			"The new password is printed once.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := a.connect()
			if err != nil {
				return err
			}

			user, err := client.FindUser(args[0])
			if err != nil {
				return err
			}
			if user == nil {
				return fmt.Errorf("no account %q under %s", args[0], client.Profile.UserBaseDN)
			}

			n := length
			if n == 0 {
				n = client.Profile.PasswordLength
			}
			password, err := secret.Generate(n)
			if err != nil {
				return err
			}
			if err := client.SetPassword(user.DN, password); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if a.jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"username": user.Username,
					"dn":       user.DN,
					"password": password,
				})
			}
			fmt.Fprintf(out, "password for %s reset to: %s\n", user.Username, password)
			fmt.Fprintf(out, "\nShown only once — the server stores it hashed.\n")
			return nil
		},
	}

	cmd.Flags().IntVar(&length, "password-length", 0, "generated password length (defaults to the profile's password_length)")
	return cmd
}

func groupNames(groups []*directory.Group) []string {
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.CN)
	}
	return names
}

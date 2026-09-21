package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"charm.land/huh/v2"
	"github.com/spf13/cobra"

	"github.com/aldo/ldap-cli/internal/directory"
	"github.com/aldo/ldap-cli/internal/mailer"
	"github.com/aldo/ldap-cli/internal/secret"
	"github.com/aldo/ldap-cli/internal/username"
)

// errQuit unwinds the menu loop when the operator chooses to leave.
var errQuit = errors.New("quit")

// Menu action identifiers.
const (
	actCreateUser   = "create-user"
	actShowUser     = "show-user"
	actAddGroups    = "add-groups"
	actRemoveGroups = "remove-groups"
	actResetPasswd  = "reset-password"
	actListUsers    = "list-users"
	actCreateGroup  = "create-group"
	actListGroups   = "list-groups"
	actShowGroup    = "show-group"
	actSwitch       = "switch-profile"
	actQuit         = "quit"
)

func (a *app) shellCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shell",
		Short: "Interactive menu — pick actions instead of typing commands",
		Long: "Starts a menu-driven session. Pick a profile, authenticate once, then choose\n" +
			"actions from a list. Groups and accounts are offered as filterable pickers, so\n" +
			"there are no command names or flags to remember.\n\n" +
			"Running ldap-cli with no arguments starts this too.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.runShell(cmd) },
	}
}

// runShell authenticates once, then loops the action menu.
func (a *app) runShell(cmd *cobra.Command) error {
	if !interactive() {
		return errors.New("the interactive shell needs a terminal; " +
			"use the flag-based commands for scripting (see `ldap-cli --help`)")
	}

	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}

	// Choosing the profile is the first thing, since everything else depends
	// on which server is being changed.
	if a.profileName == "" {
		if a.profileName, err = pickProfile(cfg); err != nil {
			return err
		}
	}

	client, err := a.connect()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nconnected to %s (%s) as %s\n",
		client.Profile.Name, client.Profile.URL, client.Profile.BindDN)
	if !client.Profile.Encrypted() {
		fmt.Fprintf(os.Stderr, "warning: this connection is not encrypted\n")
	}

	for {
		err := a.runAction(cmd, client)
		switch {
		case errors.Is(err, errQuit), errors.Is(err, huh.ErrUserAborted):
			fmt.Fprintln(os.Stderr, "bye")
			return nil
		case err != nil:
			// A failed action returns to the menu rather than exiting: the
			// usual cause is a typo or a name already in use, and quitting
			// the whole session over it would be tedious.
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		}
	}
}

// pickProfile offers the configured servers.
func pickProfile(cfg interface {
	ProfileNames() []string
}) (string, error) {
	names := cfg.ProfileNames()
	if len(names) == 1 {
		return names[0], nil
	}

	var choice string
	err := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Server").
			Description("Which directory do you want to work on?").
			Options(huh.NewOptions(names...)...).
			Value(&choice),
	)).Run()
	if err != nil {
		return "", err
	}
	return choice, nil
}

// runAction shows the main menu and dispatches one choice.
func (a *app) runAction(cmd *cobra.Command, client *directory.Client) error {
	var choice string

	form := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title(fmt.Sprintf("%s — what would you like to do?", client.Profile.Name)).
			Options(
				huh.NewOption("Create a user", actCreateUser),
				huh.NewOption("Show a user", actShowUser),
				huh.NewOption("Add a user to groups", actAddGroups),
				huh.NewOption("Remove a user from groups", actRemoveGroups),
				huh.NewOption("Reset a user's password", actResetPasswd),
				huh.NewOption("List users", actListUsers),
				huh.NewOption("Create a group", actCreateGroup),
				huh.NewOption("Show a group", actShowGroup),
				huh.NewOption("List groups", actListGroups),
				huh.NewOption("Switch server", actSwitch),
				huh.NewOption("Quit", actQuit),
			).
			Value(&choice),
	))
	if err := form.Run(); err != nil {
		return err
	}

	switch choice {
	case actCreateUser:
		return a.shellCreateUser(cmd, client)
	case actShowUser:
		return a.shellShowUser(cmd, client)
	case actAddGroups:
		return a.shellChangeGroups(cmd, client, true)
	case actRemoveGroups:
		return a.shellChangeGroups(cmd, client, false)
	case actResetPasswd:
		return a.shellResetPassword(cmd, client)
	case actListUsers:
		return a.shellListUsers(cmd, client)
	case actCreateGroup:
		return a.shellCreateGroup(cmd, client)
	case actShowGroup:
		return a.shellShowGroup(cmd, client)
	case actListGroups:
		return a.shellListGroups(cmd, client)
	case actSwitch:
		return a.shellSwitchProfile()
	case actQuit:
		return errQuit
	}
	return nil
}

// shellCreateUser gathers the details and provisions an account.
func (a *app) shellCreateUser(cmd *cobra.Command, client *directory.Client) error {
	groups, err := client.ListGroups()
	if err != nil {
		return err
	}
	if len(groups) == 0 {
		return fmt.Errorf("there are no groups under %s yet; create one first", client.Profile.GroupBaseDN)
	}

	var (
		given, surname, email string
		primary               string
		extra                 []string
	)

	// Default the primary group to the profile's configured one when it exists.
	for _, g := range groups {
		if g.CN == client.Profile.DefaultPrimaryGroup {
			primary = g.CN
		}
	}

	err = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("First name").Value(&given).Validate(notBlank("first name")),
			huh.NewInput().Title("Last name").Value(&surname).Validate(notBlank("last name")),
			huh.NewInput().
				Title("Email").
				Description(emailHint(client)).
				Value(&email),
		),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Primary group").
				Description("Supplies the account's gidNumber. Type to filter.").
				Options(groupOptions(groups)...).
				Filtering(true).
				Value(&primary),
			huh.NewMultiSelect[string]().
				Title("Additional groups").
				Description("Space to toggle, enter to accept. Type to filter. Optional.").
				Options(groupOptions(groups)...).
				Filterable(true).
				Value(&extra),
		),
	).Run()
	if err != nil {
		return err
	}

	// Show what will happen before writing anything.
	proposed, err := client.ProposeUsername(given, surname)
	if err != nil {
		return err
	}

	confirmed, err := confirmAction(fmt.Sprintf(
		"Create %s %s as %q in %s?", given, surname, proposed, primary))
	if err != nil || !confirmed {
		fmt.Fprintln(os.Stderr, "cancelled")
		return err
	}

	primaryGroup, err := client.RequireGroup(primary)
	if err != nil {
		return err
	}
	extraGroups, err := resolveGroups(client, extra)
	if err != nil {
		return err
	}

	password, err := secret.Generate(client.Profile.PasswordLength)
	if err != nil {
		return err
	}

	res, err := client.CreateUser(directory.NewUser{
		GivenName:    strings.TrimSpace(given),
		Surname:      strings.TrimSpace(surname),
		Email:        strings.TrimSpace(email),
		PrimaryGroup: primaryGroup,
		Groups:       extraGroups,
		Password:     password,
	}, true)
	if err != nil {
		return err
	}

	if err := a.reportCreated(cmd, res, primaryGroup); err != nil {
		return err
	}

	notice := mailer.Notice{
		Profile:  client.Profile.Name,
		FullName: res.User.CommonName,
		Email:    res.User.Email,
		Username: res.User.Username,
		DN:       res.User.DN,
		Password: res.Password,
	}
	if err := a.mailerFor(cmd).SendWelcome(cmd.Context(), notice); err != nil {
		fmt.Fprintf(os.Stderr, "warning: sending the welcome email failed: %v\n", err)
	}
	for _, e := range res.GroupErrors {
		fmt.Fprintf(os.Stderr, "warning: %v\n", e)
	}
	return pause()
}

// shellChangeGroups adds or removes group memberships for a chosen account.
func (a *app) shellChangeGroups(cmd *cobra.Command, client *directory.Client, add bool) error {
	user, err := pickUser(client, "Which account?")
	if err != nil {
		return err
	}

	all, err := client.ListGroups()
	if err != nil {
		return err
	}
	current, err := client.GroupsOf(user.Username)
	if err != nil {
		return err
	}

	// Offer only groups the change can actually affect, so the list stays
	// short and the outcome is never a no-op.
	var candidates []directory.Group
	in := make(map[string]bool, len(current))
	for _, g := range current {
		in[g.CN] = true
	}
	for _, g := range all {
		if in[g.CN] == add {
			continue
		}
		candidates = append(candidates, g)
	}

	if len(candidates) == 0 {
		if add {
			return fmt.Errorf("%s is already in every group under %s", user.Username, client.Profile.GroupBaseDN)
		}
		return fmt.Errorf("%s is not in any group", user.Username)
	}

	verb := "Add to"
	if !add {
		verb = "Remove from"
	}

	var chosen []string
	err = huh.NewForm(huh.NewGroup(
		huh.NewMultiSelect[string]().
			Title(fmt.Sprintf("%s which groups?", verb)).
			Description("Space to toggle, enter to accept. Type to filter.").
			Options(groupOptions(candidates)...).
			Filterable(true).
			Value(&chosen).
			Validate(func(sel []string) error {
				if len(sel) == 0 {
					return errors.New("pick at least one group")
				}
				return nil
			}),
	)).Run()
	if err != nil {
		return err
	}

	groups, err := resolveGroups(client, chosen)
	if err != nil {
		return err
	}

	var failures []error
	for _, g := range groups {
		var did bool
		if add {
			did, err = client.AddMember(g, user.Username)
		} else {
			did, err = client.RemoveMember(g, user.Username)
		}
		switch {
		case err != nil:
			failures = append(failures, err)
		case did:
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s\n", user.Username, strings.ToLower(verb), g.CN)
		default:
			fmt.Fprintf(cmd.OutOrStdout(), "%s unchanged for %s\n", g.CN, user.Username)
		}
	}
	for _, e := range failures {
		fmt.Fprintf(os.Stderr, "warning: %v\n", e)
	}
	return pause()
}

func (a *app) shellResetPassword(cmd *cobra.Command, client *directory.Client) error {
	user, err := pickUser(client, "Reset whose password?")
	if err != nil {
		return err
	}

	confirmed, err := confirmAction(fmt.Sprintf("Issue a new password for %s?", user.Username))
	if err != nil || !confirmed {
		fmt.Fprintln(os.Stderr, "cancelled")
		return err
	}

	password, err := secret.Generate(client.Profile.PasswordLength)
	if err != nil {
		return err
	}
	if err := client.SetPassword(user.DN, password); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\npassword for %s reset to: %s\n", user.Username, password)
	fmt.Fprintf(cmd.OutOrStdout(), "Shown only once — the server stores it hashed.\n")
	return pause()
}

func (a *app) shellShowUser(cmd *cobra.Command, client *directory.Client) error {
	user, err := pickUser(client, "Show which account?")
	if err != nil {
		return err
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
	fmt.Fprintf(out, "\n%-12s%s\n", "dn", user.DN)
	fmt.Fprintf(out, "%-12s%s\n", "username", user.Username)
	fmt.Fprintf(out, "%-12s%s\n", "name", user.CommonName)
	fmt.Fprintf(out, "%-12s%s\n", "email", user.Email)
	fmt.Fprintf(out, "%-12s%d\n", "uidNumber", user.UIDNumber)
	fmt.Fprintf(out, "%-12s%d\n", "gidNumber", user.GIDNumber)
	fmt.Fprintf(out, "%-12s%s\n", "home", user.HomeDir)
	fmt.Fprintf(out, "%-12s%s\n", "shell", user.LoginShell)
	fmt.Fprintf(out, "%-12s%s\n", "groups", strings.Join(names, ", "))
	return pause()
}

func (a *app) shellListUsers(cmd *cobra.Command, client *directory.Client) error {
	users, err := client.ListUsers()
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if len(users) == 0 {
		fmt.Fprintf(out, "\nno accounts under %s\n", client.Profile.UserBaseDN)
		return pause()
	}

	fmt.Fprintf(out, "\n%-20s%-8s%-8s%s\n", "USERNAME", "UID", "GID", "NAME")
	for _, u := range users {
		fmt.Fprintf(out, "%-20s%-8d%-8d%s\n", u.Username, u.UIDNumber, u.GIDNumber, u.CommonName)
	}
	return pause()
}

func (a *app) shellCreateGroup(cmd *cobra.Command, client *directory.Client) error {
	var (
		name, description string
		explicitGID       string
	)

	err := huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Group name").
			Value(&name).
			Validate(func(s string) error {
				if err := notBlank("group name")(s); err != nil {
					return err
				}
				return username.Valid(strings.TrimSpace(s), client.Profile.UsernameMaxLength)
			}),
		huh.NewInput().Title("Description").Description("Optional.").Value(&description),
		huh.NewInput().
			Title("gidNumber").
			Description(fmt.Sprintf("Leave blank to allocate from %d-%d.",
				client.Profile.GID.Min, client.Profile.GID.Max)).
			Value(&explicitGID).
			Validate(optionalNumber),
	)).Run()
	if err != nil {
		return err
	}

	gid := 0
	if s := strings.TrimSpace(explicitGID); s != "" {
		if gid, err = strconv.Atoi(s); err != nil {
			return fmt.Errorf("gidNumber %q is not a number", s)
		}
	}

	group, err := client.CreateGroup(directory.NewGroup{
		CN:          strings.TrimSpace(name),
		GIDNumber:   gid,
		Description: strings.TrimSpace(description),
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\ncreated %s with gidNumber %d\n", group.DN, group.GIDNumber)
	return pause()
}

func (a *app) shellShowGroup(cmd *cobra.Command, client *directory.Client) error {
	groups, err := client.ListGroups()
	if err != nil {
		return err
	}
	if len(groups) == 0 {
		return fmt.Errorf("no groups under %s", client.Profile.GroupBaseDN)
	}

	var choice string
	if err := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Show which group?").
			Description("Type to filter.").
			Options(groupOptions(groups)...).
			Filtering(true).
			Value(&choice),
	)).Run(); err != nil {
		return err
	}

	group, err := client.RequireGroup(choice)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "\n%-12s%s\n", "dn", group.DN)
	fmt.Fprintf(out, "%-12s%s\n", "cn", group.CN)
	fmt.Fprintf(out, "%-12s%d\n", "gidNumber", group.GIDNumber)
	if group.Description != "" {
		fmt.Fprintf(out, "%-12s%s\n", "description", group.Description)
	}
	fmt.Fprintf(out, "%-12s%s\n", "members", strings.Join(group.MemberUIDs, ", "))
	return pause()
}

func (a *app) shellListGroups(cmd *cobra.Command, client *directory.Client) error {
	groups, err := client.ListGroups()
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if len(groups) == 0 {
		fmt.Fprintf(out, "\nno groups under %s\n", client.Profile.GroupBaseDN)
		return pause()
	}

	fmt.Fprintf(out, "\n%-24s%-8s%-10s%s\n", "GROUP", "GID", "MEMBERS", "DESCRIPTION")
	for _, g := range groups {
		fmt.Fprintf(out, "%-24s%-8d%-10d%s\n", g.CN, g.GIDNumber, len(g.MemberUIDs), g.Description)
	}
	return pause()
}

// shellSwitchProfile drops the current connection so the next action binds to
// a different server.
func (a *app) shellSwitchProfile() error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}

	name, err := pickProfile(cfg)
	if err != nil {
		return err
	}

	if a.client != nil {
		a.client.Close()
		a.client = nil
	}
	a.profileName = name

	client, err := a.connect()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nconnected to %s (%s)\n", client.Profile.Name, client.Profile.URL)
	return nil
}

// pickUser offers a filterable list of accounts.
func pickUser(client *directory.Client, title string) (*directory.User, error) {
	users, err := client.ListUsers()
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("no accounts under %s yet", client.Profile.UserBaseDN)
	}

	opts := make([]huh.Option[string], 0, len(users))
	for _, u := range users {
		label := u.Username
		if u.CommonName != "" {
			label = fmt.Sprintf("%s — %s", u.Username, u.CommonName)
		}
		opts = append(opts, huh.NewOption(label, u.Username))
	}

	var choice string
	if err := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title(title).
			Description("Type to filter.").
			Options(opts...).
			Filtering(true).
			Value(&choice),
	)).Run(); err != nil {
		return nil, err
	}

	user, err := client.FindUser(choice)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("account %q disappeared", choice)
	}
	return user, nil
}

// groupOptions renders groups as picker entries, showing the gidNumber so two
// similarly named groups can be told apart.
func groupOptions(groups []directory.Group) []huh.Option[string] {
	opts := make([]huh.Option[string], 0, len(groups))
	for _, g := range groups {
		opts = append(opts, huh.NewOption(fmt.Sprintf("%s (gid %d)", g.CN, g.GIDNumber), g.CN))
	}
	return opts
}

// resolveGroups turns picked names back into groups.
func resolveGroups(client *directory.Client, names []string) ([]*directory.Group, error) {
	groups := make([]*directory.Group, 0, len(names))
	for _, n := range names {
		g, err := client.RequireGroup(n)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// confirmAction asks before a write.
func confirmAction(title string) (bool, error) {
	var ok bool
	err := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().Title(title).Affirmative("Yes").Negative("Cancel").Value(&ok),
	)).Run()
	return ok, err
}

// pause holds output on screen until the operator is ready to go back to the
// menu, which would otherwise repaint over it immediately.
func pause() error {
	var ok bool
	return huh.NewForm(huh.NewGroup(
		huh.NewConfirm().Title("").Affirmative("Back to menu").Negative("").Value(&ok),
	)).Run()
}

// notBlank builds a validator requiring a non-empty value.
func notBlank(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", what)
		}
		return nil
	}
}

// optionalNumber accepts a blank value or a positive integer.
func optionalNumber(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return errors.New("must be a number, or blank to allocate one")
	}
	if n <= 0 {
		return errors.New("must be a positive number")
	}
	return nil
}

// emailHint explains what a blank email will become.
func emailHint(client *directory.Client) string {
	if d := client.Profile.MailDomain; d != "" {
		return "Leave blank to use <username>@" + d
	}
	return "Optional."
}

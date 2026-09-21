package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/aldo/ldap-cli/internal/directory"
)

func (a *app) groupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Create and inspect groups",
	}
	cmd.AddCommand(
		a.groupCreateCmd(),
		a.groupListCmd(),
		a.groupShowCmd(),
	)
	return cmd
}

func (a *app) groupCreateCmd() *cobra.Command {
	var (
		gid         int
		description string
	)

	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a posixGroup with a generated gidNumber",
		Long: "Creates a posixGroup. The gidNumber comes from the profile's gid range unless " +
			"--gid is given, in which case it is checked for collisions first.",
		Args:    cobra.ExactArgs(1),
		Example: "  ldap-cli --profile prod group create developers --description 'Dev team'",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := a.connect()
			if err != nil {
				return err
			}

			g, err := client.CreateGroup(directory.NewGroup{
				CN:          args[0],
				GIDNumber:   gid,
				Description: description,
			})
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if a.jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"cn":          g.CN,
					"dn":          g.DN,
					"gid_number":  g.GIDNumber,
					"description": g.Description,
				})
			}

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "created\t%s\n", g.DN)
			fmt.Fprintf(tw, "cn\t%s\n", g.CN)
			fmt.Fprintf(tw, "gidNumber\t%d\n", g.GIDNumber)
			if g.Description != "" {
				fmt.Fprintf(tw, "description\t%s\n", g.Description)
			}
			return tw.Flush()
		},
	}

	f := cmd.Flags()
	f.IntVar(&gid, "gid", 0, "explicit gidNumber (default: allocate from the profile's gid range)")
	f.StringVar(&description, "description", "", "group description")
	return cmd
}

func (a *app) groupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the groups under the profile's group base",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := a.connect()
			if err != nil {
				return err
			}

			groups, err := client.ListGroups()
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if a.jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(groups)
			}

			if len(groups) == 0 {
				fmt.Fprintf(out, "no groups under %s\n", client.Profile.GroupBaseDN)
				return nil
			}

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "GROUP\tGID\tMEMBERS\tDESCRIPTION")
			for _, g := range groups {
				fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", g.CN, g.GIDNumber, len(g.MemberUIDs), g.Description)
			}
			return tw.Flush()
		},
	}
}

func (a *app) groupShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a group and its members",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := a.connect()
			if err != nil {
				return err
			}

			g, err := client.RequireGroup(args[0])
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if a.jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(g)
			}

			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "dn\t%s\n", g.DN)
			fmt.Fprintf(tw, "cn\t%s\n", g.CN)
			fmt.Fprintf(tw, "gidNumber\t%d\n", g.GIDNumber)
			if g.Description != "" {
				fmt.Fprintf(tw, "description\t%s\n", g.Description)
			}
			fmt.Fprintf(tw, "members\t%s\n", strings.Join(g.MemberUIDs, ", "))
			return tw.Flush()
		},
	}
}

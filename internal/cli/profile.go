package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func (a *app) profileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Inspect the configured servers",
	}
	cmd.AddCommand(a.profileListCmd())
	return cmd
}

func (a *app) profileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the profiles in the config file",
		Long: "Lists the configured servers. No passwords are stored in the config file, " +
			"so nothing secret is printed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}

			type row struct {
				Name        string `json:"name"`
				Default     bool   `json:"default"`
				URL         string `json:"url"`
				Encrypted   bool   `json:"encrypted"`
				BindDN      string `json:"bind_dn"`
				UserBaseDN  string `json:"user_base_dn"`
				GroupBaseDN string `json:"group_base_dn"`
			}

			var rows []row
			for _, name := range cfg.ProfileNames() {
				p := cfg.Profiles[name]
				rows = append(rows, row{
					Name:        name,
					Default:     name == cfg.DefaultProfile,
					URL:         p.URL,
					Encrypted:   p.Encrypted(),
					BindDN:      p.BindDN,
					UserBaseDN:  p.UserBaseDN,
					GroupBaseDN: p.GroupBaseDN,
				})
			}

			out := cmd.OutOrStdout()
			if a.jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"config": cfg.Path, "profiles": rows})
			}

			fmt.Fprintf(out, "config: %s\n\n", cfg.Path)
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PROFILE\tURL\tTLS\tBIND DN\tUSER BASE")
			for _, r := range rows {
				name := r.Name
				if r.Default {
					name += " (default)"
				}
				tls := "yes"
				if !r.Encrypted {
					tls = "NO"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, r.URL, tls, r.BindDN, r.UserBaseDN)
			}
			return tw.Flush()
		},
	}
}

// Command ldap-cli provisions users and groups on OpenLDAP servers.
package main

import (
	"os"

	"github.com/aldo/ldap-cli/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}

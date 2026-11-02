package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "opx",
	Short: "A 1Password-like password manager CLI",
	Long:  "opx is a simplified password manager CLI inspired by 1Password CLI.",
}

func init() {
	rootCmd.AddCommand(signinCmd)
	rootCmd.AddCommand(signoutCmd)
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(vaultCmd)
	rootCmd.AddCommand(itemCmd)
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(copyCmd)
	rootCmd.AddCommand(totpCmd)
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(sshCmd)
	rootCmd.AddCommand(srpCmd)
	rootCmd.AddCommand(serviceAccountCmd)
	rootCmd.AddCommand(pluginCmd)
	rootCmd.AddCommand(eventsCmd)
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(desktopCmd)
	rootCmd.AddCommand(cloudSyncCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(codesignCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(doctorCmd)

	// Add completion command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletion(os.Stdout)
			case "zsh":
				return rootCmd.GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	})
}

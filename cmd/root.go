// Package cmd contains all CLI commands for GoSentinel.
// Commands are registered here and wired up via Cobra.
package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var banner = `
 ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝ ██╔═══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██║  ███╗██║   ██║███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██║   ██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
╚██████╔╝╚██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
`

// rootCmd is the base command. Every other subcommand is attached to this.
var rootCmd = &cobra.Command{
	Use:   "gosentinel",
	Short: "GoSentinel — OWASP Top 10 web vulnerability scanner",
	Long: color.CyanString(banner) + "\n" +
		color.WhiteString("GoSentinel is a fast, concurrent web vulnerability scanner\n") +
		color.WhiteString("built to detect OWASP Top 10 issues in target web applications.\n"),
	// Don't print usage on every error — keeps output clean.
	SilenceUsage: true,
}

// Execute is called by main.go. It runs the root command and exits on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, color.RedString("Error: %s", err))
		os.Exit(1)
	}
}

func init() {
	// Persistent flags are inherited by all subcommands.
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
}

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
   ______      _____            _   _             _ 
  / ____/___  / ___/___  ____  / /_(_)___  ___  / / 
 / / __/ __ \ \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /  
/ /_/ / /_/ /___/ /  __/ / / / /_/ / / / /  __/ /   
\____/\____//____/\___/_/ /_/\__/_/_/ /_/\___/_/    
                                                    
`

// rootCmd is the base command. Every other subcommand is attached to this.
var rootCmd = &cobra.Command{
	Use:   "gosentinel",
	Short: "GoSentinel — OWASP Top 10 web vulnerability scanner",
	Long: color.CyanString(banner) + "\n" +
		color.WhiteString(" GoSentinel is a premium, high-performance web vulnerability scanner\n") +
		color.WhiteString(" designed to identify OWASP Top 10 risks with surgical precision.\n\n") +
		hiWhite(" Core Pillars:\n") +
		cyan("  • Intelligent BFS Crawler  ") + white("Recursively maps the attack surface with scope protection.\n") +
		cyan("  • Parallel Engine          ") + white("Orchestrates multiple security modules concurrently.\n") +
		cyan("  • Advanced Injection       ") + white("Handles complex multi-phase detections (e.g. Stored XSS).\n") +
		cyan("  • Aggregated Reporting     ") + white("Generates clean HTML dashboards and structured JSON data.\n"),
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

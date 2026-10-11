// ghost-detect enumerates pinned BPF objects and XDP/TC attachments.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/academic-redteam/ghostnic/pkg/detector"
	"github.com/spf13/cobra"
)

func main() {
	var jsonOut bool

	root := &cobra.Command{
		Use:   "ghost-detect",
		Short: "Detect pinned BPF objects and XDP/TC attachments",
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := detector.Scan()
			if err != nil {
				return err
			}

			if jsonOut {
				b, err := json.MarshalIndent(report, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(b))
				return nil
			}

			fmt.Printf("Pinned BPF objects (%d):\n", len(report.PinnedObjects))
			for _, o := range report.PinnedObjects {
				fmt.Printf("  [%s] %s id=%d name=%q type=%s\n",
					o.Type, o.Path, o.ID, o.Name, o.BPFType)
			}

			fmt.Printf("\nInterface attachments:\n")
			for _, a := range report.Interfaces {
				fmt.Printf("  %s: xdp_prog_id=%d\n", a.Name, a.XDPProgID)
				if a.TCFilters != "" {
					fmt.Printf("    TC egress filters:\n%s\n", a.TCFilters)
				}
			}
			return nil
		},
	}

	root.Flags().BoolVarP(&jsonOut, "json", "j", false, "emit JSON output")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

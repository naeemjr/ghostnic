// Package loader embeds the compiled eBPF objects into the binary so that
// ghost-load is self-contained and does not depend on a runtime `build/`
// directory.  If the embedded objects are unavailable, the loader falls back
// to the on-disk `build/` directory for development workflows.
package loader

import (
	"bytes"
	"path/filepath"

	ghostnic "github.com/academic-redteam/ghostnic"
	"github.com/academic-redteam/ghostnic/pkg/obfuscate"
	"github.com/cilium/ebpf"
)

// loadCollectionSpecFromAnywhere tries to load an eBPF collection spec from
// the embedded object first, then from the on-disk build/ directory.
func loadCollectionSpecFromAnywhere(name string) (*ebpf.CollectionSpec, error) {
	var embedded []byte
	switch name {
	case obfuscate.Decode(obfuscate.Oghost_dns_hijack):
		embedded = ghostnic.EmbeddedDNSHijack
	case obfuscate.Decode(obfuscate.Oghost_tc):
		embedded = ghostnic.EmbeddedTC
	}

	if len(embedded) > 0 {
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embedded))
		if err == nil {
			return spec, nil
		}
	}

	return ebpf.LoadCollectionSpec(filepath.Join(objectDir, name+".o"))
}

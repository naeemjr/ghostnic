//go:build !nobpf

// Package ghostnic embeds the compiled eBPF objects so the loader is
// self-contained and does not require a runtime build/ directory.
//
// The embedded objects are produced by `make` (clang + bpftool). When they are
// absent (e.g. a source-only checkout or offline CI), build with `-tags nobpf`
// to use the stub in assets_nobpf.go instead. The loader then has no embedded
// programs and cannot attach anything — which is the intended safe posture for
// review/CI that must never load BPF.
package ghostnic

import _ "embed"

//go:embed build/ghost_dns_hijack.o
var EmbeddedDNSHijack []byte

//go:embed build/ghost_tc.o
var EmbeddedTC []byte

//go:embed build/ghost_xdp.o
var EmbeddedXDP []byte

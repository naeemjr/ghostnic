//go:build nobpf

// Package ghostnic — offline/source-only stub.
//
// Built with `-tags nobpf`, this replaces the //go:embed of the compiled eBPF
// objects with empty byte slices so the Go tree builds and tests without the
// `build/*.o` artifacts (which require clang + bpftool via `make`). With no
// embedded programs the loader cannot attach anything; this is the safe
// posture for code review and CI that must never compile or load BPF.
package ghostnic

// EmbeddedDNSHijack is empty in nobpf builds (no compiled eBPF object).
var EmbeddedDNSHijack []byte

// EmbeddedTC is empty in nobpf builds (no compiled eBPF object).
var EmbeddedTC []byte

// EmbeddedXDP is empty in nobpf builds (no compiled eBPF object).
var EmbeddedXDP []byte

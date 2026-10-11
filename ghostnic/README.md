# GhostNIC

GhostNIC is a research framework that demonstrates purely passive, zero-socket
eBPF offensive tradecraft on compromised IoT/Edge Linux gateways.  The implant
never creates a socket, never spawns a process after initial load, and never
generates new packets.  It observes and subtly modifies in-flight packets at
the XDP (ingress) and TC (egress) layers.

This repository is intended for academic red-team research, defensive training,
and controlled lab environments.  It is **not** a weapon for unauthorized
networks.

## Research significance

Traditional implants rely on sockets, processes, or kernel modules to maintain
presence and manipulate traffic.  GhostNIC explores an alternative model: the
attacker moves the entire offensive capability into the kernel's packet
processing path and then removes the loader.  eBPF programs persist while
attached to network interfaces, so the implant survives even when no userspace
process remains.

The framework highlights:

* **DNS hijacking** in XDP: forge IPv4/IPv6 DNS responses and transmit them
  with `XDP_TX`.
* **MQTT steganography** in TC: encode covert bits in the parity of fractional
  digits.
* **Flow-record deception** through source-address rewriting.
* **C2 suppression**: drop outbound TCP SYNs to configured C2 endpoints and
  strip TLS SNI from ClientHello messages.
* **Minimal footprint**: no sockets, no new processes, anonymous maps, optional
  loader self-destruction, and Go string obfuscation.
* **Defensible counterpart**: a detector utility enumerates pinned BPF objects
  and XDP/TC attachments.

## Architecture

```text
                       +-----------------------------+
                       |     IoT/Edge Gateway        |
                       |  +-----------------------+  |
  ingress DNS query    |  | XDP: ghost_dns_hijack |  |  forge A/AAAA response
  -------------------->|  | - dns_targets         |  |  and return XDP_TX
                       |  | - dns6_targets        |  |
                       |  +-----------------------+  |
                       |           |                 |
                       |     kernel network stack     |
                       |           |                 |
                       |  +-----------------------+  |
  egress traffic       |  | TC:  ghost_tc         |  |  MQTT stego, netflow
  -------------------->|  | - c2_targets          |  |  poisoning, C2 SYN
                       |  | - netflow_collectors  |  |  drop, TLS SNI strip
                       |  | - mqtt_* maps         |  |
                       |  +-----------------------+  |
                       +-----------------------------+
```

## Prerequisites

* Linux kernel >= 5.4 with `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`,
  `CONFIG_XDP_SOCKETS`, and `CONFIG_NET_CLS_BPF` enabled.
* `clang` (preferred) or `zig` for compiling BPF, plus `bpftool`.
* Go 1.22+ and a working C compiler for the Go toolchain.
* `tc` from iproute2 for attaching the egress classifier.
* CAP_BPF/CAP_NET_ADMIN or root for loading and attaching programs.

## Quick start

```bash
# Clone the repository
git clone https://github.com/academic-redteam/ghostnic.git
cd ghostnic

# Build BPF objects and Go binaries
make all

# Review the example configuration (optional — CLI flags are sufficient)
cp ghostnic.json.example ghostnic.json
# edit ghostnic.json to match your lab interface and targets

# Load the implant (requires root or CAP_BPF)
sudo ./build/ghost-load --config ghostnic.json --self-destruct

# Or load without any config file
sudo ./build/ghost-load \
  --iface eth0 \
  --dns evil.example.com:10.0.0.99 \
  --dns6 evil.example.com:2001:db8::99 \
  --c2 192.0.2.100:443 \
  --netflow 192.168.1.100:2055:192.168.1.1 \
  --self-destruct

# Verify attachments (maps are anonymous by default)
sudo ./build/ghost-detect

# Remove everything
sudo ./build/ghost-ctl unload --iface eth0
```

## Self-contained deployment

The compiled eBPF objects are embedded into `ghost-load`, so the loader is a
single binary that does not require a `build/` directory at runtime. Rebuild
the objects for a different kernel with `make bpf` or `make release-bpf`.

## Build targets

| Target             | Description                                              |
|--------------------|----------------------------------------------------------|
| `make all`         | Compile BPF objects and build Go binaries                |
| `make bpf`         | Compile `ghost_xdp.o`, `ghost_tc.o`, `ghost_dns_hijack.o`|
| `make go`          | Build `ghost-load`, `ghost-ctl`, `ghost-detect`          |
| `make release-bpf` | Compile BPF without debug info                           |
| `make release`     | Build Go binaries with `garble` and stripped BPF         |
| `make arm64`       | Cross-compile userspace binaries for Linux/arm64         |
| `make test`        | Run Go unit tests and BPF artifact tests                 |
| `make docker-test` | Spin up the integration lab and run tests                |
| `make clean`       | Remove build artifacts and pinned objects                |
| `make vmlinux`     | Regenerate `bpf/vmlinux.h` from kernel BTF               |

## Persistence

A systemd service template is provided in `scripts/network-metrics.service`.
Run `sudo IFACE=eth0 CONFIG=/etc/network-metrics/config.json scripts/persist.sh`
to install the loader as `network-metrics.service` and enable it on boot.

## Red team usage

See [`docs/OFFENSIVE.md`](docs/OFFENSIVE.md) for the full playbook:
initial access, loading, operating, and cleanup.

## Blue team detection

See [`docs/DEFENSIVE.md`](docs/DEFENSIVE.md) for how to detect pinned BPF
objects, audit XDP/TC attachments, and harden the kernel.

## Implementation details

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for map schemas, packet flow
diagrams, verifier constraints, and design trade-offs.

## Threat model

See [`docs/THREATMODEL.md`](docs/THREATMODEL.md) for a formal threat model and
ethical-use statement suitable for academic peer review.

## Ethical use and license

GhostNIC is released for authorized security research and education only.
Always obtain explicit permission before running this code on any system you
do not own.

* eBPF C code: **GPL-2.0**
* Go userspace code: **MIT**

Use it responsibly.

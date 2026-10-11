# GhostNIC defensive guide

GhostNIC is intentionally detectable by a vigilant defender.  This guide covers
how to enumerate pinned BPF objects, audit XDP and TC attachments, and harden
the kernel against this class of implant.

## Detection philosophy

Because GhostNIC avoids sockets, processes, and new packets, traditional
host-based indicators (listening ports, process trees, network connections) are
not reliable.  Detection must focus on:

* XDP programs attached to network interfaces.
* TC `clsact` filters, especially egress classifiers.
* Pinned BPF objects in `/sys/fs/bpf/` (modern variants may leave none).
* Unexpected DNS responses and MQTT payload anomalies.
* Hidden systemd services that load eBPF objects on boot.

## Using ghost-detect

The repository includes a blue-team utility:

```bash
sudo ./build/ghost-detect
sudo ./build/ghost-detect --json
```

It reports:

* Every pinned program and map under `/sys/fs/bpf/`.
* The XDP program ID for each interface.
* Egress TC filters for each interface.

## Manual audit

### Enumerate pinned objects

```bash
find /sys/fs/bpf/ -type f
ls -la /sys/fs/bpf/ghostnic/ 2>/dev/null || echo "no ghostnic pins"
ls -la /sys/fs/bpf/ksysdbg 2>/dev/null || echo "no ksysdbg pin"
```

A stealthy deployment may not pin program or map paths; however, the shared
control flag is pinned so it can be updated by the operator.  Continue with
the checks below.

### List loaded BPF programs

```bash
sudo bpftool prog list
sudo bpftool prog show id <ID>
```

### Inspect XDP attachments

```bash
for iface in /sys/class/net/*/; do
    name=$(basename "$iface")
    id=$(cat "$iface/xdp/prog_id" 2>/dev/null || echo 0)
    echo "$name: xdp_prog_id=$id"
done
```

### Inspect TC classifiers

```bash
for iface in /sys/class/net/*/; do
    name=$(basename "$iface")
    echo "=== $name egress ==="
    sudo tc filter show dev "$name" egress
done
```

### Audit systemd persistence

```bash
systemctl list-unit-files --type=service | grep -E 'network-metrics|metrics'
systemctl cat network-metrics.service 2>/dev/null
```

## Network-level detection

* **DNS anomalies**: Compare responses from multiple resolvers.  Forged A or
  AAAA records will diverge between the compromised gateway and a clean
  resolver, and forged responses may arrive faster than legitimate ones.
* **Telemetry integrity**: Baseline MQTT payload fields.  Repeated low-entropy
  changes to the least significant fractional digit of numeric fields may
  indicate steganographic injection.
* **Netflow consistency**: Correlate flow records with packet captures.  Source
  address mismatches between sampled flows and raw packets can reveal
  poisoning.
* **TLS anomalies**: Missing or zeroed SNI values in ClientHello messages may
  indicate SNI stripping.
* **C2 suppression**: Outbound TCP SYNs to known C2 endpoints that never
  complete a handshake may indicate SYN dropping.

## Kernel hardening

* Restrict loading of BPF programs to trusted administrators.
* Monitor mounts of `bpffs` and creations under `/sys/fs/bpf/`.
* Consider locking down `CAP_BPF` via capabilities, LSM, or privileged
  container policies.
* Disable unneeded `CONFIG_BPF_KPROBE_OVERRIDE` and similar features that allow
  BPF to modify kernel behavior beyond networking.
* Log `bpf()` syscalls with auditd or eBPF-based audit tools.

## Detection rules

### Sigma: pinned object creation

```yaml
title: Suspicious BPF object pinned
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|startswith: /sys/fs/bpf/
  condition: selection
falsepositives:
  - Legitimate systemd or container runtime pinning
level: medium
```

### Sigma: XDP or TC attachment

```yaml
title: Suspicious network BPF attachment
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'ip link set'
      - 'xdp'
      - 'tc filter add'
      - 'clsact'
  condition: selection
falsepositives:
  - Legitimate container networking or DDoS protection tools
level: medium
```

### YARA: loader binary

A simple YARA rule can flag the loader by its combination of strings.  Note
that obfuscated builds may not contain these literals:

```yara
rule GhostNIC_Loader {
    strings:
        $a = "/sys/fs/bpf/ghostnic"
        $b = "ghost_xdp"
        $c = "ghost_tc"
        $d = "self-destruct"
    condition:
        uint16(0) == 0x5a4d and 2 of ($a, $b, $c, $d)
}
```

## Response

If GhostNIC is detected:

1. Preserve any `/sys/fs/bpf/` contents and `bpftool prog list` output for
   analysis.
2. Detach the XDP program and remove the TC filter.
3. Delete any pinned objects.
4. Inspect systemd services for hidden loaders.
5. Re-image or restore the gateway from a known-good baseline.
6. Investigate how the attacker gained the privileges required to load BPF.

# GhostNIC Threat Model

This document provides a formal threat model for the GhostNIC research
framework.  It is intended to support academic peer review and to guide
defensive operators who evaluate the implant in controlled lab environments.

## Scope and Assumptions

GhostNIC is designed to demonstrate purely passive eBPF offensive tradecraft
on a compromised Linux gateway.  The following assumptions bound the model:

* **Compromised gateway**: the attacker already has root or the equivalent
  capabilities (`CAP_BPF` + `CAP_NET_ADMIN`) on the target system.
* **Bpffs mounted**: `/sys/fs/bpf/` is available, which is the default on
  modern Linux distributions.
* **Kernel support**: the target kernel exposes eBPF, XDP and TC clsact
  (Linux >= 5.4, validated on 5.15+).
* **Physical or logical gateway position**: the implant can observe and
  modify traffic that transits the compromised host.
* **Authorized research**: the framework is used only on networks and devices
  for which the operator has explicit permission.

## Assets

| Asset | Value | Location |
|-------|-------|----------|
| DNS resolution integrity | High | Outbound DNS responses |
| MQTT telemetry integrity | High | Outbound IoT telemetry |
| Flow-record audit trail | High | NetFlow/IPFIX exports |
| Gateway integrity | Critical | Kernel packet path |
| Operational stealth | High | Absence of userspace processes/sockets |

## Threat Actors

* **External red-team operator**: loads GhostNIC, configures targets, and
  exfiltrates data through passive manipulation.
* **Insider with root access**: uses the framework to redirect internal
  services or hide malicious activity.
* **Defensive analyst**: audits the gateway for pinned BPF objects and
  unexpected XDP/TC attachments.

## Attack Tree (High Level)

```
Compromise gateway with root/CAP_BPF
    |
    +--> Transfer loader binary
    |       |
    |       +--> Obfuscated binary (garble / XOR strings)
    |
    +--> Load implant
    |       |
    |       +--> Attach XDP DNS hijacker
    |       +--> Attach TC egress program
    |       +--> Self-destruct loader
    |
    +--> Achieve objective
            |
            +--> Redirect DNS A/AAAA records
            +--> Exfiltrate via MQTT steganography
            +--> Sanitize NetFlow source addresses
            +--> Block C2 SYNs / strip TLS SNI
```

## Mitigations and Countermeasures

| Threat | Mitigation |
|--------|------------|
| Unauthorized BPF load | Restrict `CAP_BPF`; monitor `bpf()` syscalls; use LSM profiles. |
| Persistent implant | Audit `/sys/fs/bpf/`, XDP prog IDs and TC egress filters. |
| DNS hijacking | Compare resolver responses from multiple vantage points. |
| MQTT steganography | Baseline numeric fields; detect parity anomalies. |
| NetFlow poisoning | Correlate sampled flows with raw packet captures. |
| Loader reappearance | File-integrity monitoring; detect hidden systemd services. |

## Ethics and Legal Use

GhostNIC is released for authorized security research, defensive training and
controlled red-team exercises only.  Operators must obtain explicit written
permission before running the code on any system they do not own or operate.
The authors disclaim responsibility for unauthorized use.

## Risk Rating

* **Likelihood**: Low for well-hardened kernels; Medium for default IoT/edge
  gateways with broad capabilities.
* **Impact**: High, because the implant operates in the kernel packet path
  and can subvert multiple network security controls.
* **Overall risk**: High for targets that have not restricted BPF privileges
  and do not monitor XDP/TC attachments.

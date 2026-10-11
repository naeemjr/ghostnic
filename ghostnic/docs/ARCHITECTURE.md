# GhostNIC architecture

This document describes the design of the GhostNIC eBPF implant, the map
schemas it uses, and how the XDP and TC programs satisfy the kernel verifier.

## Attachment points

### XDP ingress (`bpf/ghost_dns_hijack.c`)

The XDP program attaches to the receive path of a network interface.  It runs
before skbs are allocated, so it is extremely cheap.  GhostNIC uses it to
forge DNS responses for matching IPv4 A and IPv6 AAAA queries and return them
via `XDP_TX`.

### TC egress (`bpf/ghost_tc.c`)

The TC program attaches to the egress qdisc (`clsact`) of a network interface.
It operates on fully-formed skbs and can use helpers such as
`bpf_skb_store_bytes`, `bpf_l3_csum_replace`, and `bpf_l4_csum_replace`.  This
makes it suitable for MQTT payload injection, netflow source-address
poisoning, TLS SNI stripping, and C2 SYN dropping.

## Packet flow

```text
 ingress                                          egress
   |                                                |
   v                                                |
 +----------------+                                  |
 | XDP DNS hijack | forge response, return XDP_TX   |
 | parse eth/ip/  |                                  |
 | udp/dns v4/v6  |                                  |
 +----------------+                                  |
   |                                                |
 kernel network stack                               |
   |                                                |
   v                                                |
 +----------------+ <--------------------------------+
 | TC  ghost_tc   |
 | parse eth/ip/  |
 | tcp or udp     |
 +----------------+
```

## Map schemas

### `dns_targets` (XDP)

| Field | Type   | Description                          |
|-------|--------|--------------------------------------|
| key   | `struct dns_key` | null-terminated queried domain name |
| value | `__u32`          | big-endian IPv4 address to inject   |

### `dns6_targets` (XDP)

| Field | Type   | Description                          |
|-------|--------|--------------------------------------|
| key   | `struct dns_key`  | null-terminated queried domain name |
| value | `struct dns6_value` | 16-byte IPv6 address to inject    |

### `c2_targets` (TC)

| Field | Type   | Description                              |
|-------|--------|------------------------------------------|
| key   | `struct c2_key`   | IPv4 address + port                   |
| value | `__u8`            | presence flag                         |

### `netflow_collectors` (TC)

| Field | Type   | Description                          |
|-------|--------|--------------------------------------|
| key   | `struct nf_key`   | collector IPv4 address + port   |
| value | `struct nf_value` | benign IPv4 source address      |

### `mqtt_baseline` (TC)

| Field | Type            | Description                        |
|-------|-----------------|------------------------------------|
| key   | `__u32`         | fixed index 0                      |
| value | `struct mqtt_baseline` | average size and +/- window |

### `mqtt_encoder` (TC)

| Field | Type             | Description                    |
|-------|------------------|--------------------------------|
| key   | `__u32`          | fixed index 0                  |
| value | `struct mqtt_encoder` | XOR key and encoding mode  |

### `mqtt_hidden` (TC)

| Field | Type   | Description                              |
|-------|--------|------------------------------------------|
| key   | `__u32`| byte index 0..255                        |
| value | `__u8` | hidden message byte (length-prefixed and XORed) |

### `mqtt_idx` (TC)

| Field | Type   | Description                              |
|-------|--------|------------------------------------------|
| key   | `__u32`| fixed index 0                            |
| value | `__u32`| current bit index into `mqtt_hidden`     |

### `mqtt_scratch` (TC)

| Field | Type                  | Description                       |
|-------|-----------------------|-----------------------------------|
| key   | `__u32`               | fixed index 0                     |
| value | `struct mqtt_scratch` | 512-byte per-CPU JSON buffer      |

## DNS response forging

1. Parse Ethernet, IPv4 or IPv6, and UDP headers.
2. Bail out unless the packet is a UDP query to destination port 53.
3. Walk the DNS question section and copy labels into a dot-separated string.
4. Look up the string in `dns_targets` (A) or `dns6_targets` (AAAA).
5. Verify the query is A/IN or AAAA/IN and has a single question.
6. Rewrite the packet in-place into a response:
   * Swap Ethernet, IP and UDP source/destination addresses/ports.
   * Append a single answer record pointing back at the question name.
   * Update IP total length and IPv6 payload length.
   * Recompute IPv4 header checksum and UDP checksum (with pseudo-header).
7. Return `XDP_TX`.

The program verifies that the forged response still fits inside the received
packet buffer before writing.

## MQTT telemetry injection

1. Parse Ethernet, IPv4, and TCP headers.
2. Bail out unless the destination port is 1883 and the MQTT fixed header
   indicates a PUBLISH message (`0x30` or `0x32`).
3. Decode the MQTT remaining length, topic length, and optional packet ID.
4. Load the JSON payload into the per-CPU `mqtt_scratch` map.
5. Find the first numeric value with a fractional part.
6. Read the next bit from `mqtt_hidden` using `mqtt_idx`.
7. Adjust the parity of the last fractional digit to encode the bit.
8. Write the digit back with `bpf_skb_store_bytes` and
   `BPF_F_RECOMPUTE_CSUM`.

The hidden message is length-prefixed and XORed with the configured key
before being written to `mqtt_hidden`; the provided decoder reverses the
process.

## Netflow poisoning

1. Parse the IPv4 header and determine the L4 protocol and destination port.
2. Look up the destination in `netflow_collectors`.
3. If matched, replace the IPv4 source address with the benign value.
4. Update the IPv4 checksum with `bpf_l3_csum_replace`.
5. Update the L4 checksum with `bpf_l4_csum_replace` and
   `BPF_F_PSEUDO_HDR`.

## C2 SYN drop

For every outbound TCP packet the TC program checks the SYN flag and
destination against `c2_targets`.  Matching pure SYNs (no ACK) are dropped
with `TC_ACT_SHOT`.

## TLS SNI stripping

For outbound TCP packets to port 443 the TC program parses a bounded portion
of the TLS ClientHello and, when a Server Name Indication extension is found,
overwrites the list length, name type, name length and hostname bytes with
zeros in-place.

## Verifier compliance

The programs obey the following verifier-friendly rules:

* All loops have compile-time-known upper bounds.
* Packet accesses are guarded by `data_end` checks before dereference.
* The large JSON scan buffer lives in a per-CPU map instead of the stack.
* `bpf_skb_load_bytes` is used when direct pointer access would require
  unbounded offsets.
* Helper return values are checked where the verifier requires it.

## CO-RE and BTF

The build emits BTF information with `-g` for debug builds.  Release builds
use `make release-bpf` which omits `-g`, producing smaller objects with fewer
symbols.  On kernels that expose `/sys/kernel/btf/vmlinux`, `make vmlinux`
regenerates `bpf/vmlinux.h`.  The stable networking types used by GhostNIC are
also available through the Linux UAPI headers, which makes compilation
possible even when kernel BTF is not mounted.

## Covert control channel

A single `control_flag` array map is shared between the XDP and TC programs.
It is pinned to an obfuscated bpffs path at load time so that userspace can
update it after the loader exits.  The flag is a bitmask:

* `CTL_DISABLE_MQTT` (0x01)
* `CTL_DISABLE_NETFLOW` (0x02)
* `CTL_DISABLE_C2` (0x04)

The XDP program detects DNS queries whose name begins with `trigger.` and
toggles the flag.  The TC program detects ICMP echo requests with the same
magic prefix in their payload and toggles the flag as well.  The TC program
reads the flag at the start of each packet path and skips gated features when
the corresponding bit is set.  `ghost-ctl trigger <flag>` provides a direct
userspace update path.

## Operational security

* Maps are kept anonymous by default; only the shared `control_flag` map is
  pinned, and only the TC program is briefly pinned during attachment.
* The loader overwrites its own binary with zeros before unlinking it when
  `--self-destruct` is used.
* Sensitive strings in the Go binaries are XOR obfuscated at build time via
  `scripts/genobf.go`.  The `make release` target additionally builds the
  userspace tooling with `garble`.

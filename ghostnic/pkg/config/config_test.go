package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadAndParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfgIn := `{
		"interface": "eth0",
		"dns_targets": {"firmware.update.iot": "10.0.0.99"},
		"netflow_collectors": [{"address": "192.168.1.100", "port": 2055, "spoof": "192.168.1.1"}],
		"mqtt_baseline": {"average": 150, "window": 10},
		"mqtt_encoder": {"key": 31337, "mode": 0},
		"mqtt_hidden_message": "GHOST"
	}`
	require.NoError(t, os.WriteFile(path, []byte(cfgIn), 0644))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, "eth0", cfg.Interface)
	require.Equal(t, "10.0.0.99", cfg.DNSTargets["firmware.update.iot"])

	ip, err := ParseIPv4("10.0.0.99")
	require.NoError(t, err)
	require.Equal(t, uint32(0x0a000063), ip)
}

func TestRaisedLimits(t *testing.T) {
	label := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 63 chars
	longDomain := label + "." + label + "." + label + ".aa"                    // 194 chars
	_, err := PackDNSKey(longDomain)
	require.NoError(t, err)

	_, err = PackDNSKey(string(make([]byte, DNSMaxName)))
	require.Error(t, err)

	hidden := make([]byte, MQTTPayloadMax)
	for i := range hidden {
		hidden[i] = 'x'
	}
	cfg := &Config{Interface: "eth0", HiddenMsg: string(hidden)}
	b, err := json.Marshal(cfg)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "cfg.json")
	require.NoError(t, os.WriteFile(path, b, 0644))
	_, err = Load(path)
	require.NoError(t, err)
}

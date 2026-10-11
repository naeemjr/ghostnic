//go:build !nobpf

// This test verifies the embedded compiled eBPF objects produced by `make`.
// It only applies to the full build; under `-tags nobpf` the objects are
// intentionally absent, so the test is excluded there.
package loader

import (
	"testing"

	ghostnic "github.com/academic-redteam/ghostnic"
	"github.com/academic-redteam/ghostnic/pkg/obfuscate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedObjectsAreNonEmpty(t *testing.T) {
	assert.NotEmpty(t, ghostnic.EmbeddedDNSHijack, "embedded DNS hijack object should be present")
	assert.NotEmpty(t, ghostnic.EmbeddedTC, "embedded TC object should be present")
}

func TestLoadCollectionSpecFromEmbedded(t *testing.T) {
	names := []string{
		obfuscate.Decode(obfuscate.Oghost_dns_hijack),
		obfuscate.Decode(obfuscate.Oghost_tc),
	}
	for _, name := range names {
		spec, err := loadCollectionSpecFromAnywhere(name)
		require.NoError(t, err, "loading %s", name)
		require.NotNil(t, spec, "spec for %s", name)
		assert.NotEmpty(t, spec.Programs, "programs in %s", name)
	}
}

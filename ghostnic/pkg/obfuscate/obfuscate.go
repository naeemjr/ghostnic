// Package obfuscate provides simple runtime string deobfuscation.
//
// Sensitive literals are XORed with a per-build key at code-generation time
// (see scripts/genobf.go).  At runtime, strings are decoded on demand using
// ObfKey so they never appear as plaintext in the binary's read-only data.
package obfuscate

// Decode returns the plaintext form of an obfuscated byte slice.
func Decode(in []byte) string {
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[i] ^ ObfKey
	}
	return string(out)
}

// MustDecode is a convenience wrapper for Decode.
func MustDecode(in []byte) string {
	return Decode(in)
}

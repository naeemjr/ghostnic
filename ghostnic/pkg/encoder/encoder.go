// Package encoder implements the GhostNIC steganographic encoder/decoder.
//
// The implant encodes covert data by adjusting the parity of the least
// significant fractional digit of a JSON numeric telemetry value.  An even
// digit represents a zero bit, an odd digit represents a one bit.
package encoder

import (
	"encoding/binary"
	"fmt"
)

const (
	// ModeParity is the default LSB parity encoder.
	ModeParity = 0
)

// EncodeBits turns a plaintext payload into a stream of bits using a simple
// repeating XOR keystream and length prefix.
func EncodeBits(payload []byte, key uint32) ([]int, error) {
	if len(payload) > 255 {
		return nil, fmt.Errorf("payload exceeds 255 bytes")
	}
	framed := make([]byte, 0, len(payload)+1)
	framed = append(framed, byte(len(payload)))
	framed = append(framed, payload...)

	keyBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyBytes, key)

	bits := make([]int, 0, len(framed)*8)
	for i, b := range framed {
		k := keyBytes[i%4]
		x := b ^ k
		for j := 0; j < 8; j++ {
			bits = append(bits, int((x>>j)&1))
		}
	}
	return bits, nil
}

// DecodeBits reconstructs the original payload from a stream of received
// parity bits.
func DecodeBits(bits []int, key uint32) ([]byte, error) {
	if len(bits) < 8 {
		return nil, fmt.Errorf("need at least 8 bits to decode length")
	}
	keyBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyBytes, key)

	out := make([]byte, 0, len(bits)/8)
	for i := 0; i+7 < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i+j] != 0 {
				b |= 1 << j
			}
		}
		k := keyBytes[(i/8)%4]
		out = append(out, b^k)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no bytes decoded")
	}
	length := int(out[0])
	if length+1 > len(out) {
		return nil, fmt.Errorf("incomplete payload: expected %d bytes, got %d", length, len(out)-1)
	}
	return out[1 : length+1], nil
}

// DigitForBit returns a decimal digit whose parity matches bit while staying
// as close as possible to the original digit.
func DigitForBit(original int, bit int) (int, error) {
	if original < 0 || original > 9 {
		return 0, fmt.Errorf("invalid digit %d", original)
	}
	if bit != 0 && bit != 1 {
		return 0, fmt.Errorf("invalid bit %d", bit)
	}
	if (original & 1) == bit {
		return original, nil
	}
	if original == 9 {
		return 8, nil
	}
	return original + 1, nil
}

// BitFromDigit extracts the encoded bit from a decimal digit.
func BitFromDigit(digit int) int {
	return digit & 1
}

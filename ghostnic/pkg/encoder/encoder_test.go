package encoder

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	payload := []byte("GHOST")
	key := uint32(31337)

	bits, err := EncodeBits(payload, key)
	require.NoError(t, err)
	require.NotEmpty(t, bits)

	decoded, err := DecodeBits(bits, key)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, decoded))
}

func TestDigitParity(t *testing.T) {
	cases := []struct {
		orig int
		bit  int
		want int
	}{
		{0, 0, 0},
		{0, 1, 1},
		{5, 0, 6},
		{5, 1, 5},
		{9, 0, 8},
		{9, 1, 9},
	}
	for _, tc := range cases {
		got, err := DigitForBit(tc.orig, tc.bit)
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
		require.Equal(t, tc.bit, BitFromDigit(got))
	}
}

func TestDecodeIncomplete(t *testing.T) {
	_, err := DecodeBits([]int{0, 1}, 0)
	require.Error(t, err)
}

// nolint:gosec // G404: Use of weak random number generator
package test

// From: https://github.com/tendermint/tendermint/blob/a823d167bc615b3a482420efde98c239d14985d1/internal/libs/test/mutate.go

import (
	mrand "math/rand"
)

// Contract: !bytes.Equal(input, output) && len(input) >= len(output)
func MutateByteSlice(bytez []byte) []byte {
	// If bytez is empty, panic
	if len(bytez) == 0 {
		panic("Cannot mutate an empty bytez")
	}

	// Copy bytez
	mBytez := make([]byte, len(bytez))
	copy(mBytez, bytez)
	bytez = mBytez

	// Try a random mutation
	switch mrand.Int() % 2 {
	case 0: // Mutate a single byte
		bytez[mrand.Int()%len(bytez)] += byte(mrand.Int()%255 + 1)
	case 1: // Remove an arbitrary byte
		pos := mrand.Int() % len(bytez)
		bytez = append(bytez[:pos], bytez[pos+1:]...)
	}
	return bytez
}

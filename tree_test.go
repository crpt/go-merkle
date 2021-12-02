package merkle

import (
	"crypto"
	"encoding/hex"
	"testing"
	_ "unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grand "github.com/daotl/guts/rand"

	ctest "github.com/crpt/go-merkle/internal/test"
)

//go:linkname MutateByteSlice github.com/tendermint/tendermint/internal/libs/test.MutateByteSlice
func MutateByteSlice(bytez []byte) []byte

type testItem []byte

func (tI testItem) Hash() []byte {
	return []byte(tI)
}

func TestHashFromByteSlices(t *testing.T) {
	testcases := map[string]struct {
		slices     [][]byte
		expectHash string // in hex format
	}{
		"nil":          {nil, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		"empty":        {[][]byte{}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		"single":       {[][]byte{{1, 2, 3}}, "054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8"},
		"single blank": {[][]byte{{}}, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"},
		"two":          {[][]byte{{1, 2, 3}, {4, 5, 6}}, "82e6cfce00453804379b53962939eaa7906b39904be0813fcadd31b100773c4b"},
		"many": {
			[][]byte{{1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}},
			"f326493eceab4f2d9ffbc78c59432a0a005d6ea98392045c74df5d14a113be18",
		},
	}
	for name, tc := range testcases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			hash := HashFromByteSlices(crypto.SHA256, tc.slices)
			assert.Equal(t, tc.expectHash, hex.EncodeToString(hash))
		})
	}
}

func TestProof(t *testing.T) {
	hashFn := crypto.SHA256

	// Try an empty proof first
	rootHash, proofs := ProofsFromByteSlices(hashFn, [][]byte{})
	require.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex.EncodeToString(rootHash))
	require.Empty(t, proofs)

	total := 100

	items := make([][]byte, total)
	for i := 0; i < total; i++ {
		items[i] = testItem(grand.Bytes(hashFn.Size()))
	}

	rootHash = HashFromByteSlices(hashFn, items)

	rootHash2, proofs := ProofsFromByteSlices(hashFn, items)

	require.Equal(t, rootHash, rootHash2, "Unmatched root hashes: %X vs %X", rootHash, rootHash2)

	// For each item, check the trail.
	for i, item := range items {
		proof := proofs[i]

		// Check total/index
		require.EqualValues(t, proof.Index, i, "Unmatched indicies: %d vs %d", proof.Index, i)

		require.EqualValues(t, proof.Total, total, "Unmatched totals: %d vs %d", proof.Total, total)

		// Verify success
		err := proof.Verify(rootHash, item)
		require.NoError(t, err, "Verification failed: %v.", err)

		// Trail too long should make it fail
		origAunts := proof.Aunts
		proof.Aunts = append(proof.Aunts, grand.Bytes(32))
		err = proof.Verify(rootHash, item)
		require.Error(t, err, "Expected verification to fail for wrong trail length")

		proof.Aunts = origAunts

		// Trail too short should make it fail
		proof.Aunts = proof.Aunts[0 : len(proof.Aunts)-1]
		err = proof.Verify(rootHash, item)
		require.Error(t, err, "Expected verification to fail for wrong trail length")

		proof.Aunts = origAunts

		// Mutating the itemHash should make it fail.
		err = proof.Verify(rootHash, ctest.MutateByteSlice(item))
		require.Error(t, err, "Expected verification to fail for mutated leaf hash")

		// Mutating the rootHash should make it fail.
		err = proof.Verify(ctest.MutateByteSlice(rootHash), item)
		require.Error(t, err, "Expected verification to fail for mutated root hash")
	}
}

func TestHashAlternatives(t *testing.T) {
	hashFn := crypto.SHA256

	total := 100

	items := make([][]byte, total)
	for i := 0; i < total; i++ {
		items[i] = testItem(grand.Bytes(hashFn.Size()))
	}

	rootHash1 := HashFromByteSlicesIterative(hashFn, items)
	rootHash2 := HashFromByteSlices(hashFn, items)
	require.Equal(t, rootHash1, rootHash2, "Unmatched root hashes: %X vs %X", rootHash1, rootHash2)
}

func BenchmarkHashAlternatives(b *testing.B) {
	hashFn := crypto.SHA256

	total := 100

	items := make([][]byte, total)
	for i := 0; i < total; i++ {
		items[i] = testItem(grand.Bytes(hashFn.Size()))
	}

	b.ResetTimer()
	b.Run("recursive", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = HashFromByteSlices(hashFn, items)
		}
	})

	b.Run("iterative", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = HashFromByteSlicesIterative(hashFn, items)
		}
	})
}

func Test_getSplitPoint(t *testing.T) {
	tests := []struct {
		length int64
		want   int64
	}{
		{1, 0},
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 4},
		{10, 8},
		{20, 16},
		{100, 64},
		{255, 128},
		{256, 128},
		{257, 256},
	}
	for _, tt := range tests {
		got := getSplitPoint(tt.length)
		require.EqualValues(t, tt.want, got, "getSplitPoint(%d) = %v, want %v", tt.length, got, tt.want)
	}
}

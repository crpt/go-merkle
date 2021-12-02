package merkle

import (
	"crypto"
	"hash"
)

// TODO: make these have a large predefined capacity
var (
	leafPrefix  = []byte{0}
	innerPrefix = []byte{1}
)

// returns hash(<empty>)
func emptyHash(hashFn crypto.Hash) []byte {
	h := hashFn.New()
	h.Write([]byte{})
	return h.Sum(nil)
}

// returns hash(0x00 || leaf)
func leafHash(hashFn crypto.Hash, leaf []byte) []byte {
	h := hashFn.New()
	h.Write(append(leafPrefix, leaf...))
	return h.Sum(nil)
}

// returns hash(0x00 || leaf)
func leafHashOpt(hash hash.Hash, leaf []byte) []byte {
	hash.Reset()
	hash.Write(leafPrefix)
	hash.Write(leaf)
	return hash.Sum(nil)
}

// returns hash(0x01 || left || right)
func innerHash(hashFn crypto.Hash, left []byte, right []byte) []byte {
	data := make([]byte, len(innerPrefix)+len(left)+len(right))
	n := copy(data, innerPrefix)
	n += copy(data[n:], left)
	copy(data[n:], right)
	h := hashFn.New()
	h.Write(data)
	return h.Sum(nil)
}

func innerHashOpt(s hash.Hash, left []byte, right []byte) []byte {
	s.Reset()
	s.Write(innerPrefix)
	s.Write(left)
	s.Write(right)
	return s.Sum(nil)
}

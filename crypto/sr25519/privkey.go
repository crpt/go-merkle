package sr25519

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/tendermint/tendermint/crypto"

	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

// PrivKeySize is the number of bytes in an Sr25519 private key.
const PrivKeySize = 32

// PrivKey implements crypto.PrivKey.
type PrivKey [PrivKeySize]byte

// Bytes marshals the privkey using amino encoding.
func (privKey PrivKey) Bytes() []byte {
	return cdc.MustMarshalBinaryBare(privKey)
}

// Sign produces a signature on the provided message.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	miniSecretKey, err := schnorrkel.NewMiniSecretKeyFromRaw(privKey)
	if err != nil {
		return []byte{}, err
	}
	secretKey := miniSecretKey.ExpandEd25519()

	signingContext := schnorrkel.NewSigningContext([]byte{}, msg)

	sig, err := secretKey.Sign(signingContext)
	if err != nil {
		return []byte{}, err
	}

	sigBytes := sig.Encode()
	return sigBytes[:], nil
}

// PubKey gets the corresponding public key from the private key.
func (privKey PrivKey) PubKey() crypto.PubKey {
	miniSecretKey, err := schnorrkel.NewMiniSecretKeyFromRaw(privKey)
	if err != nil {
		panic(fmt.Sprintf("Invalid private key: %v", err))
	}
	secretKey := miniSecretKey.ExpandEd25519()

	pubkey, err := secretKey.Public()
	if err != nil {
		panic(fmt.Sprintf("Could not generate public key: %v", err))
	}

	return PubKey(pubkey.Encode())
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if otherEd, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherEd[:]) == 1
	}
	return false
}

// GenPrivKey generates a new sr25519 private key.
// It uses OS randomness in conjunction with the current global random seed
// in tendermint/libs/common to generate the private key.
func GenPrivKey() PrivKey {
	return genPrivKey(crypto.CReader())
}

// genPrivKey generates a new sr25519 private key using the provided reader.
func genPrivKey(rand io.Reader) PrivKey {
	var seed [64]byte

	out := make([]byte, 64)
	_, err := io.ReadFull(rand, out)
	if err != nil {
		panic(err)
	}

	copy(seed[:], out)

	return schnorrkel.NewMiniSecretKey(seed).ExpandEd25519().Encode()
}

// GenPrivKeyFromSecret hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
// NOTE: secret should be the output of a KDF like bcrypt,
// if it's derived from user input.
func GenPrivKeyFromSecret(secret []byte) PrivKey {
	seed := crypto.Sha256(secret) // Not Ripemd160 because we want 32 bytes.
	var bz [PrivKeySize]byte
	copy(bz[:], seed)
	privKey, _ := schnorrkel.NewMiniSecretKeyFromRaw(bz)
	return privKey.ExpandEd25519().Encode()
}
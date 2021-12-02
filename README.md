# Merkle Tree

DAOT Labs' fork of [Tendermint's Merkle Tree implementation](https://github.com/tendermint/tendermint/tree/master/crypto/merkle).

[![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/crpt/go-merkle)

For smaller static data structures that don't require immutable snapshots or mutability; 
for instance the transactions and validation signatures of a block can be hashed using this simple merkle tree logic.

This fork additionally supports specifying the hash function to be used in calculating the merkle tree.

## License

[Apache 2.0](LICENSE)

Copyright for portions of this fork are held by Tendermint as part of the original
[Tendermint Core](https://github.com/tendermint/tendermint) project. All other
copyright for this fork are held by DAOT Labs. All rights reserved.

# sn-merkle-trie

[![Crates.io](https://img.shields.io/crates/v/sn-merkle-trie?style=flat-square&logo=lootcrate)](https://crates.io/crates/sn-merkle-trie)
[![Documentation](https://img.shields.io/docsrs/sn-merkle-trie)](https://docs.rs/sn-merkle-trie)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Minimal implelementation of a [StarkNet MPT](https://docs.starknet.io/architecture-and-concepts/network-architecture/starknet-state/#merkle_patricia_trie).

Heavily rely on [pathfinder's merkle tree implementation](https://github.com/eqlabs/pathfinder/tree/9e0ceec2c56a88ed58b6e49ee7ca6bccd703af33/crates/merkle-tree), but target to make it easy port as external dependency + sync primitives with [type-rs](https://github.com/starknet-io/types-rs).

### Usage

- tx trie

```rust

fn main() {
    // transaction tree either pedersen or poseidon
    let mut tree = TransactionMerkleTree::Pedersen(MerkleTree::default());
    let key1 = from_felt_to_bits(&Felt::from_hex_unchecked("0x0")); // 0b01
    let value_1 = Felt::from_hex_unchecked("0x2");
    // insert key and value
    tree.set(key1.clone(), value_1).unwrap();
    // commit tree to get root
    let (root, root_idx) = tree.commit().unwrap();
    // get proof of inclusion/non-inclusion
    let proof = tree.get_proof(root_idx, key1.clone()).unwrap().unwrap();
    // verify return membership proof
    let mem = tree.verify_proof(root, &key1, value_1, &proof);
}
```

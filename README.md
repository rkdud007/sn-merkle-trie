# SN Merkle Tree

Minimal implelementation of a Merkle Tree used in StarkNet.

Heavily rely on [pathfinder's merkle tree implementation](https://github.com/eqlabs/pathfinder/tree/9e0ceec2c56a88ed58b6e49ee7ca6bccd703af33/crates/merkle-tree), but target to make it easy port as external dependency.

- [x] transaction trie generation / commit / get proof / verify
- [ ] receipt trie generation / commit / get proof / verify
- [ ] sync with type from [type-rs](https://github.com/starknet-io/types-rs)

### Usage

- tx trie

```rust

fn main() {
    // transaction tree height is 64 fix
    let mut tree: MerkleTree<Pedersen, InMememoryStorage, 64> = Default::default();
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

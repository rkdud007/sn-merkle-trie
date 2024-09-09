use bitvec::{order::Msb0, slice::BitSlice};
use starknet_types_core::felt::Felt;

pub mod memory;

use crate::StoredNode;

/// Read-only storage used by the [Merkle tree](crate::tree::MerkleTree).
pub trait Storage {
    /// Returns the node stored at the given index.
    fn get(&self, index: u64) -> anyhow::Result<Option<StoredNode>>;
    /// Returns the hash of the node at the given index.
    fn hash(&self, index: u64) -> anyhow::Result<Option<Felt>>;
    /// Returns the value of the leaf at the given path.
    fn leaf(&self, path: &BitSlice<u8, Msb0>) -> anyhow::Result<Option<Felt>>;
    /// Inserts a leaf into the storage.
    fn insert_leaves(&mut self, key: Felt, value: Felt);

    fn insert_nodes(&mut self, key: u64, value: (Felt, StoredNode));

    fn get_next_index(&self) -> u64;

    fn add_next_index(&mut self, index: u64) -> u64 {
        self.get_next_index() + index
    }
}

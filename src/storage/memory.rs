use std::collections::HashMap;

use bitvec::{order::Msb0, slice::BitSlice};
use starknet_types_core::felt::Felt;

use crate::{conversion::from_bits_to_felt, StoredNode};

use super::Storage;

#[derive(Default, Debug)]
pub struct InMememoryStorage {
    pub nodes: HashMap<u64, (Felt, StoredNode)>,
    pub leaves: HashMap<Felt, Felt>,
    pub next_index: u64,
}

impl Storage for InMememoryStorage {
    fn get(&self, index: u64) -> anyhow::Result<Option<StoredNode>> {
        Ok(self.nodes.get(&index).map(|x| x.1.clone()))
    }

    fn hash(&self, index: u64) -> anyhow::Result<Option<Felt>> {
        Ok(self.nodes.get(&index).map(|x| x.0))
    }

    fn leaf(&self, path: &BitSlice<u8, Msb0>) -> anyhow::Result<Option<Felt>> {
        let key = from_bits_to_felt(path)?;
        Ok(self.leaves.get(&key).cloned())
    }

    fn insert_leaves(&mut self, key: Felt, value: Felt) {
        self.leaves.insert(key, value);
    }

    fn insert_nodes(&mut self, key: u64, value: (Felt, StoredNode)) {
        self.nodes.insert(key, value);
    }

    fn get_next_index(&self) -> u64 {
        self.next_index
    }
}

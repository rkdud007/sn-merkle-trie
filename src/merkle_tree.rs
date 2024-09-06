use std::{cell::RefCell, collections::HashMap, error::Error, rc::Rc};

use starknet_types_core::{felt::Felt, hash::StarkHash};

use crate::merkle_node::InternalNode;

pub struct MerkleTree<H: StarkHash, const HEIGHT: usize> {
    pub root: Option<Rc<RefCell<InternalNode>>>,
    leaves: HashMap<Felt, Felt>,
    _hasher: std::marker::PhantomData<H>,
}

impl<H: StarkHash, const HEIGHT: usize> MerkleTree<H, HEIGHT> {
    pub fn new(root: u64) -> Self {
        let root = Some(Rc::new(RefCell::new(InternalNode::Unresolved(root))));
        Self {
            root,
            _hasher: std::marker::PhantomData,
            leaves: Default::default(),
        }
    }

    pub fn empty() -> Self {
        Self {
            root: None,
            _hasher: std::marker::PhantomData,
            leaves: Default::default(),
        }
    }

    pub fn set(key: Felt, value: Felt) -> Result<(), Box<dyn Error>> {
        // TODO
        Ok(())
    }
}

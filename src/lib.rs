pub mod conversion;
pub mod node;
pub mod transaction;

use bitvec::{order::Msb0, slice::BitSlice, vec::BitVec};
use conversion::from_bits_to_felt;
use node::{BinaryNode, Direction, EdgeNode, InternalNode};
use starknet_types_core::{felt::Felt, hash::StarkHash};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

#[derive(Default)]
pub struct InMememoryStorage {
    nodes: HashMap<u64, (Felt, StoredNode)>,
    leaves: HashMap<Felt, Felt>,
    next_index: u64,
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
}

#[derive(Clone, Debug, PartialEq)]
pub enum StoredNode {
    Binary { left: u64, right: u64 },
    Edge { child: u64, path: BitVec<u8, Msb0> },
    LeafBinary,
    LeafEdge { path: BitVec<u8, Msb0> },
}

/// Read-only storage used by the [Merkle tree](crate::tree::MerkleTree).
pub trait Storage {
    /// Returns the node stored at the given index.
    fn get(&self, index: u64) -> anyhow::Result<Option<StoredNode>>;
    /// Returns the hash of the node at the given index.
    fn hash(&self, index: u64) -> anyhow::Result<Option<Felt>>;
    /// Returns the value of the leaf at the given path.
    fn leaf(&self, path: &BitSlice<u8, Msb0>) -> anyhow::Result<Option<Felt>>;
}

pub struct MerkleTree<H: StarkHash, S: Storage, const HEIGHT: usize> {
    pub root: Option<Rc<RefCell<InternalNode>>>,
    pub leaves: HashMap<BitVec<u8, Msb0>, Felt>,
    _hasher: std::marker::PhantomData<H>,
    pub storage: S,
}

impl<H: StarkHash, S: Storage + Default, const HEIGHT: usize> Default for MerkleTree<H, S, HEIGHT> {
    fn default() -> Self {
        Self {
            root: None,
            leaves: Default::default(),
            _hasher: std::marker::PhantomData,
            storage: Default::default(),
        }
    }
}

impl<H: StarkHash, S: Storage, const HEIGHT: usize> MerkleTree<H, S, HEIGHT> {
    pub fn set(&mut self, key: BitVec<u8, Msb0>, value: Felt) -> anyhow::Result<()> {
        // if value == Felt::ZERO {
        //     return self.delete_leaf(storage, &key);
        // }

        // Changing or inserting a new leaf into the tree will change the hashes
        // of all nodes along the path to the leaf.
        let path = self.traverse(&self.storage, &key)?;

        // There are three possibilities.
        //
        // 1. The leaf exists, in which case we simply change its value.
        //
        // 2. The tree is empty, we insert the new leaf and the root becomes an edge
        //    node connecting to it.
        //
        // 3. The leaf does not exist, and the tree is not empty. The final node in the
        //    traversal will be an edge node who's path diverges from our new leaf
        //    node's.
        //
        //    This edge must be split into a new subtree containing both the existing
        // edge's child and the    new leaf. This requires an edge followed by a
        // binary node and then further edges to both the    current child and
        // the new leaf. Any of these new edges may also end with an empty path in
        //    which case they should be elided. It depends on the common path length of
        // the current edge    and the new leaf i.e. the split may be at the
        // first bit (in which case there is no leading    edge), or the split
        // may be in the middle (requires both leading and post edges), or the
        //    split may be the final bit (no post edge).
        use InternalNode::*;
        match path.last() {
            Some(node) => {
                let updated = match &*node.borrow() {
                    Edge(edge) => {
                        let common = edge.common_path(&key);

                        // Height of the binary node
                        let branch_height = edge.height + common.len();
                        // Height of the binary node's children
                        let child_height = branch_height + 1;

                        // Path from binary node to new leaf
                        let new_path = key[child_height..].to_bitvec();
                        // Path from binary node to existing child
                        let old_path = edge.path[common.len() + 1..].to_bitvec();

                        // The new leaf branch of the binary node.
                        // (this may be edge -> leaf, or just leaf depending).
                        let new = match new_path.is_empty() {
                            true => Rc::new(RefCell::new(InternalNode::Leaf)),
                            false => {
                                let new_edge = InternalNode::Edge(EdgeNode {
                                    storage_index: None,
                                    height: child_height,
                                    path: new_path,
                                    child: Rc::new(RefCell::new(InternalNode::Leaf)),
                                });
                                Rc::new(RefCell::new(new_edge))
                            }
                        };

                        // The existing child branch of the binary node.
                        let old = match old_path.is_empty() {
                            true => edge.child.clone(),
                            false => {
                                let old_edge = InternalNode::Edge(EdgeNode {
                                    storage_index: None,
                                    height: child_height,
                                    path: old_path,
                                    child: edge.child.clone(),
                                });
                                Rc::new(RefCell::new(old_edge))
                            }
                        };

                        let new_direction = Direction::from(key[branch_height]);
                        let (left, right) = match new_direction {
                            Direction::Left => (new, old),
                            Direction::Right => (old, new),
                        };

                        let branch = InternalNode::Binary(BinaryNode {
                            storage_index: None,
                            height: branch_height,
                            left,
                            right,
                        });

                        // We may require an edge leading to the binary node.
                        match common.is_empty() {
                            true => branch,
                            false => InternalNode::Edge(EdgeNode {
                                storage_index: None,
                                height: edge.height,
                                path: common.to_bitvec(),
                                child: Rc::new(RefCell::new(branch)),
                            }),
                        }
                    }
                    // Leaf exists already.
                    Leaf => InternalNode::Leaf,
                    Unresolved(_) | Binary(_) => {
                        unreachable!("The end of a traversion cannot be unresolved or binary")
                    }
                };

                let old_node = node.replace(updated);
                // if let Some(index) = old_node.storage_index() {
                //     self.nodes_removed.push(index);
                // };
            }
            None => {
                // Getting no travel nodes implies that the tree is empty.
                //
                // Create a new leaf node with the value, and the root becomes
                // an edge node connecting to the leaf.
                let edge = InternalNode::Edge(EdgeNode {
                    storage_index: None,
                    height: 0,
                    path: key.to_bitvec(),
                    child: Rc::new(RefCell::new(InternalNode::Leaf)),
                });

                self.root = Some(Rc::new(RefCell::new(edge)));
            }
        }

        self.leaves.insert(key, value);

        Ok(())
    }

    /// Traverses from the current root towards destination node.
    /// Returns the list of nodes along the path.
    ///
    /// If the destination node exists, it will be the final node in the list.
    ///
    /// This means that the final node will always be either a the destination
    /// [Leaf](InternalNode::Leaf) node, or an [Edge](InternalNode::Edge)
    /// node who's path suffix does not match the leaf's path.
    ///
    /// The final node can __not__ be a [Binary](InternalNode::Binary) node
    /// since it would always be possible to continue on towards the
    /// destination. Nor can it be an [Unresolved](InternalNode::Unresolved)
    /// node since this would be resolved to check if we can travel further.
    fn traverse(
        &self,
        storage: &impl Storage,
        dst: &BitSlice<u8, Msb0>,
    ) -> anyhow::Result<Vec<Rc<RefCell<InternalNode>>>> {
        let Some(mut current) = self.root.clone() else {
            return Ok(Vec::new());
        };

        let mut height = 0;
        let mut nodes = Vec::new();
        loop {
            use InternalNode::*;

            let current_tmp = current.borrow().clone();

            let next = match current_tmp {
                Unresolved(idx) => {
                    // let node = self.resolve(storage, idx, height)?;
                    // current.replace(node);
                    // current
                    current
                }
                Binary(binary) => {
                    nodes.push(current.clone());
                    let next = binary.direction(dst);
                    let next = binary.get_child(next);
                    height += 1;
                    next
                }
                Edge(edge) if edge.path_matches(dst) => {
                    nodes.push(current.clone());
                    height += edge.path.len();
                    edge.child.clone()
                }
                Leaf | Edge(_) => {
                    nodes.push(current);
                    return Ok(nodes);
                }
            };

            current = next;
        }
    }
}

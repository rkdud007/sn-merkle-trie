pub mod conversion;
pub mod node;
pub mod storage;
pub mod transaction;

use anyhow::Context;
use bitvec::{order::Msb0, slice::BitSlice, vec::BitVec};
use conversion::from_bits_to_felt;
use node::{BinaryNode, Direction, EdgeNode, InternalNode, TrieNode};
use starknet_types_core::{
    felt::Felt,
    hash::{Pedersen, StarkHash},
};
use std::{cell::RefCell, collections::HashMap, rc::Rc};
use storage::Storage;

/// The result of committing a Merkle tree.
#[derive(Default, Debug)]
pub struct TrieUpdate {
    /// New nodes added. Note that these may contain false positives if the
    /// mutations resulted in removing and then re-adding the same nodes within
    /// the tree.
    ///
    /// The last node is the root of the trie.
    pub nodes_added: Vec<(Felt, Node)>,
    /// Nodes committed to storage that have been removed.
    pub nodes_removed: Vec<u64>,
    /// New root commitment of the trie.
    pub root_commitment: Felt,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StoredNode {
    Binary { left: u64, right: u64 },
    Edge { child: u64, path: BitVec<u8, Msb0> },
    LeafBinary,
    LeafEdge { path: BitVec<u8, Msb0> },
}

#[derive(Debug, PartialEq)]
pub enum Membership {
    Member,
    NonMember,
}

#[derive(Clone, Debug)]
pub enum Node {
    Binary {
        left: NodeRef,
        right: NodeRef,
    },
    Edge {
        child: NodeRef,
        path: BitVec<u8, Msb0>,
    },
    LeafBinary,
    LeafEdge {
        path: BitVec<u8, Msb0>,
    },
}

#[derive(Copy, Clone, Debug)]
pub enum NodeRef {
    // A reference to a node that has already been committed to storage.
    StorageIndex(u64),
    // A reference to a node that has not yet been committed to storage.
    // The index within the `nodes_added` vector is used as a reference.
    Index(usize),
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
    pub fn get_proof(
        &self,
        root_idx: u64,
        key: BitVec<u8, Msb0>,
    ) -> anyhow::Result<Option<Vec<TrieNode>>> {
        // Manually traverse towards the key.
        let mut nodes = Vec::new();

        let mut next = Some(root_idx);
        let mut height = 0;
        while let Some(index) = next.take() {
            let Some(node) = self.storage.get(index).context("Resolving node")? else {
                println!("Node not found ");

                return Ok(None);
            };

            let node = match node {
                StoredNode::Binary { left, right } => {
                    // Choose the direction to go in.
                    next = match key.get(height).map(|b| Direction::from(*b)) {
                        Some(Direction::Left) => Some(left),
                        Some(Direction::Right) => Some(right),
                        None => anyhow::bail!("Key path too short for binary node"),
                    };
                    height += 1;

                    let left = self
                        .storage
                        .hash(left)
                        .context("Querying left child's hash")?
                        .context("Left child's hash is missing")?;

                    let right = self
                        .storage
                        .hash(right)
                        .context("Querying right child's hash")?
                        .context("Right child's hash is missing")?;

                    TrieNode::Binary { left, right }
                }
                StoredNode::Edge { child, path } => {
                    let key = key
                        .get(height..height + path.len())
                        .context("Key path is too short for edge node")?;
                    height += path.len();

                    // If the path matches then we continue otherwise the proof is complete.
                    if key == path {
                        next = Some(child);
                    }

                    let child = self
                        .storage
                        .hash(child)
                        .context("Querying child child's hash")?
                        .context("Child's hash is missing")?;

                    TrieNode::Edge { child, path }
                }
                StoredNode::LeafBinary => {
                    // End of the line, get child hashes.
                    let mut path = key[..height].to_bitvec();
                    path.push(Direction::Left.into());
                    let left = self
                        .storage
                        .leaf(&path)
                        .context("Querying left leaf hash")?
                        .context("Left leaf is missing")?;
                    path.pop();
                    path.push(Direction::Right.into());
                    let right = self
                        .storage
                        .leaf(&path)
                        .context("Querying right leaf hash")?
                        .context("Right leaf is missing")?;

                    TrieNode::Binary { left, right }
                }
                StoredNode::LeafEdge { path } => {
                    let mut current_path = key[..height].to_bitvec();
                    // End of the line, get hash of the child.
                    current_path.extend_from_bitslice(&path);
                    let child = self
                        .storage
                        .leaf(&current_path)
                        .context("Querying leaf hash")?
                        .context("Child leaf is missing")?;

                    TrieNode::Edge { child, path }
                }
            };

            nodes.push(node);
        }

        Ok(Some(nodes))
    }

    pub fn verify_proof(
        &self,
        root: Felt,
        key: &BitSlice<u8, Msb0>,
        value: Felt,
        proofs: &[TrieNode],
    ) -> Option<Membership> {
        // Protect from ill-formed keys
        if key.len() != 251 {
            return None;
        }

        let mut expected_hash = root;
        let mut remaining_path: &BitSlice<u8, Msb0> = key;

        for proof_node in proofs.iter() {
            // Hash mismatch? Return None.
            if proof_node.hash::<Pedersen>() != expected_hash {
                return None;
            }
            match proof_node {
                TrieNode::Binary { left, right } => {
                    // Direction will always correspond to the 0th index
                    // because we're removing bits on every iteration.
                    let direction = Direction::from(remaining_path[0]);

                    // Set the next hash to be the left or right hash,
                    // depending on the direction
                    expected_hash = match direction {
                        Direction::Left => *left,
                        Direction::Right => *right,
                    };

                    // Advance by a single bit
                    remaining_path = &remaining_path[1..];
                }
                TrieNode::Edge { child, path } => {
                    if path != &remaining_path[..path.len()] {
                        // If paths don't match, we've found a proof of non membership because
                        // we:
                        // 1. Correctly moved towards the target insofar as is possible, and
                        // 2. hashing all the nodes along the path does result in the root hash,
                        //    which means
                        // 3. the target definitely does not exist in this tree
                        return Some(Membership::NonMember);
                    }

                    // Set the next hash to the child's hash
                    expected_hash = *child;

                    // Advance by the whole edge path
                    remaining_path = &remaining_path[path.len()..];
                }
            }
        }

        // At this point, we should reach `value` !
        if expected_hash == value {
            Some(Membership::Member)
        } else {
            // Hash mismatch. Return `None`.
            None
        }
    }

    pub fn commit(&mut self) -> anyhow::Result<(Felt, u64)> {
        for (key, value) in &self.leaves {
            let key = from_bits_to_felt(key).unwrap();
            self.storage.insert_leaves(key, *value);
        }

        // Go through tree, collect mutated nodes and calculate their hashes.
        let mut added = Vec::new();
        let mut removed = Vec::new();

        let root_hash = if let Some(root) = self.root.as_ref() {
            match &mut *root.borrow_mut() {
                // If the root node is unresolved that means that there have been no changes made
                // to the tree.
                InternalNode::Unresolved(idx) => self
                    .storage
                    .hash(*idx)
                    .context("Fetching root node's hash")?
                    .context("Root node's hash is missing")?,
                other => {
                    let (root_hash, _) = self.commit_subtree(
                        other,
                        &mut added,
                        &mut removed,
                        &self.storage,
                        BitVec::new(),
                    )?;
                    root_hash
                }
            }
        } else {
            // An empty trie has a root of zero
            Felt::ZERO
        };

        //  removed.extend(self.nodes_removed.clone());

        let update = TrieUpdate {
            nodes_added: added,
            nodes_removed: removed,
            root_commitment: root_hash,
        };

        let number_of_nodes_added = update.nodes_added.len() as u64;

        for (rel_index, (hash, node)) in update.nodes_added.into_iter().enumerate() {
            let node = match node {
                Node::Binary { left, right } => {
                    let left = match left {
                        NodeRef::StorageIndex(idx) => idx,
                        NodeRef::Index(idx) => self.storage.get_next_index() + (idx as u64),
                    };

                    let right = match right {
                        NodeRef::StorageIndex(idx) => idx,
                        NodeRef::Index(idx) => self.storage.get_next_index() + (idx as u64),
                    };

                    StoredNode::Binary { left, right }
                }
                Node::Edge { child, path } => {
                    let child = match child {
                        NodeRef::StorageIndex(idx) => idx,
                        NodeRef::Index(idx) => self.storage.get_next_index() + (idx as u64),
                    };

                    StoredNode::Edge { child, path }
                }
                Node::LeafBinary => StoredNode::LeafBinary,
                Node::LeafEdge { path } => StoredNode::LeafEdge { path },
            };

            let index = self.storage.get_next_index() + (rel_index as u64);

            self.storage.insert_nodes(index, (hash, node));
        }

        let storage_root_index = self.storage.get_next_index() + number_of_nodes_added - 1;
        let _ = self.storage.add_next_index(number_of_nodes_added);

        Ok((update.root_commitment, storage_root_index))
    }

    fn commit_subtree(
        &self,
        node: &mut InternalNode,
        added: &mut Vec<(Felt, Node)>,
        removed: &mut Vec<u64>,
        storage: &impl Storage,
        mut path: BitVec<u8, Msb0>,
    ) -> anyhow::Result<(Felt, Option<NodeRef>)> {
        let result = match node {
            InternalNode::Unresolved(idx) => {
                // Unresolved nodes are already committed, but we need their hash for subsequent
                // iterations.
                let hash = storage
                    .hash(*idx)
                    .context("Fetching stored node's hash")?
                    .context("Stored node's hash is missing")?;
                (hash, Some(NodeRef::StorageIndex(*idx)))
            }
            InternalNode::Leaf => {
                let hash = if let Some(value) = self.leaves.get(&path) {
                    *value
                } else {
                    storage
                        .leaf(&path)
                        .context("Fetching leaf value from storage")?
                        .context("Leaf value missing from storage")?
                };
                (hash, None)
            }
            InternalNode::Binary(binary) => {
                let mut left_path = path.clone();
                left_path.push(Direction::Left.into());
                let (left_hash, left_child) = self.commit_subtree(
                    &mut binary.left.borrow_mut(),
                    added,
                    removed,
                    storage,
                    left_path,
                )?;
                let mut right_path = path.clone();
                right_path.push(Direction::Right.into());
                let (right_hash, right_child) = self.commit_subtree(
                    &mut binary.right.borrow_mut(),
                    added,
                    removed,
                    storage,
                    right_path,
                )?;
                let hash = BinaryNode::calculate_hash::<H>(left_hash, right_hash);

                let persisted_node = match (left_child, right_child) {
                    (None, None) => Node::LeafBinary,
                    (Some(_), None) | (None, Some(_)) => {
                        anyhow::bail!(
                            "Inconsistent binary children. Both children must be leaves or not \
                             leaves."
                        )
                    }
                    (Some(left), Some(right)) => Node::Binary { left, right },
                };

                if let Some(storage_index) = binary.storage_index {
                    removed.push(storage_index);
                };

                let node_index = added.len();
                added.push((hash, persisted_node));

                (hash, Some(NodeRef::Index(node_index)))
            }
            InternalNode::Edge(edge) => {
                path.extend_from_bitslice(&edge.path);
                let (child_hash, child) = self.commit_subtree(
                    &mut edge.child.borrow_mut(),
                    added,
                    removed,
                    storage,
                    path,
                )?;

                let hash = EdgeNode::calculate_hash::<H>(child_hash, &edge.path);

                let persisted_node = match child {
                    None => Node::LeafEdge {
                        path: edge.path.clone(),
                    },
                    Some(child) => Node::Edge {
                        child,
                        path: edge.path.clone(),
                    },
                };

                let node_index = added.len();
                added.push((hash, persisted_node));
                if let Some(storage_index) = edge.storage_index {
                    removed.push(storage_index);
                };

                (hash, Some(NodeRef::Index(node_index)))
            }
        };

        Ok(result)
    }

    pub fn set(&mut self, key: BitVec<u8, Msb0>, value: Felt) -> anyhow::Result<()> {
        // if value == Felt::ZERO {
        //     return self.delete_leaf(storage, &key);
        // }

        // Changing or inserting a new leaf into the tree will change the hashes
        // of all nodes along the path to the leaf.
        let path = self.traverse(&key)?;

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

                let _ = node.replace(updated);
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
    fn traverse(&self, dst: &BitSlice<u8, Msb0>) -> anyhow::Result<Vec<Rc<RefCell<InternalNode>>>> {
        let Some(mut current) = self.root.clone() else {
            return Ok(Vec::new());
        };

        let mut nodes = Vec::new();
        loop {
            use InternalNode::*;

            let current_tmp = current.borrow().clone();

            let next = match current_tmp {
                Unresolved(_) => {
                    // let node = self.resolve(storage, idx, height)?;
                    // current.replace(node);
                    // current
                    current
                }
                Binary(binary) => {
                    nodes.push(current.clone());
                    let next = binary.direction(dst);
                    binary.get_child(next)
                }
                Edge(edge) if edge.path_matches(dst) => {
                    nodes.push(current.clone());
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

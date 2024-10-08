use std::{cell::RefCell, rc::Rc};

use bitvec::{order::Msb0, slice::BitSlice, vec::BitVec};
use starknet_types_core::{felt::Felt, hash::StarkHash};

use crate::conversion::from_bits_to_felt;

/// A node in a Starknet patricia-merkle trie.
///
/// See pathfinders merkle-tree crate for more information.
#[derive(Debug, Clone, PartialEq)]
pub enum TrieNode {
    Binary { left: Felt, right: Felt },
    Edge { child: Felt, path: BitVec<u8, Msb0> },
}

impl TrieNode {
    pub fn hash<H: StarkHash>(&self) -> Felt {
        match self {
            TrieNode::Binary { left, right } => H::hash(left, right),
            TrieNode::Edge { child, path } => {
                let mut length = [0; 32];
                // Safe as len() is guaranteed to be <= 251
                length[31] = path.len() as u8;
                let path = from_bits_to_felt(path).unwrap();

                let length = Felt::from_bytes_be(&length);
                H::hash(child, &path) + length
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum InternalNode {
    /// A node that has not been fetched from storage yet.
    ///
    /// As such, all we know is its index.
    Unresolved(u64),
    /// A branch node with exactly two children.
    Binary(BinaryNode),
    /// Describes a path connecting two other nodes.
    Edge(EdgeNode),
    /// A leaf node.
    Leaf,
}

impl InternalNode {
    pub fn as_edge(&self) -> Option<&EdgeNode> {
        match self {
            InternalNode::Edge(edge) => Some(edge),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EdgeNode {
    /// The storage index of this node (if it was loaded from storage).
    pub storage_index: Option<u64>,
    /// The starting height of this node in the tree.
    pub height: usize,
    /// The path this edge takes.
    pub path: BitVec<u8, Msb0>,
    /// The child of this node.
    pub child: Rc<RefCell<InternalNode>>,
}

impl EdgeNode {
    /// Returns true if the edge node's path matches the same path given by the
    /// key.
    pub fn path_matches(&self, key: &BitSlice<u8, Msb0>) -> bool {
        self.path == key[self.height..self.height + self.path.len()]
    }

    /// Returns the common bit prefix between the edge node's path and the given
    /// key.
    ///
    /// This is calculated with the edge's height taken into account.
    pub fn common_path(&self, key: &BitSlice<u8, Msb0>) -> &BitSlice<u8, Msb0> {
        let key_path = key.iter().skip(self.height);
        let common_length = key_path
            .zip(self.path.iter())
            .take_while(|(a, b)| a == b)
            .count();

        &self.path[..common_length]
    }

    pub(crate) fn calculate_hash<H: StarkHash>(child: Felt, path: &BitSlice<u8, Msb0>) -> Felt {
        let mut length = [0; 32];
        // Safe as len() is guaranteed to be <= 251
        length[31] = path.len() as u8;
        let length = Felt::from_bytes_be(&length);
        let path = from_bits_to_felt(path).unwrap();

        H::hash(&child, &path) + length
    }
}

/// Describes the [InternalNode::Binary] variant.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryNode {
    /// The storage index of this node (if it was loaded from storage).
    pub storage_index: Option<u64>,
    /// The height of this node in the tree.
    pub height: usize,
    /// [Left](Direction::Left) child.
    pub left: Rc<RefCell<InternalNode>>,
    /// [Right](Direction::Right) child.
    pub right: Rc<RefCell<InternalNode>>,
}

impl BinaryNode {
    /// Maps the key's bit at the binary node's height to a [Direction].
    ///
    /// This can be used to check which direction the key describes in the
    /// context of this binary node i.e. which direction the child along the
    /// key's path would take.
    pub fn direction(&self, key: &BitSlice<u8, Msb0>) -> Direction {
        key[self.height].into()
    }

    /// Returns the [Left] or [Right] child.
    ///
    /// [Left]: Direction::Left
    /// [Right]: Direction::Right
    pub fn get_child(&self, direction: Direction) -> Rc<RefCell<InternalNode>> {
        match direction {
            Direction::Left => self.left.clone(),
            Direction::Right => self.right.clone(),
        }
    }

    pub(crate) fn calculate_hash<H: StarkHash>(left: Felt, right: Felt) -> Felt {
        H::hash(&left, &right)
    }
}

/// Describes the direction a child of a [BinaryNode] may have.
///
/// Binary nodes have two children, one left and one right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

impl From<bool> for Direction {
    fn from(tf: bool) -> Self {
        match tf {
            true => Direction::Right,
            false => Direction::Left,
        }
    }
}

impl From<Direction> for bool {
    fn from(direction: Direction) -> Self {
        match direction {
            Direction::Left => false,
            Direction::Right => true,
        }
    }
}

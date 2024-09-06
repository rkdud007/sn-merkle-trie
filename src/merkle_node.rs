//! Contains constructs for describing the nodes in a Binary Merkle Patricia
//! Tree used by Starknet.
//!
//! For more information about how these Starknet trees are structured, see
//! [`MerkleTree`](crate::tree::MerkleTree).

use std::cell::RefCell;
use std::rc::Rc;

use starknet_types_core::felt::Felt;
use starknet_types_core::hash::StarkHash;

/// A node in a Binary Merkle-Patricia Tree graph.
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

/// Describes the [InternalNode::Binary] variant.
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryNode {
    /// The height of this node in the tree.
    pub height: usize,
    /// [Left](Direction::Left) child.
    pub left: Rc<RefCell<InternalNode>>,
    /// [Right](Direction::Right) child.
    pub right: Rc<RefCell<InternalNode>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EdgeNode {
    /// The starting height of this node in the tree.
    pub height: usize,
    /// The path this edge takes.
    pub path: [u8; 32],
    /// The child of this node.
    pub child: Rc<RefCell<InternalNode>>,
}

/// Describes the direction a child of a [BinaryNode] may have.
///
/// Binary nodes have two children, one left and one right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

impl Direction {
    /// Inverts the [Direction].
    ///
    /// [Left] becomes [Right], and [Right] becomes [Left].
    ///
    /// [Left]: Direction::Left
    /// [Right]: Direction::Right
    pub fn invert(self) -> Direction {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

impl From<u8> for Direction {
    fn from(tf: u8) -> Self {
        match tf {
            1 => Direction::Right,
            0 => Direction::Left,
            _ => panic!("Invalid direction"),
        }
    }
}

impl BinaryNode {
    /// Maps the key's bit at the binary node's height to a [Direction].
    ///
    /// This can be used to check which direction the key describes in the
    /// context of this binary node i.e. which direction the child along the
    /// key's path would take.
    pub fn direction(&self, key: &[u8]) -> Direction {
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

impl InternalNode {
    pub fn is_binary(&self) -> bool {
        matches!(self, InternalNode::Binary(..))
    }

    pub fn as_binary(&self) -> Option<&BinaryNode> {
        match self {
            InternalNode::Binary(binary) => Some(binary),
            _ => None,
        }
    }

    pub fn as_edge(&self) -> Option<&EdgeNode> {
        match self {
            InternalNode::Edge(edge) => Some(edge),
            _ => None,
        }
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self, InternalNode::Leaf)
    }
}

impl EdgeNode {
    /// Returns true if the edge node's path matches the same path given by the
    /// key.
    pub fn path_matches(&self, key: &[u8]) -> bool {
        self.path == key[self.height..self.height + self.path.len()]
    }

    /// Returns the common bit prefix between the edge node's path and the given
    /// key.
    ///
    /// This is calculated with the edge's height taken into account.
    pub fn common_path(&self, key: &[u8]) -> &[u8] {
        let key_path = key.iter().skip(self.height);
        let common_length = key_path
            .zip(self.path.iter())
            .take_while(|(a, b)| a == b)
            .count();

        &self.path[..common_length]
    }

    pub(crate) fn calculate_hash<H: StarkHash>(child: Felt, path: Felt) -> Felt {
        let mut length = [0; 32];
        // Safe as len() is guaranteed to be <= 251
        let bit_length = path.bits();
        length[31] = bit_length as u8;
        let length = Felt::from_bytes_be(&length);

        H::hash(&child, &path) + length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_types_core::hash::Pedersen;
    use std::str::FromStr;

    #[test]
    fn binary_hash() {
        // Test data taken from starkware cairo-lang repo:
        // https://github.com/starkware-libs/cairo-lang/blob/fc97bdd8322a7df043c87c371634b26c15ed6cee/src/starkware/starkware_utils/commitment_tree/patricia_tree/nodes_test.py#L14
        //
        // Note that the hash function must be exchanged for `async_stark_hash_func`,
        // otherwise it just uses some other test hash function.
        let expected =
            Felt::from_str("0x0615bb8d47888d2987ad0c63fc06e9e771930986a4dd8adc55617febfcf3639e")
                .unwrap();
        let left = Felt::from_str("0x1234").unwrap();
        let right = Felt::from_str("0xabcd").unwrap();

        let hash = BinaryNode::calculate_hash::<Pedersen>(left, right);

        assert_eq!(hash, expected);
    }

    #[test]
    fn edge_hash() {
        // Test data taken from starkware cairo-lang repo:
        // https://github.com/starkware-libs/cairo-lang/blob/fc97bdd8322a7df043c87c371634b26c15ed6cee/src/starkware/starkware_utils/commitment_tree/patricia_tree/nodes_test.py#L38
        //
        // Note that the hash function must be exchanged for `async_stark_hash_func`,
        // otherwise it just uses some other test hash function.
        let expected =
            Felt::from_str("0x1d937094c09b5f8e26a662d21911871e3cbc6858d55cc49af9848ea6fed4e9")
                .unwrap();
        let child = Felt::from_str("0x1234ABCD").unwrap();
        // Path = 42 in binary.
        let path = Felt::from(42);

        let hash = EdgeNode::calculate_hash::<Pedersen>(child, path);

        assert_eq!(hash, expected);
    }
}

use std::collections::HashMap;

use bitvec::{order::Msb0, slice::BitSlice};
use starknet_types_core::felt::Felt;

use crate::{conversion::from_bits_to_felt, Storage, StoredNode};

#[cfg(test)]
mod tests {

    use starknet_types_core::hash::Pedersen;

    use crate::{conversion::from_felt_to_bits, InMememoryStorage, MerkleTree};

    use super::*;

    #[test]
    fn test_commitment_merkle_tree() {
        let mut tree: MerkleTree<Pedersen, InMememoryStorage, 64> = Default::default();

        let key1 = from_felt_to_bits(&Felt::from_hex_unchecked("0x0")); // 0b01
        let key2 = from_felt_to_bits(&Felt::from_hex_unchecked("0x1")); // 0b01
        let key3 = from_felt_to_bits(&Felt::from_hex_unchecked("0x2")); // 0b01
        let key4 = from_felt_to_bits(&Felt::from_hex_unchecked("0x3")); // 0b01
        let key5 = from_felt_to_bits(&Felt::from_hex_unchecked("0x4")); // 0b01
        let key6 = from_felt_to_bits(&Felt::from_hex_unchecked("0x5")); // 0b01

        println!("{:?}", key1);

        let value_1 = Felt::from_hex_unchecked("0x2");
        let value_2 = Felt::from_hex_unchecked("0x3");
        let value_3 = Felt::from_hex_unchecked("0x4");
        let value_4 = Felt::from_hex_unchecked("0x5");
        let value_5 = Felt::from_hex_unchecked("0x6");
        let value_6 = Felt::from_hex_unchecked("0x7");

        tree.set(key1.clone(), value_1).unwrap();
        // println!("{:?}", tree.root);
        tree.set(key2.clone(), value_2).unwrap();
        // println!("{:?}", tree.root);
        tree.set(key3.clone(), value_3).unwrap();
        // println!("{:?}", tree.root);
        tree.set(key4.clone(), value_4).unwrap();
        // println!("{:?}", tree.root);
        tree.set(key5.clone(), value_5).unwrap();
        // println!("{:?}", tree.root);
        tree.set(key6.clone(), value_6).unwrap();
        println!("{:?}", tree.leaves);

        // produced by the cairo-lang Python implementation:
        // `hex(asyncio.run(calculate_patricia_root([1, 2, 3, 4], height=64,
        // ffc=ffc))))`
        // let expected_root_hash =
        //     felt!("0x1a0e579b6b444769e4626331230b5ae39bd880f47e703b73fa56bf77e52e461");
        let (root, root_idx) = tree.commit().unwrap();
        println!("{:?}", root);
        println!("{:?}", root_idx);

        // assert_eq!(expected_root_hash, root);
        // // let key = Felt::from_u64(1);
        // // let value = Felt::from_u64(2);
        // let proof = tree.get_proof(root_idx, key1.clone()).unwrap().unwrap();
        // println!("{:?}", proof);
        // let mem =
        //     TransactionOrEventTree::<PedersenHash>::verify_proof(root, &key1, value_1, &proof);
        // println!("{:?}", mem);

        // let mem =
        //     TransactionOrEventTree::<PedersenHash>::verify_proof(root, &key1, value_2, &proof);
        // println!("{:?}", mem);

        // let key7 = felt!("0xabc").view_bits().to_owned(); // 0b01

        // let mem =
        //     TransactionOrEventTree::<PedersenHash>::verify_proof(root, &key7, value_2, &proof);
        // println!("{:?}", mem);
    }
}

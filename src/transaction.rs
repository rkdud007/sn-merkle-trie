#[cfg(test)]
mod tests {
    use crate::storage::memory::InMememoryStorage;
    use crate::Membership;
    use crate::{conversion::from_felt_to_bits, MerkleTree};
    use starknet_types_core::felt::Felt;
    use starknet_types_core::hash::Pedersen;

    #[test]
    fn test_commitment_merkle_tree() {
        let mut tree: MerkleTree<Pedersen, InMememoryStorage, 64> = Default::default();

        let key1 = from_felt_to_bits(&Felt::from_hex_unchecked("0x0")); // 0b01
        let key2 = from_felt_to_bits(&Felt::from_hex_unchecked("0x1")); // 0b01
        let key3 = from_felt_to_bits(&Felt::from_hex_unchecked("0x2")); // 0b01
        let key4 = from_felt_to_bits(&Felt::from_hex_unchecked("0x3")); // 0b01
        let key5 = from_felt_to_bits(&Felt::from_hex_unchecked("0x4")); // 0b01
        let key6 = from_felt_to_bits(&Felt::from_hex_unchecked("0x5")); // 0b01

        let value_1 = Felt::from_hex_unchecked("0x2");
        let value_2 = Felt::from_hex_unchecked("0x3");
        let value_3 = Felt::from_hex_unchecked("0x4");
        let value_4 = Felt::from_hex_unchecked("0x5");
        let value_5 = Felt::from_hex_unchecked("0x6");
        let value_6 = Felt::from_hex_unchecked("0x7");

        tree.set(key1.clone(), value_1).unwrap();
        tree.set(key2.clone(), value_2).unwrap();
        tree.set(key3.clone(), value_3).unwrap();
        tree.set(key4.clone(), value_4).unwrap();
        tree.set(key5.clone(), value_5).unwrap();
        tree.set(key6.clone(), value_6).unwrap();

        let (root, root_idx) = tree.commit().unwrap();

        let proof = tree.get_proof(root_idx, key1.clone()).unwrap().unwrap();

        let mem = tree.verify_proof(root, &key1, value_1, &proof);
        assert_eq!(mem, Some(Membership::Member));

        let mem = tree.verify_proof(root, &key1, value_2, &proof);
        assert_eq!(mem, None);

        let key7 = from_felt_to_bits(&Felt::from_hex_unchecked("0xabc"));
        let mem = tree.verify_proof(root, &key7, value_2, &proof);
        assert_eq!(mem, Some(Membership::NonMember));
    }
}

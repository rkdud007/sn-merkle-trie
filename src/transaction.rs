#[cfg(test)]
mod tests {
    use crate::storage::memory::InMememoryStorage;
    use crate::Membership;
    use crate::{conversion::from_felt_to_bits, MerkleTree};
    use bitvec::view::BitView;
    use starknet_types_core::felt::Felt;
    use starknet_types_core::hash::Pedersen;

    #[test]
    fn test_tx_commitment_merkle_tree() {
        let mut tree: MerkleTree<Pedersen, InMememoryStorage, 64> = Default::default();

        // Note: depends on bits length commit will be differ
        let key1 = 0_u64.to_be_bytes().view_bits().to_owned();
        let key2 = 1_u64.to_be_bytes().view_bits().to_owned();
        let key3 = 2_u64.to_be_bytes().view_bits().to_owned();
        let key4 = 3_u64.to_be_bytes().view_bits().to_owned();

        let value_1 = Felt::from_hex_unchecked("0x1");
        let value_2 = Felt::from_hex_unchecked("0x2");
        let value_3 = Felt::from_hex_unchecked("0x3");
        let value_4 = Felt::from_hex_unchecked("0x4");

        tree.set(key1.clone(), value_1).unwrap();
        tree.set(key2.clone(), value_2).unwrap();
        tree.set(key3.clone(), value_3).unwrap();
        tree.set(key4.clone(), value_4).unwrap();

        let (root, root_idx) = tree.commit().unwrap();

        assert_eq!(
            root,
            Felt::from_hex_unchecked(
                "0x1a0e579b6b444769e4626331230b5ae39bd880f47e703b73fa56bf77e52e461"
            )
        );

        // seems proof is share able with key 1 and key 2 huh
        let proof = tree.get_proof(root_idx, key1.clone()).unwrap().unwrap();

        let mem = tree.verify_proof(root, &key1, value_1, &proof);
        assert_eq!(mem, Some(Membership::Member));

        let mem = tree.verify_proof(root, &key2, value_2, &proof);
        assert_eq!(mem, Some(Membership::Member));

        // seems proof is share able with key 3 and key 4 huh
        let proof = tree.get_proof(root_idx, key3.clone()).unwrap().unwrap();

        let mem = tree.verify_proof(root, &key3, value_3, &proof);
        assert_eq!(mem, Some(Membership::Member));

        let mem = tree.verify_proof(root, &key4, value_4, &proof);
        assert_eq!(mem, Some(Membership::Member));

        // invalid cases:
        let mem = tree.verify_proof(root, &key1, value_2, &proof);
        assert_eq!(mem, None);

        let key7 = from_felt_to_bits(&Felt::from_hex_unchecked("0xabc"));
        let mem = tree.verify_proof(root, &key7, value_2, &proof);
        assert_eq!(mem, None);
    }
}

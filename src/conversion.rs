use anyhow::bail;
use bitvec::{order::Msb0, slice::BitSlice, vec::BitVec, view::BitView};
use starknet_types_core::felt::Felt;

/// From [`BitSlice`] to [`Felt`] conversion
pub fn from_bits_to_felt(bits: &BitSlice<u8, Msb0>) -> anyhow::Result<Felt> {
    if bits.len() > 251 {
        bail!("overflow");
    }

    let mut bytes = [0u8; 32];
    bytes.view_bits_mut::<Msb0>()[256 - bits.len()..].copy_from_bitslice(bits);
    Ok(Felt::from_bytes_be(&bytes))
}

pub fn from_felt_to_bits(felt: &Felt) -> BitVec<u8, Msb0> {
    let bytes = felt.to_bytes_be();
    let mut bv = BitVec::<u8, Msb0>::from_slice(&bytes);

    // Remove leading zeros.
    // Felt is 252 bits, so we remove the first 4 bits (32 * 8 - 252 = 4)
    bv.drain(..4);

    bv
}

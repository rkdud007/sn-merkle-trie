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

/// Returns a bit view of the 251 least significant bits in MSB order.
pub fn from_felt_to_bits(felt: &Felt) -> BitVec<u8, Msb0> {
    let bytes = felt.to_bytes_be();
    let mut bv = BitVec::<u8, Msb0>::from_slice(&bytes);

    // Remove leading zeros.
    // 32 * 8 - 251 = 4
    bv.drain(..5);

    bv
}

/// From [`u64`] to [`BitVec`] conversion
pub fn from_u64_to_bits(value: u64) -> BitVec<u8, Msb0> {
    value.to_be_bytes().view_bits().to_owned()
}

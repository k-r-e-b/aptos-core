// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::natives::util::make_native_from_func;
use move_deps::{
    move_binary_format::errors::PartialVMResult,
    move_vm_runtime::native_functions::{NativeContext, NativeFunction},
    move_vm_types::{
        loaded_data::runtime_types::Type, natives::function::NativeResult, pop_arg, values::Value,
    },
};
use smallvec::smallvec;
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct LittleEndianBitVectorFromByteVectorGasParams {
    pub base_cost: u64,
    pub per_byte_cost: u64,
}

fn native_little_endian_bitvector_from_byte_vector(
    gas_params: &LittleEndianBitVectorFromByteVectorGasParams,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    cost += gas_params.per_byte_cost * bytes.len() as u64;

    let bits = bytes_to_little_endian_bits(&bytes);

    Ok(NativeResult::ok(cost, smallvec![Value::vector_bool(bits)]))
}

#[derive(Debug, Clone)]
pub struct BigEndianBitVectorFromByteVectorGasParams {
    pub base_cost: u64,
    pub per_byte_cost: u64,
}

fn native_big_endian_bitvector_from_byte_vector(
    gas_params: &BigEndianBitVectorFromByteVectorGasParams,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    cost += gas_params.per_byte_cost * bytes.len() as u64;

    let bits = bytes_to_big_endian_bits(&bytes);

    Ok(NativeResult::ok(cost, smallvec![Value::vector_bool(bits)]))
}

/// Converts a vector of bytes to a vector of bits in little-endian order.
///
/// e.g., 0x1C would typically be expressed in binary as:
///     bit: 0 0 0 1 1 1 0 0
///     idx: 0 1 2 3 4 5 6 7
///
/// However, this function will represent it by reversing the bits as:
///     bit: 0 0 1 1 1 0 0 0
///     idx: 0 1 2 3 4 5 6 7
fn bytes_to_little_endian_bits(bytes: &Vec<u8>) -> Vec<bool> {
    let mut bits = vec![];

    for byte in bytes {
        let mut byte = *byte;

        for _ in 0..8usize {
            let bit = (byte & 0x01) == 0x01; // get the least-significant bit (LSB)
            byte >>= 1; // right shift by 1
            bits.push(bit);
        }
    }
    bits
}

/// Converts a vector of bytes to a vector of bits in big-endian order.
///
/// e.g., for 0x1C this function would represent it as:
///     bit: 0 0 0 1 1 1 0 0
///     idx: 0 1 2 3 4 5 6 7
fn bytes_to_big_endian_bits(bytes: &Vec<u8>) -> Vec<bool> {
    let mut bits = vec![];

    for byte in bytes {
        let mut byte = *byte;

        for _ in 0..8usize {
            let bit = (byte & 0x80) == 0x80; // get the most-significant bit (MSB)
            byte <<= 1; // left shift by 1
            bits.push(bit);
        }
    }
    bits
}

#[derive(Debug, Clone)]
pub struct GasParameters {
    pub little_endian_bitvector_from_byte_vector: LittleEndianBitVectorFromByteVectorGasParams,
    pub big_endian_bitvector_from_byte_vector: BigEndianBitVectorFromByteVectorGasParams,
}

pub fn make_all(gas_params: GasParameters) -> impl Iterator<Item = (String, NativeFunction)> {
    let natives = [
        (
            "little_endian_bitvector_from_byte_vector_internal",
            make_native_from_func(
                gas_params.little_endian_bitvector_from_byte_vector,
                native_little_endian_bitvector_from_byte_vector,
            ),
        ),
        (
            "big_endian_bitvector_from_byte_vector_internal",
            make_native_from_func(
                gas_params.big_endian_bitvector_from_byte_vector,
                native_big_endian_bitvector_from_byte_vector,
            ),
        ),
    ];

    crate::natives::helpers::make_module_natives(natives)
}

#[cfg(test)]
mod test {
    use crate::natives::bit_vector::{bytes_to_big_endian_bits, bytes_to_little_endian_bits};

    const X_INV: [u8; 32] = [
        0x1c, 0xdc, 0x17, 0xfc, 0xe0, 0xe9, 0xa5, 0xbb, 0xd9, 0x24, 0x7e, 0x56, 0xbb, 0x01, 0x63,
        0x47, 0xbb, 0xba, 0x31, 0xed, 0xd5, 0xa9, 0xbb, 0x96, 0xd5, 0x0b, 0xcd, 0x7a, 0x3f, 0x96,
        0x2a, 0x0f,
    ];

    // X_INV from above, but in big-endian binary (most significant bit is at the smallest index)::
    // 0001110011011100000101111111110011100000111010011010010110111011110110010010010001111110010101101011101100000001011000110100011110111011101110100011000111101101110101011010100110111011100101101101010100001011110011010111101000111111100101100010101000001111
    const X_INV_BE_BITS: [bool; 256] = [
        false, false, false, true, true, true, false, false, true, true, false, true, true, true,
        false, false, false, false, false, true, false, true, true, true, true, true, true, true,
        true, true, false, false, true, true, true, false, false, false, false, false, true, true,
        true, false, true, false, false, true, true, false, true, false, false, true, false, true,
        true, false, true, true, true, false, true, true, true, true, false, true, true, false,
        false, true, false, false, true, false, false, true, false, false, false, true, true, true,
        true, true, true, false, false, true, false, true, false, true, true, false, true, false,
        true, true, true, false, true, true, false, false, false, false, false, false, false, true,
        false, true, true, false, false, false, true, true, false, true, false, false, false, true,
        true, true, true, false, true, true, true, false, true, true, true, false, true, true,
        true, false, true, false, false, false, true, true, false, false, false, true, true, true,
        true, false, true, true, false, true, true, true, false, true, false, true, false, true,
        true, false, true, false, true, false, false, true, true, false, true, true, true, false,
        true, true, true, false, false, true, false, true, true, false, true, true, false, true,
        false, true, false, true, false, false, false, false, true, false, true, true, true, true,
        false, false, true, true, false, true, false, true, true, true, true, false, true, false,
        false, false, true, true, true, true, true, true, true, false, false, true, false, true,
        true, false, false, false, true, false, true, false, true, false, false, false, false,
        false, true, true, true, true,
    ];

    // X_INV from above, but in little-endian binary (least significant bit is at the smallest index)
    // These bits were obtained by writing a custom test in curve25519-dalek's src/scalar.rs file.
    const X_INV_LE_BITS: [bool; 256] = [
        false, false, true, true, true, false, false, false, false, false, true, true, true, false,
        true, true, true, true, true, false, true, false, false, false, false, false, true, true,
        true, true, true, true, false, false, false, false, false, true, true, true, true, false,
        false, true, false, true, true, true, true, false, true, false, false, true, false, true,
        true, true, false, true, true, true, false, true, true, false, false, true, true, false,
        true, true, false, false, true, false, false, true, false, false, false, true, true, true,
        true, true, true, false, false, true, true, false, true, false, true, false, true, true,
        false, true, true, true, false, true, true, false, false, false, false, false, false,
        false, true, true, false, false, false, true, true, false, true, true, true, false, false,
        false, true, false, true, true, false, true, true, true, false, true, false, true, false,
        true, true, true, false, true, true, false, false, false, true, true, false, false, true,
        false, true, true, false, true, true, true, true, false, true, false, true, false, true,
        true, true, false, false, true, false, true, false, true, true, true, false, true, true,
        true, false, true, false, true, true, false, true, false, false, true, true, false, true,
        false, true, false, true, true, true, true, false, true, false, false, false, false, true,
        false, true, true, false, false, true, true, false, true, false, true, true, true, true,
        false, true, true, true, true, true, true, false, false, false, true, true, false, true,
        false, false, true, false, true, false, true, false, true, false, false, true, true, true,
        true, false, false, false, false,
    ];

    fn assert_bytes_ordered_correctly(bits: &Vec<bool>) {
        // Assuming bits came from vec![0xFF, 0x00];

        for bit in bits.iter().take(bits.len() / 2) {
            assert_eq!(*bit, true);
        }

        for bit in bits.iter().skip(bits.len() / 2) {
            assert_eq!(*bit, false);
        }
    }

    #[test]
    fn test_bytes_to_bits() {
        // Test bytes get ordered correctly
        let v = vec![0xFF, 0x00];

        assert_bytes_ordered_correctly(&bytes_to_little_endian_bits(&v));
        assert_bytes_ordered_correctly(&bytes_to_big_endian_bits(&v));

        // Test little-endian ordering of bits
        let v = vec![0x0F, 0x0F];
        let le_bits = bytes_to_little_endian_bits(&v);
        for offset in [0, 8] {
            for i in 0..4 {
                assert_eq!(le_bits[offset + i], true);
                assert_eq!(le_bits[offset + 4 + i], false);
            }
        }

        // Test big-endian ordering of bits
        let v = vec![0x0F, 0x0F];
        let le_bits = bytes_to_big_endian_bits(&v);
        for offset in [0, 8] {
            for i in 0..4 {
                assert_eq!(le_bits[offset + i], false);
                assert_eq!(le_bits[offset + 4 + i], true);
            }
        }

        // Test big-endianness
        let bits = bytes_to_big_endian_bits(&X_INV.to_vec());
        let be_bits = X_INV_BE_BITS.to_vec();
        assert_eq!(bits, be_bits);

        // Test little-endianness (and thus consistency with curve25519-dalek)
        let bits = bytes_to_little_endian_bits(&X_INV.to_vec());
        let le_bits = X_INV_LE_BITS.to_vec();
        assert_eq!(bits, le_bits);
    }
}

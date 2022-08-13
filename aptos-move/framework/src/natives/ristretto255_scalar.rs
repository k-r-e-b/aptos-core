// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use curve25519_dalek::scalar::Scalar;
use move_deps::{
    move_binary_format::errors::PartialVMResult,
    move_vm_runtime::native_functions::NativeContext,
    move_vm_types::{
        loaded_data::runtime_types::Type, natives::function::NativeResult, pop_arg, values::Value,
    },
};
use sha2::Sha512;
use smallvec::smallvec;
use std::ops::{Add, Mul, Neg, Sub};
use std::{collections::VecDeque, convert::TryFrom};

/// Constructs a curve25519-dalek Scalar from a sequence of bytes which are assumed to
/// canonically-encode it. Callers who are not sure of the canonicity of the encoding MUST call
/// Scalar::is_canonical() after on the returned Scalar.
pub fn scalar_from_valid_bytes(bytes: Vec<u8>) -> Scalar {
    // A Move Scalar's length should be exactly 32 bytes
    match <[u8; 32]>::try_from(bytes) {
        // NOTE: This will clear the high bit of 'slice'
        Ok(slice) => Scalar::from_bits(slice),
        Err(_) => {
            unreachable!()
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScalarIsCanonicalGasParameters {
    pub base_cost: u64,
    pub per_scalar_deserialize_cost: u64,
}

pub(crate) fn native_scalar_is_canonical(
    gas_params: &ScalarIsCanonicalGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    let bytes_slice = match <[u8; 32]>::try_from(bytes) {
        Ok(slice) => slice,
        Err(_) => return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    };

    let s = Scalar::from_canonical_bytes(bytes_slice);
    cost += gas_params.per_scalar_deserialize_cost;

    // TODO: Speed up this implementation using bit testing on 'bytes'?
    Ok(NativeResult::ok(cost, smallvec![Value::bool(s.is_some())]))
}

#[derive(Debug, Clone)]
pub struct ScalarInvertGasParameters {
    pub base_cost: u64,
    pub per_scalar_invert_cost: u64,
}

pub(crate) fn native_scalar_invert(
    gas_params: &ScalarInvertGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    let s = scalar_from_valid_bytes(bytes);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(s.is_canonical());

    // Invert and return
    cost += gas_params.per_scalar_invert_cost;
    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.invert().to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFromSha512GasParameters {
    pub base_cost: u64,
    pub per_hash_sha512_cost: u64,
    pub per_byte_sha512_cost: u64,
}

pub(crate) fn native_scalar_from_sha512(
    gas_params: &ScalarFromSha512GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    cost += gas_params.per_hash_sha512_cost + gas_params.per_byte_sha512_cost * bytes.len() as u64;
    let s = Scalar::hash_from_bytes::<Sha512>(bytes.as_slice());

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarMulGasParameters {
    pub base_cost: u64,
    pub mul_cost: u64,
}

pub(crate) fn native_scalar_mul(
    gas_params: &ScalarMulGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 2);

    let mut cost = gas_params.base_cost;

    let b_bytes = pop_arg!(arguments, Vec<u8>);
    let a_bytes = pop_arg!(arguments, Vec<u8>);

    let a = scalar_from_valid_bytes(a_bytes);
    let b = scalar_from_valid_bytes(b_bytes);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());
    debug_assert!(b.is_canonical());

    cost += gas_params.mul_cost;
    let s = a.mul(b);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}
#[derive(Debug, Clone)]
pub struct ScalarAddGasParameters {
    pub base_cost: u64,
    pub add_cost: u64,
}

pub(crate) fn native_scalar_add(
    gas_params: &ScalarAddGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 2);

    let mut cost = gas_params.base_cost;

    let b_bytes = pop_arg!(arguments, Vec<u8>);
    let a_bytes = pop_arg!(arguments, Vec<u8>);

    let a = scalar_from_valid_bytes(a_bytes);
    let b = scalar_from_valid_bytes(b_bytes);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());
    debug_assert!(b.is_canonical());

    cost += gas_params.add_cost;
    let s = a.add(b);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarSubGasParameters {
    pub base_cost: u64,
    pub sub_cost: u64,
}

pub(crate) fn native_scalar_sub(
    gas_params: &ScalarSubGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 2);

    let mut cost = gas_params.base_cost;

    let b_bytes = pop_arg!(arguments, Vec<u8>);
    let a_bytes = pop_arg!(arguments, Vec<u8>);

    let a = scalar_from_valid_bytes(a_bytes);
    let b = scalar_from_valid_bytes(b_bytes);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());
    debug_assert!(b.is_canonical());

    cost += gas_params.sub_cost;
    let s = a.sub(b);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarNegGasParameters {
    pub base_cost: u64,
    pub neg_cost: u64,
}

pub(crate) fn native_scalar_neg(
    gas_params: &ScalarNegGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let a_bytes = pop_arg!(arguments, Vec<u8>);

    let a = scalar_from_valid_bytes(a_bytes);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());

    cost += gas_params.neg_cost;
    let s = a.neg();

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFromU64GasParameters {
    pub base_cost: u64,
    pub from_u64_cost: u64,
}

pub(crate) fn native_scalar_from_u64(
    gas_params: &ScalarFromU64GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let num = pop_arg!(arguments, u64);

    cost += gas_params.from_u64_cost;
    let s = Scalar::from(num);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFromU128GasParameters {
    pub base_cost: u64,
    pub from_u128_cost: u64,
}

pub(crate) fn native_scalar_from_u128(
    gas_params: &ScalarFromU128GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let num = pop_arg!(arguments, u128);

    cost += gas_params.from_u128_cost;
    let s = Scalar::from(num);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFrom256BitsGasParameters {
    pub base_cost: u64,
    pub from_256_bits_cost: u64,
}

pub(crate) fn native_scalar_from_256_bits(
    gas_params: &ScalarFrom256BitsGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 32 bytes
    debug_assert!(bytes.len() == 32);
    let bytes_slice = match <[u8; 32]>::try_from(bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    cost += gas_params.from_256_bits_cost;
    let s = Scalar::from_bytes_mod_order(bytes_slice);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFrom512BitsGasParameters {
    pub base_cost: u64,
    pub from_512_bits_cost: u64,
}

pub(crate) fn native_scalar_from_512_bits(
    gas_params: &ScalarFrom512BitsGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 64 bytes
    debug_assert!(bytes.len() == 64);
    let bytes_slice = match <[u8; 64]>::try_from(bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 64
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    cost += gas_params.from_512_bits_cost;
    let s = Scalar::from_bytes_mod_order_wide(&bytes_slice);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::natives::cryptography::ristretto255::{
    pop_32_byte_slice, pop_64_byte_slice, pop_scalar, GasCost, GasParameters,
};
use curve25519_dalek::scalar::Scalar;
use move_deps::move_binary_format::errors::PartialVMError;
use move_deps::move_core_types::vm_status::StatusCode;
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
pub fn scalar_from_valid_bytes(bytes: Vec<u8>) -> PartialVMResult<Scalar> {
    // A Move Scalar's length should be exactly 32 bytes
    let slice = <[u8; 32]>::try_from(bytes)
        .map_err(|_| PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR))?;

    // NOTE: This will clear the high bit of 'slice'
    Ok(Scalar::from_bits(slice))
}

pub(crate) fn native_scalar_is_canonical(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = GasCost(gas_params.base_cost);

    let bytes = pop_arg!(arguments, Vec<u8>);
    if bytes.len() != 32 {
        return Ok(NativeResult::ok(cost.into(), smallvec![Value::bool(false)]));
    }

    let bytes_slice = <[u8; 32]>::try_from(bytes).unwrap();

    let s = Scalar::from_canonical_bytes(bytes_slice);
    cost.add(gas_params.scalar_is_canonical_cost);

    // TODO: Speed up this implementation using bit testing on 'bytes'?
    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::bool(s.is_some())],
    ))
}

pub(crate) fn native_scalar_invert(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = GasCost(gas_params.base_cost);

    let s = pop_scalar(&mut arguments)?;

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(s.is_canonical());

    // Invert and return
    cost.add(gas_params.scalar_invert_cost);
    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.invert().to_bytes().to_vec())],
    ))
}

pub(crate) fn native_scalar_from_sha512(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = GasCost(gas_params.base_cost);

    let bytes = pop_arg!(arguments, Vec<u8>);

    cost.add(gas_params.scalar_from_64_uniform_bytes_cost)
        .add(gas_params.sha512_per_hash_cost)
        .add(gas_params.sha512_per_byte_cost * bytes.len() as u64);
    let s = Scalar::hash_from_bytes::<Sha512>(bytes.as_slice());

    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

pub(crate) fn native_scalar_mul(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 2);

    let mut cost = GasCost(gas_params.base_cost);

    let b = pop_scalar(&mut arguments)?;
    let a = pop_scalar(&mut arguments)?;

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());
    debug_assert!(b.is_canonical());

    cost.add(gas_params.scalar_mul_cost);
    let s = a.mul(b);

    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

pub(crate) fn native_scalar_add(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 2);

    let mut cost = GasCost(gas_params.base_cost);

    let b = pop_scalar(&mut arguments)?;
    let a = pop_scalar(&mut arguments)?;

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());
    debug_assert!(b.is_canonical());

    cost.add(gas_params.scalar_add_cost);
    let s = a.add(b);

    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

pub(crate) fn native_scalar_sub(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 2);

    let mut cost = GasCost(gas_params.base_cost);

    let b = pop_scalar(&mut arguments)?;
    let a = pop_scalar(&mut arguments)?;

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());
    debug_assert!(b.is_canonical());

    cost.add(gas_params.scalar_sub_cost);
    let s = a.sub(b);

    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

pub(crate) fn native_scalar_neg(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = GasCost(gas_params.base_cost);

    let a = pop_scalar(&mut arguments)?;

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());

    cost.add(gas_params.scalar_neg_cost);
    let s = a.neg();

    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

pub(crate) fn native_scalar_from_u64(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = GasCost(gas_params.base_cost);

    let num = pop_arg!(arguments, u64);

    cost.add(gas_params.scalar_from_u64_cost);
    let s = Scalar::from(num);

    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

pub(crate) fn native_scalar_from_u128(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = GasCost(gas_params.base_cost);

    let num = pop_arg!(arguments, u128);

    cost.add(gas_params.scalar_from_u128_cost);
    let s = Scalar::from(num);

    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

pub(crate) fn native_scalar_from_256_bits(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = GasCost(gas_params.base_cost);

    let bytes_slice = pop_32_byte_slice(&mut arguments)?;

    cost.add(gas_params.scalar_from_256_bits_cost);
    let s = Scalar::from_bytes_mod_order(bytes_slice);

    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

pub(crate) fn native_scalar_from_64_uniform_bytes(
    gas_params: &GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(args.len() == 1);

    let mut cost = GasCost(gas_params.base_cost);

    let bytes_slice = pop_64_byte_slice(&mut args)?;

    cost.add(gas_params.scalar_from_64_uniform_bytes_cost);
    let s = Scalar::from_bytes_mod_order_wide(&bytes_slice);

    Ok(NativeResult::ok(
        cost.into(),
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

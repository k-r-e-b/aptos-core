// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::natives::cryptography::{ristretto255_point, ristretto255_scalar};
use crate::natives::util::make_native_from_func;
use aptos_types::vm_status::StatusCode;
use curve25519_dalek::scalar::Scalar;
use move_deps::move_binary_format::errors::{PartialVMError, PartialVMResult};
use move_deps::move_vm_types::values::Value;
use move_deps::{move_vm_runtime::native_functions::NativeFunction, move_vm_types::pop_arg};
use std::collections::VecDeque;

pub struct GasCost(pub(crate) u64);

impl GasCost {
    pub fn add(&mut self, op_cost: u64) -> &mut GasCost {
        self.0 += op_cost;
        self
    }
}

impl From<GasCost> for u64 {
    fn from(c: GasCost) -> Self {
        c.0
    }
}

#[derive(Debug, Clone)]
pub struct GasParameters {
    pub base_cost: u64,

    pub basepoint_double_mul_cost: u64,

    pub point_add_cost: u64,
    pub point_compress_cost: u64,
    pub point_decompress_cost: u64,
    pub point_equals_cost: u64,
    pub point_from_64_uniform_bytes_cost: u64,
    pub point_identity_cost: u64,
    pub point_mul_cost: u64,
    pub point_neg_cost: u64,
    pub point_sub_cost: u64,

    pub sha512_per_byte_cost: u64,
    pub sha512_per_hash_cost: u64,

    pub scalar_add_cost: u64,
    pub scalar_from_256_bits_cost: u64,
    pub scalar_from_64_uniform_bytes_cost: u64,
    pub scalar_from_u128_cost: u64,
    pub scalar_from_u64_cost: u64,
    pub scalar_invert_cost: u64,
    pub scalar_is_canonical_cost: u64,
    pub scalar_mul_cost: u64,
    pub scalar_neg_cost: u64,
    pub scalar_sub_cost: u64,
}

pub fn make_all(gas_params: GasParameters) -> impl Iterator<Item = (String, NativeFunction)> {
    let natives = [
        (
            "point_is_canonical_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_point::native_point_is_canonical,
            ),
        ),
        (
            "point_identity_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_point::native_point_identity,
            ),
        ),
        (
            "point_decompress_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_point::native_point_decompress,
            ),
        ),
        (
            "point_compress_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_point::native_point_compress,
            ),
        ),
        (
            "point_mul_internal",
            make_native_from_func(gas_params.clone(), ristretto255_point::native_point_mul),
        ),
        (
            "point_equals",
            make_native_from_func(gas_params.clone(), ristretto255_point::native_point_equals),
        ),
        (
            "point_neg_internal",
            make_native_from_func(gas_params.clone(), ristretto255_point::native_point_neg),
        ),
        (
            "point_add_internal",
            make_native_from_func(gas_params.clone(), ristretto255_point::native_point_add),
        ),
        (
            "point_sub_internal",
            make_native_from_func(gas_params.clone(), ristretto255_point::native_point_sub),
        ),
        (
            "basepoint_double_mul_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_point::native_basepoint_double_mul,
            ),
        ),
        (
            "new_point_from_sha512_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_point::native_new_point_from_sha512,
            ),
        ),
        (
            "new_point_from_64_uniform_bytes_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_point::native_new_point_from_64_uniform_bytes,
            ),
        ),
        (
            "scalar_is_canonical_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_scalar::native_scalar_is_canonical,
            ),
        ),
        (
            "scalar_invert_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_scalar::native_scalar_invert,
            ),
        ),
        (
            "scalar_from_sha512_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_scalar::native_scalar_from_sha512,
            ),
        ),
        (
            "scalar_mul_internal",
            make_native_from_func(gas_params.clone(), ristretto255_scalar::native_scalar_mul),
        ),
        (
            "scalar_add_internal",
            make_native_from_func(gas_params.clone(), ristretto255_scalar::native_scalar_add),
        ),
        (
            "scalar_sub_internal",
            make_native_from_func(gas_params.clone(), ristretto255_scalar::native_scalar_sub),
        ),
        (
            "scalar_neg_internal",
            make_native_from_func(gas_params.clone(), ristretto255_scalar::native_scalar_neg),
        ),
        (
            "scalar_from_u64_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_scalar::native_scalar_from_u64,
            ),
        ),
        (
            "scalar_from_u128_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_scalar::native_scalar_from_u128,
            ),
        ),
        (
            "scalar_from_256_bits_internal",
            make_native_from_func(
                gas_params.clone(),
                ristretto255_scalar::native_scalar_from_256_bits,
            ),
        ),
        (
            "scalar_from_64_uniform_bytes_internal",
            make_native_from_func(
                gas_params,
                ristretto255_scalar::native_scalar_from_64_uniform_bytes,
            ),
        ),
    ];

    crate::natives::helpers::make_module_natives(natives)
}

/// Pops a 32 byte slice off the argument stack.
pub fn pop_32_byte_slice(arguments: &mut VecDeque<Value>) -> PartialVMResult<[u8; 32]> {
    let bytes = pop_arg!(arguments, Vec<u8>);

    <[u8; 32]>::try_from(bytes).map_err(|_| PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR))
}

/// Pops a 64 byte slice off the argument stack.
pub fn pop_64_byte_slice(arguments: &mut VecDeque<Value>) -> PartialVMResult<[u8; 64]> {
    let bytes = pop_arg!(arguments, Vec<u8>);

    <[u8; 64]>::try_from(bytes).map_err(|_| PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR))
}

/// Pops a Scalar off the argument stack.
pub fn pop_scalar(arguments: &mut VecDeque<Value>) -> PartialVMResult<Scalar> {
    let bytes = pop_arg!(arguments, Vec<u8>);

    ristretto255_scalar::scalar_from_valid_bytes(bytes)
}

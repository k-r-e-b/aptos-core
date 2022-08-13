// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::natives::ristretto255_point;
use crate::natives::ristretto255_point::{
    PointAddGasParameters, PointCompressGasParameters, PointDecompressGasParameters,
    PointEqualsGasParameters, PointIdentityGasParameters, PointIsCanonicalGasParameters,
    PointMulGasParameters, PointNegGasParameters, PointSubGasParameters,
};
use crate::natives::ristretto255_scalar;
use crate::natives::ristretto255_scalar::{
    ScalarAddGasParameters, ScalarFrom256BitsGasParameters, ScalarFrom512BitsGasParameters,
    ScalarFromSha512GasParameters, ScalarFromU128GasParameters, ScalarFromU64GasParameters,
    ScalarInvertGasParameters, ScalarIsCanonicalGasParameters, ScalarMulGasParameters,
    ScalarNegGasParameters, ScalarSubGasParameters,
};
use crate::natives::util::make_native_from_func;
use move_deps::move_vm_runtime::native_functions::NativeFunction;

#[derive(Debug, Clone)]
pub struct GasParameters {
    pub point_is_canonical: PointIsCanonicalGasParameters,
    pub point_identity: PointIdentityGasParameters,
    pub point_decompress: PointDecompressGasParameters,
    pub point_compress: PointCompressGasParameters,
    pub point_mul: PointMulGasParameters,
    pub point_equals: PointEqualsGasParameters,
    pub point_neg: PointNegGasParameters,
    pub point_add: PointAddGasParameters,
    pub point_sub: PointSubGasParameters,

    pub scalar_is_canonical: ScalarIsCanonicalGasParameters,
    pub scalar_invert: ScalarInvertGasParameters,
    pub scalar_from_sha512: ScalarFromSha512GasParameters,
    pub scalar_mul: ScalarMulGasParameters,
    pub scalar_add: ScalarAddGasParameters,
    pub scalar_sub: ScalarSubGasParameters,
    pub scalar_neg: ScalarNegGasParameters,
    pub scalar_from_u64: ScalarFromU64GasParameters,
    pub scalar_from_u128: ScalarFromU128GasParameters,
    pub scalar_from_256_bits: ScalarFrom256BitsGasParameters,
    pub scalar_from_512_bits: ScalarFrom512BitsGasParameters,
}

pub fn make_all(gas_params: GasParameters) -> impl Iterator<Item = (String, NativeFunction)> {
    let natives = [
        (
            "point_is_canonical_internal",
            make_native_from_func(
                gas_params.point_is_canonical,
                ristretto255_point::native_point_is_canonical,
            ),
        ),
        (
            "point_identity_internal",
            make_native_from_func(
                gas_params.point_identity,
                ristretto255_point::native_point_identity,
            ),
        ),
        (
            "point_decompress_internal",
            make_native_from_func(
                gas_params.point_decompress,
                ristretto255_point::native_point_decompress,
            ),
        ),
        (
            "point_compress_internal",
            make_native_from_func(
                gas_params.point_compress,
                ristretto255_point::native_point_compress,
            ),
        ),
        (
            "point_mul_internal",
            make_native_from_func(gas_params.point_mul, ristretto255_point::native_point_mul),
        ),
        (
            "point_equals",
            make_native_from_func(
                gas_params.point_equals,
                ristretto255_point::native_point_equals,
            ),
        ),
        (
            "point_neg_internal",
            make_native_from_func(gas_params.point_neg, ristretto255_point::native_point_neg),
        ),
        (
            "point_add_internal",
            make_native_from_func(gas_params.point_add, ristretto255_point::native_point_add),
        ),
        (
            "point_sub_internal",
            make_native_from_func(gas_params.point_sub, ristretto255_point::native_point_sub),
        ),
        (
            "scalar_is_canonical_internal",
            make_native_from_func(
                gas_params.scalar_is_canonical,
                ristretto255_scalar::native_scalar_is_canonical,
            ),
        ),
        (
            "scalar_invert_internal",
            make_native_from_func(
                gas_params.scalar_invert,
                ristretto255_scalar::native_scalar_invert,
            ),
        ),
        (
            "scalar_from_sha512_internal",
            make_native_from_func(
                gas_params.scalar_from_sha512,
                ristretto255_scalar::native_scalar_from_sha512,
            ),
        ),
        (
            "scalar_mul_internal",
            make_native_from_func(
                gas_params.scalar_mul,
                ristretto255_scalar::native_scalar_mul,
            ),
        ),
        (
            "scalar_add_internal",
            make_native_from_func(
                gas_params.scalar_add,
                ristretto255_scalar::native_scalar_add,
            ),
        ),
        (
            "scalar_sub_internal",
            make_native_from_func(
                gas_params.scalar_sub,
                ristretto255_scalar::native_scalar_sub,
            ),
        ),
        (
            "scalar_neg_internal",
            make_native_from_func(
                gas_params.scalar_neg,
                ristretto255_scalar::native_scalar_neg,
            ),
        ),
        (
            "scalar_from_u64_internal",
            make_native_from_func(
                gas_params.scalar_from_u64,
                ristretto255_scalar::native_scalar_from_u64,
            ),
        ),
        (
            "scalar_from_u128_internal",
            make_native_from_func(
                gas_params.scalar_from_u128,
                ristretto255_scalar::native_scalar_from_u128,
            ),
        ),
        (
            "scalar_from_256_bits_internal",
            make_native_from_func(
                gas_params.scalar_from_256_bits,
                ristretto255_scalar::native_scalar_from_256_bits,
            ),
        ),
        (
            "scalar_from_512_bits_internal",
            make_native_from_func(
                gas_params.scalar_from_512_bits,
                ristretto255_scalar::native_scalar_from_512_bits,
            ),
        ),
    ];

    crate::natives::helpers::make_module_natives(natives)
}

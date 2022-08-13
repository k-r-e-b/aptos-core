// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

//! A crate which extends Move with a RistrettoPoint struct that points to a Rust-native
//! curve25519_dalek::ristretto::RistrettoPoint.

use crate::natives::ristretto255_scalar::scalar_from_valid_bytes;
use better_any::{Tid, TidAble};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use move_deps::{
    move_binary_format::errors::PartialVMResult,
    move_vm_runtime::native_functions::NativeContext,
    move_vm_types::{
        loaded_data::runtime_types::Type,
        natives::function::NativeResult,
        pop_arg,
        values::{Reference, StructRef, Value},
    },
};
use smallvec::smallvec;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::{cell::RefCell, collections::VecDeque, convert::TryFrom, fmt::Display};

// ===========================================================================================
// Public Data Structures and Constants

// TODO(Alin): Could make this generic and re-use for BLS
// TODO(Alin): Refactor gas parameters to avoid redeclaring stuff

/// The representation of a RistrettoPoint handle.
/// The handle is just an incrementing counter whenever a new point is added to the PointStore.
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct RistrettoPointHandle(pub u64);

impl Display for RistrettoPointHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "RistrettoPoint-{:X}", self.0)
    }
}

/// The native RistrettoPoint context extension. This needs to be attached to the NativeContextExtensions
/// value which is passed into session functions, so its accessible from natives of this extension.
#[derive(Tid)]
pub struct NativeRistrettoPointContext {
    point_data: RefCell<PointStore>,
}

// ===========================================================================================
// Private Data Structures and Constants

/// A structure representing mutable data of the NativeRistrettoPointContext. This is in a RefCell
/// of the overall context so we can mutate while still accessing the overall context.
#[derive(Default)]
struct PointStore {
    points: Vec<RistrettoPoint>,
}

/// The field index of the `handle` field in the `RistrettoPoint` Move struct.
const HANDLE_FIELD_INDEX: usize = 0;

// =========================================================================================
// Implementation of Native RistrettoPoint Context

impl NativeRistrettoPointContext {
    /// Create a new instance of a native RistrettoPoint context. This must be passed in via an
    /// extension into VM session functions.
    pub fn new() -> Self {
        Self {
            point_data: Default::default(),
        }
    }
}

impl PointStore {
    /// Re-sets a RistrettoPoint that was previously allocated.
    fn set_point(&mut self, handle: &RistrettoPointHandle, point: RistrettoPoint) {
        self.points[handle.0 as usize] = point
    }

    /// Gets a RistrettoPoint that was previously allocated.
    fn get_point(&self, handle: &RistrettoPointHandle) -> &RistrettoPoint {
        //&self.points[handle.0 as usize]
        self.points.get(handle.0 as usize).unwrap()
    }

    /// Gets a RistrettoPoint that was previously allocated.
    fn get_point_mut(&mut self, handle: &RistrettoPointHandle) -> &mut RistrettoPoint {
        //&mut self.points[handle.0 as usize]
        self.points.get_mut(handle.0 as usize).unwrap()
    }

    /// Returns mutable references to two different Ristretto points in the vector using split_at_mut.
    /// Note that Rust's linear types prevent us from simply returning `(&mut points[i], &mut points[j])`.
    fn get_two_muts(
        &mut self,
        a: &RistrettoPointHandle,
        b: &RistrettoPointHandle,
    ) -> (&mut RistrettoPoint, &mut RistrettoPoint) {
        use std::cmp::Ordering;

        // println!("orig a: {a}");
        // println!("orig b: {b}");

        let (sw, a, b) = match Ord::cmp(&a, &b) {
            Ordering::Less => (false, a.0 as usize, b.0 as usize),
            Ordering::Greater => (true, b.0 as usize, a.0 as usize),
            Ordering::Equal => panic!("attempted to exclusive-borrow one element twice"),
        };

        // println!("a: {a}");
        // println!("b: {b}");
        // println!("b - a + 1: {}", b - a + 1);

        let (left, right) = self.points.split_at_mut(a + 1);
        let (a_ref, b_ref) = (&mut left[a], &mut right[b - (a + 1)]);

        if sw {
            (b_ref, a_ref)
        } else {
            (a_ref, b_ref)
        }
    }

    /// Adds the point to the store and returns its RistrettoPointHandle ID
    pub fn add_point(&mut self, point: RistrettoPoint) -> u64 {
        let id = self.points.len();
        self.points.push(point);

        id as u64
    }
}

// =========================================================================================
// Native Function Implementations

#[derive(Debug, Clone)]
pub struct PointIdentityGasParameters {
    pub base_cost: u64,
}

pub(crate) fn native_point_identity(
    gas_params: &PointIdentityGasParameters,
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(ty_args.len(), 0);
    assert_eq!(args.len(), 0);

    let cost = gas_params.base_cost;

    let point_context = context.extensions().get::<NativeRistrettoPointContext>();
    let mut point_data = point_context.point_data.borrow_mut();

    let result_handle = point_data.add_point(RistrettoPoint::identity());

    Ok(NativeResult::ok(cost, smallvec![Value::u64(result_handle)]))
}

#[derive(Debug, Clone)]
pub struct PointIsCanonicalGasParameters {
    pub base_cost: u64,
    pub is_canonical_cost: u64,
}

pub(crate) fn native_point_is_canonical(
    gas_params: &PointIsCanonicalGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(_ty_args.len(), 0);
    assert_eq!(args.len(), 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(args, Vec<u8>);

    let opt_point =
        decompress_maybe_non_canonical_point_bytes(&mut cost, gas_params.is_canonical_cost, bytes);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::bool(opt_point.is_some())],
    ))
}

#[derive(Debug, Clone)]
pub struct PointDecompressGasParameters {
    pub base_cost: u64,
    pub decompress_cost: u64,
}

pub(crate) fn native_point_decompress(
    gas_params: &PointDecompressGasParameters,
    context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(_ty_args.len(), 0);
    assert_eq!(args.len(), 1);

    let point_context = context.extensions().get::<NativeRistrettoPointContext>();
    let mut point_data = point_context.point_data.borrow_mut();

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(args, Vec<u8>);

    let point = match decompress_maybe_non_canonical_point_bytes(
        &mut cost,
        gas_params.decompress_cost,
        bytes,
    ) {
        Some(point) => point,
        None => {
            // NOTE: We return (u64::MAX, false) in this case.
            return Ok(NativeResult::ok(
                cost,
                smallvec![Value::u64(u64::MAX), Value::bool(false)],
            ));
        }
    };

    // Take the # of points produced so far, which creates a unique and deterministic global ID
    // within the temporary scope of this current transaction. Then, store the RistrettoPoint in
    // a vector using this global ID as an index.
    let id = point_data.add_point(point);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::u64(id), Value::bool(true)],
    ))
}

#[derive(Debug, Clone)]
pub struct PointCompressGasParameters {
    pub base_cost: u64,
}

pub(crate) fn native_point_compress(
    gas_params: &PointCompressGasParameters,
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(ty_args.len(), 0);
    assert_eq!(args.len(), 1);

    let cost = gas_params.base_cost;

    let point_context = context.extensions().get::<NativeRistrettoPointContext>();
    let mut point_data = point_context.point_data.borrow_mut();

    let handle = get_point_handle(&pop_arg!(args, StructRef))?;

    let point = point_data.get_point_mut(&handle);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(point.compress().to_bytes())],
    ))
}

#[derive(Debug, Clone)]
pub struct PointMulGasParameters {
    pub base_cost: u64,
}

pub(crate) fn native_point_mul(
    gas_params: &PointMulGasParameters,
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(ty_args.len(), 0);
    assert_eq!(args.len(), 3);

    let cost = gas_params.base_cost;

    let point_context = context.extensions().get::<NativeRistrettoPointContext>();
    let mut point_data = point_context.point_data.borrow_mut();

    let in_place = pop_arg!(args, bool);
    let scalar_bytes = pop_arg!(args, Vec<u8>);
    let point_handle = get_point_handle(&pop_arg!(args, StructRef))?;

    let scalar = scalar_from_valid_bytes(scalar_bytes);
    debug_assert!(scalar.is_canonical());

    // Compute result = a * point (or a = a * point) and return a RistrettoPointHandle
    let result_handle = match in_place {
        false => {
            let point = point_data.get_point(&point_handle).mul(scalar);
            point_data.add_point(point)
        }
        true => {
            point_data.get_point_mut(&point_handle).mul_assign(scalar);
            point_handle.0
        }
    };

    Ok(NativeResult::ok(cost, smallvec![Value::u64(result_handle)]))
}

#[derive(Debug, Clone)]
pub struct PointEqualsGasParameters {
    pub base_cost: u64,
}

pub(crate) fn native_point_equals(
    gas_params: &PointEqualsGasParameters,
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(ty_args.len(), 0);
    assert_eq!(args.len(), 2);

    let cost = gas_params.base_cost;

    let point_context = context.extensions().get::<NativeRistrettoPointContext>();
    let point_data = point_context.point_data.borrow_mut();

    let b_handle = get_point_handle(&pop_arg!(args, StructRef))?;
    let a_handle = get_point_handle(&pop_arg!(args, StructRef))?;

    let a = point_data.get_point(&a_handle);
    let b = point_data.get_point(&b_handle);

    // Checks if a == b
    Ok(NativeResult::ok(cost, smallvec![Value::bool(a.eq(b))]))
}

#[derive(Debug, Clone)]
pub struct PointNegGasParameters {
    pub base_cost: u64,
}

pub(crate) fn native_point_neg(
    gas_params: &PointNegGasParameters,
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(ty_args.len(), 0);
    assert_eq!(args.len(), 2);

    let cost = gas_params.base_cost;

    let point_context = context.extensions().get::<NativeRistrettoPointContext>();
    let mut point_data = point_context.point_data.borrow_mut();

    let in_place = pop_arg!(args, bool);
    let point_handle = get_point_handle(&pop_arg!(args, StructRef))?;

    // Compute result = - point (or point = -point) and return a RistrettoPointHandle
    let result_handle = match in_place {
        false => {
            let point = point_data.get_point(&point_handle).neg();
            point_data.add_point(point)
        }
        true => {
            let neg = point_data.get_point_mut(&point_handle).neg();
            point_data.set_point(&point_handle, neg);
            point_handle.0
        }
    };

    Ok(NativeResult::ok(cost, smallvec![Value::u64(result_handle)]))
}

#[derive(Debug, Clone)]
pub struct PointAddGasParameters {
    pub base_cost: u64,
}

pub(crate) fn native_point_add(
    gas_params: &PointAddGasParameters,
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(ty_args.len(), 0);
    assert_eq!(args.len(), 3);

    let cost = gas_params.base_cost;

    let point_context = context.extensions().get::<NativeRistrettoPointContext>();
    let mut point_data = point_context.point_data.borrow_mut();

    let in_place = pop_arg!(args, bool);
    let b_handle = get_point_handle(&pop_arg!(args, StructRef))?;
    let a_handle = get_point_handle(&pop_arg!(args, StructRef))?;

    // Compute result = a + b (or a = a + b) and return a RistrettoPointHandle
    let result_handle = match in_place {
        false => {
            let a = point_data.get_point(&a_handle);
            let b = point_data.get_point(&b_handle);

            let point = a.add(b);
            point_data.add_point(point)
        }
        true => {
            // NOTE: When calling Move's add_assign, Move's linear types ensure that we will never
            // get references to the same a and b RistrettoPoint, while our own invariants ensure
            // we never have two different Move RistrettoPoint constructed with the same handles.
            debug_assert!(a_handle != b_handle);
            let (a, b) = point_data.get_two_muts(&a_handle, &b_handle);

            a.add_assign(&*b);
            a_handle.0
        }
    };

    Ok(NativeResult::ok(cost, smallvec![Value::u64(result_handle)]))
}

#[derive(Debug, Clone)]
pub struct PointSubGasParameters {
    pub base_cost: u64,
}

pub(crate) fn native_point_sub(
    gas_params: &PointSubGasParameters,
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    assert_eq!(ty_args.len(), 0);
    assert_eq!(args.len(), 3);

    let cost = gas_params.base_cost;

    let point_context = context.extensions().get::<NativeRistrettoPointContext>();
    let mut point_data = point_context.point_data.borrow_mut();

    let in_place = pop_arg!(args, bool);
    let b_handle = get_point_handle(&pop_arg!(args, StructRef))?;
    let a_handle = get_point_handle(&pop_arg!(args, StructRef))?;

    // Compute result = a - b (or a = a - b) and return a RistrettoPointHandle
    let result_handle = match in_place {
        false => {
            let a = point_data.get_point(&a_handle);
            let b = point_data.get_point(&b_handle);

            let point = a.sub(b);
            point_data.add_point(point)
        }
        true => {
            // NOTE: When calling Move's sub_assign, Move's linear types ensure that we will never
            // get references to the same a and b RistrettoPoint, while our own invariants ensure
            // we never have two different Move RistrettoPoint constructed with the same handles.
            debug_assert!(a_handle != b_handle);
            let (a, b) = point_data.get_two_muts(&a_handle, &b_handle);

            a.sub_assign(&*b);
            a_handle.0
        }
    };

    Ok(NativeResult::ok(cost, smallvec![Value::u64(result_handle)]))
}

// =========================================================================================
// Helpers

fn get_point_handle(move_point: &StructRef) -> PartialVMResult<RistrettoPointHandle> {
    let field_ref = move_point
        .borrow_field(HANDLE_FIELD_INDEX)?
        .value_as::<Reference>()?;

    field_ref
        .read_ref()?
        .value_as::<u64>()
        .map(RistrettoPointHandle)
}

fn compressed_point_from_bytes(bytes: Vec<u8>) -> Option<CompressedRistretto> {
    match <[u8; 32]>::try_from(bytes) {
        Ok(slice) => Some(CompressedRistretto(slice)),
        Err(_) => {
            // NOTE: We return MAX in this case. Since the caller always passes in 32 bytes to this
            // function, this path should never be reached.
            None
        }
    }
}

/// If 'bytes' canonically-encode a valid RistrettoPoint, returns the point.  Otherwise, returns None.
fn decompress_maybe_non_canonical_point_bytes(
    cumulative_cost: &mut u64,
    op_cost: u64,
    bytes: Vec<u8>,
) -> Option<RistrettoPoint> {
    let compressed = match compressed_point_from_bytes(bytes) {
        None => return None,
        Some(point) => point,
    };

    *cumulative_cost += op_cost;
    compressed.decompress()
}

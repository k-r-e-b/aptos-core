// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use framework::natives::GasParameters;

crate::natives::define_gas_parameters_for_natives!(GasParameters, "aptos_framework", [
    [.account.create_address.base_cost, "account.create_address.base", 1],
    [.account.create_signer.base_cost, "account.create_signer.base", 1],

    [.bls12381.base_cost, "bls12381.base", 1],

    [.bls12381.per_pubkey_deserialize_cost, "bls12381.per_pubkey_deserialize", 1],
    [.bls12381.per_pubkey_aggregate_cost, "bls12381.per_pubkey_aggregate", 1],
    [.bls12381.per_pubkey_subgroup_check_cost, "bls12381.per_pubkey_subgroup_check", 1],

    [.bls12381.per_sig_deserialize_cost, "bls12381.per_sig_deserialize", 1],
    [.bls12381.per_sig_aggregate_cost, "bls12381.per_sig_aggregate", 1],
    [.bls12381.per_sig_subgroup_check_cost, "bls12381.per_sig_subgroup_check", 1],

    [.bls12381.per_sig_verify_cost, "bls12381.per_sig_verify", 1],
    [.bls12381.per_pop_verify_cost, "bls12381.per_pop_verify", 1],

    [.bls12381.per_pairing_cost, "bls12381.per_pairing", 1],

    [.bls12381.per_msg_hashing_cost, "bls12381.per_msg_hashing", 1],
    [.bls12381.per_byte_hashing_cost, "bls12381.per_byte_hashing", 1],

    [.bit_vector.little_endian_bitvector_from_byte_vector.base_cost, "bit_vector.little_endian_bitvector_from_byte_vector.base", 1],
    [.bit_vector.little_endian_bitvector_from_byte_vector.per_byte_cost, "bit_vector.little_endian_bitvector_from_byte_vector.per_byte", 1],

    [.bit_vector.big_endian_bitvector_from_byte_vector.base_cost, "bit_vector.big_endian_bitvector_from_byte_vector.base", 1],
    [.bit_vector.big_endian_bitvector_from_byte_vector.per_byte_cost, "bit_vector.big_endian_bitvector_from_byte_vector.per_byte", 1],

    [.ristretto255.point_is_canonical.base_cost, "cryptography.ristretto255.point_is_canonical.base", 1],
    [.ristretto255.point_is_canonical.is_canonical_cost, "cryptography.point_is_canonical.is_canonical", 1],

    [.ristretto255.point_identity.base_cost, "cryptography.ristretto255.point_identity.base", 1 ],

    [.ristretto255.point_decompress.base_cost, "cryptography.ristretto255.point_decompress.base", 1 ],
    [.ristretto255.point_decompress.decompress_cost, "cryptography.ristretto255.point_decompress.decompress", 1 ],

    [.ristretto255.point_compress.base_cost, "cryptography.ristretto255.point_compress.base", 1 ],

    [.ristretto255.point_mul.base_cost, "cryptography.ristretto255.point_mul.base", 1 ],

    [.ristretto255.point_equals.base_cost, "cryptography.ristretto255.point_equals.base", 1 ],

    [.ristretto255.point_neg.base_cost, "cryptography.ristretto255.point_neg.base", 1 ],

    [.ristretto255.point_add.base_cost, "cryptography.ristretto255.point_add.base", 1 ],
    [.ristretto255.point_sub.base_cost, "cryptography.ristretto255.point_add.base", 1 ],

    [.ristretto255.scalar_is_canonical.base_cost, "cryptography.ristretto255.scalar_is_canonical.base", 1],
    [.ristretto255.scalar_is_canonical.per_scalar_deserialize_cost, "cryptography.ristretto255.scalar_is_canonical.per_scalar_deserialize", 1],

    [.ristretto255.scalar_invert.base_cost, "cryptography.ristretto255.scalar_invert.base", 1],
    [.ristretto255.scalar_invert.per_scalar_invert_cost, "cryptography.ristretto255.scalar_invert.per_scalar_invert", 1],

    [.ristretto255.scalar_from_sha512.base_cost, "cryptography.ristretto255.scalar_from_sha512.base", 1],
    [.ristretto255.scalar_from_sha512.per_hash_sha512_cost, "cryptography.ristretto255.scalar_from_sha512.per_hash_sha512", 1],
    [.ristretto255.scalar_from_sha512.per_byte_sha512_cost, "cryptography.ristretto255.scalar_from_sha512.per_byte_sha512", 1],

    [.ristretto255.scalar_mul.base_cost, "cryptography.ristretto255.scalar_mul.base", 1],
    [.ristretto255.scalar_mul.mul_cost, "cryptography.ristretto255.scalar_mul.mul", 1],

    [.ristretto255.scalar_add.base_cost, "cryptography.ristretto255.scalar_add.base", 1],
    [.ristretto255.scalar_add.add_cost, "cryptography.ristretto255.scalar_add.add", 1],

    [.ristretto255.scalar_sub.base_cost, "cryptography.ristretto255.scalar_sub.base", 1],
    [.ristretto255.scalar_sub.sub_cost, "cryptography.ristretto255.scalar_sub.sub", 1],

    [.ristretto255.scalar_neg.base_cost, "cryptography.ristretto255.scalar_neg.base", 1],
    [.ristretto255.scalar_neg.neg_cost, "cryptography.ristretto255.scalar_neg.neg", 1],

    [.ristretto255.scalar_from_u64.base_cost, "cryptography.ristretto255.scalar_from_u64.base", 1],
    [.ristretto255.scalar_from_u64.from_u64_cost, "cryptography.ristretto255.scalar_from_u64.from_u64", 1],

    [.ristretto255.scalar_from_u128.base_cost, "cryptography.ristretto255.scalar_from_u128.base", 1],
    [.ristretto255.scalar_from_u128.from_u128_cost, "cryptography.ristretto255.scalar_from_u128.from_u128", 1],

    [.ristretto255.scalar_from_256_bits.base_cost, "cryptography.ristretto255.scalar_from_256_bits.base", 1],
    [.ristretto255.scalar_from_256_bits.from_256_bits_cost, "cryptography.ristretto255.scalar_from_256_bits.from_256_bits", 1],

    [.ristretto255.scalar_from_512_bits.base_cost, "cryptography.ristretto255.scalar_from_512_bits.base", 1],
    [.ristretto255.scalar_from_512_bits.from_512_bits_cost, "cryptography.ristretto255.scalar_from_512_bits.from_512_bits", 1],

    [.signature.ed25519_validate_pubkey.base_cost, "signature.ed25519_validate_pubkey.base", 1],
    [.signature.ed25519_validate_pubkey.per_pubkey_deserialize_cost, "signature.ed25519_validate_pubkey.per_pubkey_deserialize", 1],
    [.signature.ed25519_validate_pubkey.per_pubkey_small_order_check_cost, "signature.ed25519_validate_pubkey.per_pubkey_small_order_check", 1],

    [.signature.ed25519_verify.base_cost, "signature.ed25519_verify.base", 1],
    [.signature.ed25519_verify.per_pubkey_deserialize_cost, "signature.ed25519_verify.per_pubkey_deserialize", 1],
    [.signature.ed25519_verify.per_sig_deserialize_cost, "signature.ed25519_verify.per_sig_deserialize", 1],
    [.signature.ed25519_verify.per_sig_strict_verify_cost, "signature.ed25519_verify.per_sig_strict_verify", 1],
    [.signature.ed25519_verify.per_msg_hashing_base_cost, "signature.ed25519_verify.per_msg_hashing_base", 1],
    [.signature.ed25519_verify.per_msg_byte_hashing_cost, "signature.ed25519_verify.per_msg_byte_hashing", 1],

    [.signature.secp256k1_ecdsa_recover.base_cost, "signature.secp256k1_ecdsa_recover.base", 1],

    [.hash.sip_hash.base_cost, "hash.sip_hash.base", 1],
    [.hash.sip_hash.unit_cost, "hash.sip_hash.unit", 1],

    [.type_info.type_of.base_cost, "type_info.type_of.base", 1],
    [.type_info.type_of.unit_cost, "type_info.type_of.unit", 1],
    [.type_info.type_name.base_cost, "type_info.type_name.base", 1],
    [.type_info.type_name.unit_cost, "type_info.type_name.unit", 1],

    [.util.from_bytes.base_cost, "util.from_bytes.base", 1],
    [.util.from_bytes.unit_cost, "util.from_bytes.unit", 1],

    [.transaction_context.get_script_hash.base_cost, "transaction_context.get_script_hash.base", 1],

    [.code.request_publish.base_cost, "code.request_publish.base", 1],
    [.code.request_publish.unit_cost, "code.request_publish.unit", 1],

    [.event.write_to_event_store.unit_cost, "event.write_to_event_store.unit", 1],
]);

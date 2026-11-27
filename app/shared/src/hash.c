// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shared/hash.h"
#include "ripemd160.h"
#include "shared/mem_util.h"

psa_status_t hash_sha256_stream_init(hash_sha256_stream_t *stream)
{
    if (!stream) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_hash_operation_t fresh = PSA_HASH_OPERATION_INIT;
    stream->op = fresh;
    return psa_hash_setup(&stream->op, PSA_ALG_SHA_256);
}

psa_status_t hash_sha256_stream_update(hash_sha256_stream_t *stream, const uint8_t *input,
                                       size_t input_size)
{
    if (!stream) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (input_size == 0) {
        return PSA_SUCCESS;
    }
    if (!input) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = psa_hash_update(&stream->op, input, input_size);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&stream->op);
    }
    return status;
}

psa_status_t hash_sha256_stream_finish(hash_sha256_stream_t *stream, uint8_t *hash_out,
                                       size_t hash_out_size)
{
    if (!stream || !hash_out || hash_out_size < 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t hash_size = 0;
    psa_status_t status = psa_hash_finish(&stream->op, hash_out, 32, &hash_size);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&stream->op);
        return status;
    }
    if (hash_size != 32) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}

void hash_sha256_stream_abort(hash_sha256_stream_t *stream)
{
    if (stream) {
        psa_hash_abort(&stream->op);
    }
}

psa_status_t hash_sha256(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                         size_t hash_out_size)
{
    size_t n = 0;
    psa_status_t status;

    if (!input || input_size == 0 || !hash_out || hash_out_size < 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = psa_hash_compute(PSA_ALG_SHA_256, input, input_size, hash_out, 32, &n);
    if (status == PSA_SUCCESS && n != 32) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return status;
}

psa_status_t hash_double_sha256(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                                size_t hash_out_size)
{
    uint8_t first[32];
    psa_status_t status = hash_sha256(input, input_size, first, sizeof(first));

    if (status == PSA_SUCCESS) {
        status = hash_sha256(first, sizeof(first), hash_out, hash_out_size);
    }
    mem_zeroize(first, sizeof(first));
    return status;
}

psa_status_t hash_ripemd160(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                            size_t hash_out_size)
{
    if (!input || input_size == 0 || !hash_out || hash_out_size < 20) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ripemd160(input, input_size, hash_out);
    return PSA_SUCCESS;
}

psa_status_t hash_hash160(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                          size_t hash_out_size)
{
    uint8_t sha[32];
    psa_status_t status = hash_sha256(input, input_size, sha, sizeof(sha));
    if (status == PSA_SUCCESS) {
        status = hash_ripemd160(sha, sizeof(sha), hash_out, hash_out_size);
    }
    mem_zeroize(sha, sizeof(sha));
    return status;
}

psa_status_t hash_pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                                     const uint8_t *salt, size_t salt_len, uint32_t iterations,
                                     uint8_t *output, size_t output_size)
{
    if (!output || output_size < 64) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((password_len > 0 && !password) || (salt_len > 0 && !salt)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status;
    psa_key_id_t password_key = 0;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_512));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);

    status = psa_import_key(&attributes, password, password_len, &password_key);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_512));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, iterations);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, password_key);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_output_bytes(&op, output, 64);

cleanup:
    psa_key_derivation_abort(&op);
    psa_destroy_key(password_key);
    return status;
}

psa_status_t hash_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *input,
                              size_t input_len, uint8_t *output, size_t output_size)
{
    if (!key || key_len == 0 || !input || !output || output_size < 64) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status;
    psa_key_id_t key_id;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_512));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);

    status = psa_import_key(&attributes, key, key_len, &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        return status;
    }

    size_t mac_length = 0;
    status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_512), input, input_len, output,
                             output_size, &mac_length);

    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS || mac_length != 64) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}

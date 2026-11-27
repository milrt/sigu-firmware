// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// The hashes, on top of PSA Crypto.
// RIPEMD-160 is in software, because the nRF54L backend has no PSA_ALG_RIPEMD160.
// Each output is the full digest, and `*_size` is the buffer size.
// A smaller buffer, a NULL pointer or an empty input is PSA_ERROR_INVALID_ARGUMENT.
// An empty input is allowed only in a stream update.

#pragma once

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    psa_hash_operation_t op;
} hash_sha256_stream_t;

psa_status_t hash_sha256_stream_init(hash_sha256_stream_t *stream);
psa_status_t hash_sha256_stream_update(hash_sha256_stream_t *stream, const uint8_t *input,
                                       size_t input_size);
psa_status_t hash_sha256_stream_finish(hash_sha256_stream_t *stream, uint8_t *hash_out,
                                       size_t hash_out_size);
void hash_sha256_stream_abort(hash_sha256_stream_t *stream);

psa_status_t hash_sha256(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                         size_t hash_out_size);
// SHA256(SHA256(x)), the txid and checksum hash.
psa_status_t hash_double_sha256(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                                size_t hash_out_size);
psa_status_t hash_ripemd160(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                            size_t hash_out_size);
// RIPEMD160(SHA256(x)), 20 bytes.
psa_status_t hash_hash160(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                          size_t hash_out_size);
// 64 bytes. An empty password or salt is allowed.
psa_status_t hash_pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                                     const uint8_t *salt, size_t salt_len, uint32_t iterations,
                                     uint8_t *output, size_t output_size);
psa_status_t hash_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *input,
                              size_t input_len, uint8_t *output, size_t output_size);

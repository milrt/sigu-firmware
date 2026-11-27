// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "base58.h"
#include "libbase58.h"
#include "shared/hash.h"
#include "shared/mem_util.h"
#include <string.h>

static bool sha256_wrapper(void *digest, const void *data, size_t datasz)
{
    return hash_sha256(data, datasz, (uint8_t *)digest, 32) == PSA_SUCCESS;
}

void base58_init(void)
{
    b58_sha256_impl = sha256_wrapper;
}

psa_status_t base58_check_encode(const uint8_t *data, size_t data_size, char *str, size_t str_size)
{
    if (!data || (data_size == 0) || !str) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (data_size > BASE58_ENCODE_MAX_DATA_SIZE - 4) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t buf[BASE58_ENCODE_MAX_DATA_SIZE];
    memcpy(buf, data, data_size);

    uint8_t hash[32];
    psa_status_t status = hash_double_sha256(data, data_size, hash, sizeof(hash));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    memcpy(buf + data_size, hash, 4);

    size_t encoded_size = str_size;
    if (!b58enc(str, &encoded_size, buf, data_size + 4)) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
    }

cleanup:
    mem_zeroize(buf, sizeof(buf));
    return status;
}

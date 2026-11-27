// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// Zephyr's base64 is Mbed TLS's, with errno codes.

#pragma once

#include <errno.h>
#include <mbedtls/base64.h>

static inline int sim_base64_rc(int rc)
{
    if (rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return -ENOMEM;
    }
    return rc ? -EINVAL : 0;
}

static inline int base64_encode(uint8_t *dst, size_t dlen, size_t *olen, const uint8_t *src,
                                size_t slen)
{
    return sim_base64_rc(mbedtls_base64_encode(dst, dlen, olen, src, slen));
}

static inline int base64_decode(uint8_t *dst, size_t dlen, size_t *olen, const uint8_t *src,
                                size_t slen)
{
    return sim_base64_rc(mbedtls_base64_decode(dst, dlen, olen, src, slen));
}

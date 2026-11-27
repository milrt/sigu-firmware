// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "psbt_compactsize.h"
#include <string.h>
#include <zephyr/sys/byteorder.h>

// The header byte, and the size of the value after it.
static uint8_t header_of(uint64_t n, size_t *size)
{
    if (n < 0xFD) {
        *size = 0;
        return n;
    }
    if (n <= 0xFFFF) {
        *size = 2;
        return 0xFD;
    }
    if (n <= 0xFFFFFFFF) {
        *size = 4;
        return 0xFE;
    }
    *size = 8;
    return 0xFF;
}

bool compactsize_read(const uint8_t **p, size_t *remaining, uint64_t *n)
{
    if (*remaining < 1) {
        return false;
    }

    uint8_t header = **p;
    const uint8_t *b = *p + 1;
    size_t size = header < 0xFD ? 0 : header == 0xFD ? 2 : header == 0xFE ? 4 : 8;
    size_t shortest;

    if (*remaining < 1 + size) {
        return false;
    }
    *n = size == 0   ? header
         : size == 2 ? sys_get_le16(b)
         : size == 4 ? sys_get_le32(b)
                     : sys_get_le64(b);
    // Only the shortest form, so a value has one encoding.
    header_of(*n, &shortest);
    if (shortest != size) {
        return false;
    }
    *p += 1 + size;
    *remaining -= 1 + size;
    return true;
}

bool compactsize_write(uint8_t **p, size_t *remaining, uint64_t n)
{
    size_t size;
    uint8_t header = header_of(n, &size);
    uint8_t *b = *p;

    if (*remaining < 1 + size) {
        return false;
    }
    b[0] = header;
    if (size == 2) {
        sys_put_le16(n, b + 1);
    } else if (size == 4) {
        sys_put_le32(n, b + 1);
    } else if (size == 8) {
        sys_put_le64(n, b + 1);
    }
    *p += 1 + size;
    *remaining -= 1 + size;
    return true;
}

bool compactsize_read_bytes(const uint8_t **p, size_t *remaining, const uint8_t **bytes,
                            size_t *len)
{
    uint64_t n;

    if (!compactsize_read(p, remaining, &n) || n > *remaining) {
        return false;
    }
    *bytes = *p;
    *len = n;
    *p += n;
    *remaining -= n;
    return true;
}

bool compactsize_write_bytes(uint8_t **p, size_t *remaining, const uint8_t *bytes, size_t len)
{
    if (!compactsize_write(p, remaining, len) || len > *remaining) {
        return false;
    }
    if (len > 0) {
        memcpy(*p, bytes, len);
    }
    *p += len;
    *remaining -= len;
    return true;
}

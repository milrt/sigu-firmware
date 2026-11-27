// Copyright (C) 2026 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shared/descriptor.h"
#include <stdbool.h>
#include <string.h>

#define ORIGIN "84h/0h/0h"

#define CHECKSUM_LEN 8

static const char input_charset[] = "0123456789()[],'/*abcdefgh@:$%{}"
                                    "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
                                    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
static const char checksum_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const char hex[] = "0123456789abcdef";

static uint64_t polymod(uint64_t c, unsigned int v)
{
    static const uint64_t gen[] = {0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a,
                                   0x644d626ffd};
    unsigned int top = (unsigned int)(c >> 35);

    c = ((c & 0x7ffffffff) << 5) ^ v;
    for (int i = 0; i < 5; i++) {
        if ((top >> i) & 1) {
            c ^= gen[i];
        }
    }
    return c;
}

// The BIP380 checksum of `s`. Each char gives its low 5 bits,
// and every 3 chars also give their 2-bit groups as one symbol.
static bool descsum(const char *s, char out[CHECKSUM_LEN + 1])
{
    uint64_t c = 1;
    unsigned int groups = 0;
    unsigned int n = 0;

    for (; *s != '\0'; s++) {
        const char *p = strchr(input_charset, *s);
        unsigned int v;

        if (!p) {
            return false;
        }
        v = (unsigned int)(p - input_charset);
        c = polymod(c, v & 31);
        groups = groups * 3 + (v >> 5);
        if (++n == 3) {
            c = polymod(c, groups);
            groups = 0;
            n = 0;
        }
    }
    if (n > 0) {
        c = polymod(c, groups);
    }
    for (int i = 0; i < CHECKSUM_LEN; i++) {
        c = polymod(c, 0);
    }
    c ^= 1;
    for (int i = 0; i < CHECKSUM_LEN; i++) {
        out[i] = checksum_charset[(c >> (5 * (CHECKSUM_LEN - 1 - i))) & 31];
    }
    out[CHECKSUM_LEN] = '\0';
    return true;
}

static bool add(char *out, size_t size, size_t *len, const char *s)
{
    size_t n = strlen(s);

    if (n >= size - *len) {
        return false;
    }
    memcpy(out + *len, s, n + 1);
    *len += n;
    return true;
}

size_t descriptor_build(const uint8_t fp[BITCOIN_FINGERPRINT_SIZE], const char *xpub, char *out,
                        size_t size)
{
    char fp_hex[2 * BITCOIN_FINGERPRINT_SIZE + 1];
    char sum[CHECKSUM_LEN + 1];
    size_t len = 0;

    for (int i = 0; i < BITCOIN_FINGERPRINT_SIZE; i++) {
        fp_hex[2 * i] = hex[fp[i] >> 4];
        fp_hex[2 * i + 1] = hex[fp[i] & 15];
    }
    fp_hex[sizeof(fp_hex) - 1] = '\0';

    if (size == 0 || !add(out, size, &len, "wpkh([") || !add(out, size, &len, fp_hex) ||
        !add(out, size, &len, "/" ORIGIN "]") || !add(out, size, &len, xpub) ||
        !add(out, size, &len, "/<0;1>/*)") || !descsum(out, sum) || !add(out, size, &len, "#") ||
        !add(out, size, &len, sum)) {
        return 0;
    }
    return len;
}

// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/text.h"

bool text_add(char *buf, size_t size, size_t *len, const char *s)
{
    // No room even for the NUL. Nothing is written.
    if (*len >= size) {
        return false;
    }
    while (*s) {
        if (*len + 1 >= size) {
            buf[*len] = '\0';
            return false;
        }
        buf[(*len)++] = *s++;
    }
    buf[*len] = '\0';
    return true;
}

bool text_add_u32(char *buf, size_t size, size_t *len, uint32_t v)
{
    char digits[11];
    size_t i = sizeof(digits) - 1;

    digits[i] = '\0';
    do {
        digits[--i] = '0' + v % 10;
        v /= 10;
    } while (v);
    return text_add(buf, size, len, &digits[i]);
}

static bool add_2digits(char *buf, size_t size, size_t *len, uint32_t v)
{
    char pair[3] = {'0' + v / 10, '0' + v % 10, '\0'};

    return text_add(buf, size, len, pair);
}

// The days-to-civil algorithm by Howard Hinnant.
// Its year starts in March, so a leap day is the last day of its year.
bool text_add_utc_date(char *buf, size_t size, size_t *len, uint32_t t)
{
    uint32_t z = t / 86400 + 719468;
    uint32_t era = z / 146097;
    uint32_t doe = z - era * 146097;
    uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint32_t mp = (5 * doy + 2) / 153;
    uint32_t day = doy - (153 * mp + 2) / 5 + 1;
    uint32_t month = mp < 10 ? mp + 3 : mp - 9;
    uint32_t year = yoe + era * 400 + (month <= 2);

    return text_add_u32(buf, size, len, year) && text_add(buf, size, len, "-") &&
           add_2digits(buf, size, len, month) && text_add(buf, size, len, "-") &&
           add_2digits(buf, size, len, day);
}

bool text_add_hex(char *buf, size_t size, size_t *len, const uint8_t *b, size_t n)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < n; i++) {
        char pair[3] = {digits[b[i] >> 4], digits[b[i] & 0xF], '\0'};

        if (!text_add(buf, size, len, pair)) {
            return false;
        }
    }
    return true;
}

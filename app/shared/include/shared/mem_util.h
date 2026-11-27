// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>

static inline void mem_zeroize(void *buf, size_t len)
{
    volatile unsigned char *p = buf;
    while (len--) {
        *p++ = 0;
    }
}

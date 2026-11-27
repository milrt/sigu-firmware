// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// String building for the screens, because the SP has no snprintf.
// Each call appends to the string in `buf` (`size` bytes, `*len` used) and moves `*len`.
// On overflow it keeps what fits, keeps the NUL and returns false.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool text_add(char *buf, size_t size, size_t *len, const char *s);

// `v` in decimal.
bool text_add_u32(char *buf, size_t size, size_t *len, uint32_t v);

// The UTC date of unix time `t`, as YYYY-MM-DD.
bool text_add_utc_date(char *buf, size_t size, size_t *len, uint32_t t);

// Lowercase hex.
bool text_add_hex(char *buf, size_t size, size_t *len, const uint8_t *b, size_t n);

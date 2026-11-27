// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

// Bitcoin's compactsize, the variable length integer of txs and PSBTs.
// Each call moves `*p` past what it read or wrote and lowers `*remaining` by the same amount.
// It fails when the bytes do not fit, and the caller then drops the whole buffer.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Refuses a value that does not use the shortest form.
bool compactsize_read(const uint8_t **p, size_t *remaining, uint64_t *n);
bool compactsize_write(uint8_t **p, size_t *remaining, uint64_t n);

// A compactsize length, then that many bytes. `*bytes` points into the input.
bool compactsize_read_bytes(const uint8_t **p, size_t *remaining, const uint8_t **bytes,
                            size_t *len);
bool compactsize_write_bytes(uint8_t **p, size_t *remaining, const uint8_t *bytes, size_t len);
